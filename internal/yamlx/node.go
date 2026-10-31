// Package yamlx reads YAML 1.2 files into a tree that keeps the position of
// every value, and decodes that tree into structs.
package yamlx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Kind int

const (
	Null Kind = iota
	Scalar
	Map
	List
)

// Node is a YAML value. A Scalar holds a string, bool, int64, or float64 in
// Value.
type Node struct {
	Kind  Kind
	Value any
	Pairs []Pair
	Items []*Node
	Pos   Pos
	// Tag is "!expr" for an expression, "!tpl" for a template, "!secret" for
	// a secret, else empty.
	Tag string
	// Text is the source text of a scalar from a file.
	Text string
}

type Pair struct {
	Key string
	// KeyValue is the key resolved as a scalar value, so a plain 1234 is an
	// int64 and a quoted "1234" is a string.
	KeyValue any
	KeyPos   Pos
	Value    *Node
}

// Parse reads one YAML document. An empty file is a Null node.
func Parse(file string, data []byte) (*Node, error) {
	root, err := parseRoot(file, data)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return &Node{Kind: Null, Pos: Pos{File: file, Line: 1, Col: 1}}, nil
	}
	c := converter{file: file, seen: map[*yaml.Node]*Node{}, open: map[*yaml.Node]bool{}}
	n := c.convert(root)
	return n, errors.Join(c.errs...)
}

// parseRoot reads one YAML document and returns its root node, or nil for an
// empty file.
func parseRoot(file string, data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, parseError(file, data, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, Errorf(Pos{file, extra.Line, extra.Column}, "a file holds one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return nil, parseError(file, data, err)
	}
	return doc.Content[0], nil
}

// HasComment reports whether the YAML in data holds a comment.
func HasComment(data []byte) bool {
	var doc yaml.Node
	return yaml.Unmarshal(data, &doc) == nil && len(comments(&doc)) > 0
}

var lineRe = regexp.MustCompile(`^yaml: line (\d+): (.*)$`)

// parseError gives the error of the YAML parser a position in file. The
// errors of a tab in the indentation name the line of the tab or the line
// above it, and on the first line no line.
func parseError(file string, data []byte, err error) error {
	msg, line := strings.TrimPrefix(err.Error(), "yaml: "), 1
	if m := lineRe.FindStringSubmatch(err.Error()); m != nil {
		line, _ = strconv.Atoi(m[1])
		msg = m[2]
	}
	if slices.Contains(tabErrors, msg) {
		lines := strings.Split(string(data), "\n")
		for i := line - 1; i <= line && i < len(lines); i++ {
			indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " \t"))]
			if col := strings.IndexByte(indent, '\t'); col >= 0 {
				return Errorf(Pos{file, i + 1, col + 1}, "a tab indents this line; YAML indents with spaces")
			}
		}
	}
	return Errorf(Pos{file, line, 1}, "%s", msg)
}

var tabErrors = []string{
	"found character that cannot start any token",
	"found a tab character that violates indentation",
	"found a tab character where an indentation space is expected",
}

type converter struct {
	file string
	seen map[*yaml.Node]*Node
	// open holds the nodes being converted, to find an alias inside its
	// own anchor.
	open map[*yaml.Node]bool
	errs []error
}

func winchTag(tag string) bool {
	return tag == "!expr" || tag == "!tpl" || tag == "!secret"
}

func (c *converter) pos(n *yaml.Node) Pos {
	return Pos{File: c.file, Line: n.Line, Col: n.Column}
}

func (c *converter) errorf(n *yaml.Node, format string, args ...any) {
	c.errs = append(c.errs, Errorf(c.pos(n), format, args...))
}

func (c *converter) convert(n *yaml.Node) *Node {
	if n.Kind == yaml.AliasNode {
		if c.open[n.Alias] {
			c.errorf(n, "an alias cannot refer to its own anchor")
			return &Node{Pos: c.pos(n)}
		}
		return c.convert(n.Alias)
	}
	if out, ok := c.seen[n]; ok {
		return out
	}
	out := &Node{Pos: c.pos(n)}
	c.seen[n] = out
	c.open[n] = true
	defer delete(c.open, n)
	if n.Style&yaml.TaggedStyle != 0 {
		switch {
		case winchTag(n.Tag) && n.Kind == yaml.ScalarNode:
			out.Kind, out.Value, out.Tag = Scalar, n.Value, n.Tag
			return out
		case winchTag(n.Tag):
			kind := "a map"
			if n.Kind == yaml.SequenceNode {
				kind = "a list"
			}
			c.errorf(n, "the %s tag needs a string, got %s", n.Tag, kind)
			return out
		case n.Kind != yaml.ScalarNode || n.Tag != "!!str":
			c.errorf(n, `unknown tag; the tags are !expr, !tpl, and !secret; quote a value that starts with "!"`)
			return out
		}
	}
	switch n.Kind {
	case yaml.ScalarNode:
		var err error
		out.Kind, out.Value, err = scalar(n)
		if err != nil {
			c.errorf(n, "%v", err)
		}
		out.Text = n.Value
	case yaml.MappingNode:
		out.Kind = Map
		first := map[string]Pos{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode {
				c.errorf(k, "a map key must be a scalar")
				continue
			}
			if k.Style&yaml.TaggedStyle != 0 && winchTag(k.Tag) {
				c.errorf(k, "a map key cannot have the tag %q", k.Tag)
				continue
			}
			if k.Style&yaml.TaggedStyle != 0 && k.Tag != "!!str" {
				c.errorf(k, `a map key cannot have a tag; quote a key that starts with "!"`)
				continue
			}
			if k.Value == "<<" && k.Style == 0 {
				c.errorf(k, "merge keys (<<) are not allowed")
				continue
			}
			if p, ok := first[k.Value]; ok {
				c.errorf(k, "duplicate key %q (first at line %d)", k.Value, p.Line)
				continue
			}
			first[k.Value] = c.pos(k)
			_, kv, err := scalar(k)
			if err != nil {
				c.errorf(k, "%v", err)
				continue
			}
			out.Pairs = append(out.Pairs, Pair{Key: k.Value, KeyValue: kv, KeyPos: c.pos(k), Value: c.convert(v)})
		}
	case yaml.SequenceNode:
		out.Kind = List
		for _, item := range n.Content {
			out.Items = append(out.Items, c.convert(item))
		}
	}
	return out
}

var (
	decRe    = regexp.MustCompile(`^[-+]?[0-9]+$`)
	digitsRe = regexp.MustCompile(`^[0-9]+$`)
	octRe    = regexp.MustCompile(`^0o[0-7]+$`)
	hexRe    = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	floatRe  = regexp.MustCompile(`^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`)
)

// scalar resolves a scalar by the YAML 1.2 core schema, with two changes: only
// "true" and "false" are booleans, and an integer must fit in an int.
func scalar(n *yaml.Node) (Kind, any, error) {
	s := n.Value
	if n.Style != 0 {
		return Scalar, s, nil
	}
	switch s {
	case "", "~", "null", "Null", "NULL":
		return Null, nil, nil
	case "true":
		return Scalar, true, nil
	case "false":
		return Scalar, false, nil
	case ".inf", "+.inf", ".Inf", "+.Inf", ".INF", "+.INF":
		return Scalar, math.Inf(1), nil
	case "-.inf", "-.Inf", "-.INF":
		return Scalar, math.Inf(-1), nil
	case ".nan", ".NaN", ".NAN":
		return Scalar, math.NaN(), nil
	}
	var base int
	digits := s
	switch {
	case decRe.MatchString(s):
		base = 10
	case octRe.MatchString(s):
		base, digits = 8, s[2:]
	case hexRe.MatchString(s):
		base, digits = 16, s[2:]
	}
	if base != 0 {
		i, err := strconv.ParseInt(digits, base, strconv.IntSize)
		if err != nil {
			return Scalar, s, fmt.Errorf("the integer %s is out of range (%d to %d); quote it to make it a string", s, math.MinInt, math.MaxInt)
		}
		return Scalar, i, nil
	}
	if floatRe.MatchString(s) {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return Scalar, f, nil
		}
	}
	return Scalar, s, nil
}

// Describe names a value for an error message.
func Describe(n *Node) string {
	switch n.Kind {
	case Scalar:
		switch v := n.Value.(type) {
		case string:
			return fmt.Sprintf("the string %q", v)
		case bool:
			return fmt.Sprintf("the boolean %v", v)
		case int64:
			return fmt.Sprintf("the integer %d", v)
		case float64:
			return fmt.Sprintf("the number %v", v)
		}
	case Map:
		return "a map"
	case List:
		return "a list"
	}
	return "null"
}
