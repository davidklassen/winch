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
	// Tag is "!expr" for an expression, else empty.
	Tag string
}

type Pair struct {
	Key    string
	KeyPos Pos
	Value  *Node
}

// Parse reads one YAML document. An empty file is a Null node.
func Parse(file string, data []byte) (*Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return &Node{Kind: Null, Pos: Pos{File: file, Line: 1, Col: 1}}, nil
		}
		return nil, parseError(file, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, Errorf(Pos{file, extra.Line, extra.Column}, "a file holds one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return nil, parseError(file, err)
	}
	c := converter{file: file, seen: map[*yaml.Node]*Node{}, open: map[*yaml.Node]bool{}}
	n := c.convert(doc.Content[0])
	return n, errors.Join(c.errs...)
}

var lineRe = regexp.MustCompile(`^yaml: line (\d+): (.*)$`)

func parseError(file string, err error) error {
	msg := err.Error()
	if m := lineRe.FindStringSubmatch(msg); m != nil {
		line, _ := strconv.Atoi(m[1])
		return Errorf(Pos{file, line, 1}, "%s", m[2])
	}
	return Errorf(Pos{file, 1, 1}, "%s", strings.TrimPrefix(msg, "yaml: "))
}

type converter struct {
	file string
	seen map[*yaml.Node]*Node
	// open holds the nodes being converted, to find an alias inside its
	// own anchor.
	open map[*yaml.Node]bool
	errs []error
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
		case n.Tag == "!expr" && n.Kind == yaml.ScalarNode:
			out.Kind, out.Value, out.Tag = Scalar, n.Value, n.Tag
			return out
		case n.Tag == "!expr":
			kind := "a map"
			if n.Kind == yaml.SequenceNode {
				kind = "a list"
			}
			c.errorf(n, "the %s tag needs a string, got %s", n.Tag, kind)
			return out
		case n.Kind != yaml.ScalarNode || n.Tag != "!!str":
			c.errorf(n, "unknown tag %q", n.Tag)
			return out
		}
	}
	switch n.Kind {
	case yaml.ScalarNode:
		out.Kind, out.Value = scalar(n)
	case yaml.MappingNode:
		out.Kind = Map
		first := map[string]Pos{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode {
				c.errorf(k, "a map key must be a scalar")
				continue
			}
			if k.Style&yaml.TaggedStyle != 0 && k.Tag != "!!str" {
				c.errorf(k, "a map key cannot have the tag %q", k.Tag)
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
			out.Pairs = append(out.Pairs, Pair{Key: k.Value, KeyPos: c.pos(k), Value: c.convert(v)})
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
	decRe   = regexp.MustCompile(`^[-+]?[0-9]+$`)
	octRe   = regexp.MustCompile(`^0o[0-7]+$`)
	hexRe   = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	floatRe = regexp.MustCompile(`^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`)
)

// scalar resolves a scalar by the YAML 1.2 core schema, with one change: only
// "true" and "false" are booleans.
func scalar(n *yaml.Node) (Kind, any) {
	s := n.Value
	if n.Style != 0 {
		return Scalar, s
	}
	switch s {
	case "", "~", "null", "Null", "NULL":
		return Null, nil
	case "true":
		return Scalar, true
	case "false":
		return Scalar, false
	case ".inf", "+.inf", ".Inf", "+.Inf", ".INF", "+.INF":
		return Scalar, math.Inf(1)
	case "-.inf", "-.Inf", "-.INF":
		return Scalar, math.Inf(-1)
	case ".nan", ".NaN", ".NAN":
		return Scalar, math.NaN()
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
		if i, err := strconv.ParseInt(digits, base, 64); err == nil {
			return Scalar, i
		}
		return Scalar, s
	}
	if floatRe.MatchString(s) {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return Scalar, f
		}
	}
	return Scalar, s
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
