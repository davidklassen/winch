package project

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	tparse "text/template/parse"
	"unicode"

	"github.com/davidklassen/winch/internal/yamlx"
)

// funcs replaces the built-in index, which gives the zero value for a missing
// map key.
var funcs = template.FuncMap{"index": index, "join": join, "has": has, "title": title, "quote": quote, "sqlquote": sqlquote}

// tmplFile is a parsed template file of a recipe.
type tmplFile struct {
	t *template.Template
	// item is true when the template reads .item.
	item  bool
	reads []string
}

// parseTemplate parses the template text of file and checks the names it
// reads. item is allowed: the step that uses the file decides.
func parseTemplate(file string, text []byte, sc scope) (*tmplFile, error) {
	t, err := template.New(file).Option("missingkey=error").Funcs(funcs).Parse(string(text))
	if err != nil {
		return nil, templateError(file, err)
	}
	c := nameCheck{sc: sc, at: func(off int) yamlx.Pos {
		before := string(text[:off])
		return yamlx.Pos{File: file, Line: strings.Count(before, "\n") + 1, Col: off - strings.LastIndexByte(before, '\n')}
	}}
	c.check(t, file)
	if err := errors.Join(c.errs...); err != nil {
		return nil, err
	}
	failNull(t)
	return &tmplFile{t: t, item: c.item, reads: c.reads}, nil
}

// parseInline parses the text of a !tpl value at pos. It returns the
// variables that the template reads.
func parseInline(pos yamlx.Pos, text string, sc scope) (*template.Template, []string, error) {
	t, err := template.New(pos.String()).Option("missingkey=error").Funcs(funcs).Parse(text)
	if err != nil {
		// A parse error names the template, which is the position here.
		msg := strings.ReplaceAll(templateMessage(pos.String(), err), pos.String()+":", "line ")
		return nil, nil, yamlx.Errorf(pos, "%s", msg)
	}
	c := nameCheck{sc: sc, at: func(int) yamlx.Pos { return pos }}
	c.check(t, pos.String())
	if c.item && sc.noItem != "" {
		c.errs = append(c.errs, yamlx.Errorf(pos, "%s", sc.noItem))
	}
	if err := errors.Join(c.errs...); err != nil {
		return nil, nil, err
	}
	failNull(t)
	return t, c.reads, nil
}

// names is a level of the names that a template can read. A nil *names allows
// any name.
type names struct {
	noun string
	sub  map[string]*names
}

func (sc scope) names() *names {
	vars := &names{noun: "variable", sub: map[string]*names{}}
	for n := range sc.vars {
		vars.sub[n] = nil
	}
	fact := map[string]*names{}
	for _, n := range osFields {
		fact[n] = nil
	}
	host := map[string]*names{"vars": vars}
	for _, n := range hostFields {
		if n != "vars" {
			host[n] = nil
		}
	}
	return &names{noun: "name", sub: map[string]*names{
		"vars":  vars,
		"facts": {noun: "fact", sub: map[string]*names{"os": {noun: "fact", sub: fact}}},
		"host":  {noun: "host field", sub: host},
		"item":  nil,
	}}
}

// nameCheck checks the names of each field that reads the data. at gives the
// position of an offset in the text.
type nameCheck struct {
	sc    scope
	at    func(off int) yamlx.Pos
	t     *template.Template
	top   *names
	main  bool
	item  bool
	reads []string
	errs  []error
}

// check checks every template of t. main names the template of the text,
// where $ is the data.
func (c *nameCheck) check(t *template.Template, main string) {
	c.t = t
	c.top = c.sc.names()
	for _, d := range t.Templates() {
		c.main = d.Name() == main
		c.walk(d.Root, c.main)
	}
}

// walk checks n. top is false where "." is another value: inside range and
// with, and in a defined template.
func (c *nameCheck) walk(n tparse.Node, top bool) {
	switch n := n.(type) {
	case *tparse.ListNode:
		if n != nil {
			for _, x := range n.Nodes {
				c.walk(x, top)
			}
		}
	case *tparse.ActionNode:
		c.walk(n.Pipe, top)
	case *tparse.TemplateNode:
		if c.t.Lookup(n.Name) == nil {
			var defined []string
			for _, d := range c.t.Templates() {
				defined = append(defined, d.Name())
			}
			c.errs = append(c.errs, yamlx.Errorf(c.at(int(n.Pos)), "template %q is not defined in this template%s", n.Name, yamlx.Suggest(n.Name, defined)))
		}
		if n.Pipe != nil {
			c.walk(n.Pipe, top)
		}
	case *tparse.PipeNode:
		if n != nil {
			for _, x := range n.Cmds {
				c.walk(x, top)
			}
		}
	case *tparse.CommandNode:
		for _, x := range n.Args {
			c.walk(x, top)
		}
	case *tparse.ChainNode:
		c.walk(n.Node, top)
	case *tparse.IfNode:
		c.walk(n.Pipe, top)
		c.walk(n.List, top)
		c.walk(n.ElseList, top)
	case *tparse.RangeNode:
		c.walk(n.Pipe, top)
		c.walk(n.List, false)
		c.walk(n.ElseList, top)
	case *tparse.WithNode:
		c.walk(n.Pipe, top)
		c.walk(n.List, false)
		c.walk(n.ElseList, top)
	case *tparse.FieldNode:
		// The position of .a.b is the position of .b.
		dot := int(n.Pos)
		if len(n.Ident) > 1 {
			dot -= len(n.Ident[0]) + 1
		}
		if top {
			c.field(n.Ident, dot, dot)
		}
	case *tparse.VariableNode:
		// The position of $.a is the position of .a.
		if c.main && n.Ident[0] == "$" {
			if len(n.Ident) > 1 {
				c.field(n.Ident[1:], int(n.Pos), int(n.Pos)-1)
			} else {
				c.notByName(int(n.Pos))
			}
		}
	case *tparse.DotNode:
		if top {
			c.notByName(int(n.Pos))
		}
	}
}

func (c *nameCheck) notByName(off int) {
	if c.sc.byName != "" {
		c.errs = append(c.errs, yamlx.Errorf(c.at(off), "%s", c.sc.byName))
	}
}

// field checks the names of a field such as .host.vars.domain. dot is the
// offset of its first dot, first the offset for an error in the first name.
func (c *nameCheck) field(ident []string, dot, first int) {
	if ident[0] == "item" {
		c.item = true
	}
	level := c.top
	off := first
	for i, id := range ident {
		if level == nil {
			return
		}
		if i > 0 {
			off = dot
		}
		next, ok := level.sub[id]
		if !ok {
			var opts []string
			for n := range level.sub {
				opts = append(opts, n)
			}
			slices.Sort(opts)
			c.errs = append(c.errs, yamlx.Errorf(c.at(off), "unknown %s %q%s", level.noun, id, yamlx.Suggest(id, opts)))
			return
		}
		if level.noun == "variable" {
			c.reads = append(c.reads, id)
		}
		level = next
		dot += len(id) + 1
	}
	if level == c.top.sub["vars"] || level == c.top.sub["host"] {
		c.notByName(first)
	}
}

// nullError is the error of an action that prints a null value. text is the
// pipeline of the action.
type nullError struct{ text string }

func (nullError) Error() string { return "the value is null" }

// failNull makes each action of t that prints fail on a null value: the
// template package prints null as "<no value>". It adds the notNull function
// at the end of the pipeline, after the parse, so that a template cannot call
// it.
func failNull(t *template.Template) {
	t.Funcs(template.FuncMap{"notNull": notNull})
	var walk func(n tparse.Node)
	walk = func(n tparse.Node) {
		switch n := n.(type) {
		case *tparse.ListNode:
			if n != nil {
				for _, x := range n.Nodes {
					walk(x)
				}
			}
		case *tparse.ActionNode:
			if len(n.Pipe.Decl) > 0 {
				return
			}
			text := n.Pipe.String()
			n.Pipe.Cmds = append(n.Pipe.Cmds, &tparse.CommandNode{NodeType: tparse.NodeCommand, Pos: n.Pipe.Pos, Args: []tparse.Node{
				tparse.NewIdentifier("notNull").SetPos(n.Pipe.Pos),
				&tparse.StringNode{NodeType: tparse.NodeString, Pos: n.Pipe.Pos, Quoted: strconv.Quote(text), Text: text},
			}})
		case *tparse.IfNode:
			walk(n.List)
			walk(n.ElseList)
		case *tparse.RangeNode:
			walk(n.List)
			walk(n.ElseList)
		case *tparse.WithNode:
			walk(n.List)
			walk(n.ElseList)
		}
	}
	for _, d := range t.Templates() {
		walk(d.Root)
	}
}

func notNull(text string, v any) (any, error) {
	if v == nil {
		return nil, nullError{text}
	}
	return v, nil
}

// index is the built-in index, except that a missing map key is an error.
func index(item any, keys ...any) (any, error) {
	v := reflect.ValueOf(item)
	for _, k := range keys {
		kv := reflect.ValueOf(k)
		switch v.Kind() {
		case reflect.Map:
			if !kv.IsValid() || !kv.Type().AssignableTo(v.Type().Key()) {
				return nil, fmt.Errorf("index: key %v is not a %s", k, v.Type().Key())
			}
			e := v.MapIndex(kv)
			if !e.IsValid() {
				return nil, fmt.Errorf("map has no entry for key %q", fmt.Sprint(k))
			}
			v = e
		case reflect.Slice, reflect.Array, reflect.String:
			i, ok := k.(int)
			if !ok {
				return nil, fmt.Errorf("index: %v is not an integer", k)
			}
			if i < 0 || i >= v.Len() {
				return nil, fmt.Errorf("index %d out of range for length %d", i, v.Len())
			}
			v = v.Index(i)
		default:
			return nil, fmt.Errorf("index: cannot index %s", v.Kind())
		}
		for v.Kind() == reflect.Interface {
			v = v.Elem()
		}
	}
	if !v.IsValid() {
		return nil, nil
	}
	return v.Interface(), nil
}

func listArg(name string, l any) (reflect.Value, error) {
	v := reflect.ValueOf(l)
	if v.Kind() != reflect.Slice && v.Kind() != reflect.Array {
		return v, fmt.Errorf("%s: %s is not a list", name, describeValue(l))
	}
	return v, nil
}

func join(l any, sep string) (string, error) {
	v, err := listArg("join", l)
	if err != nil {
		return "", err
	}
	parts := make([]string, v.Len())
	for i := range v.Len() {
		e := v.Index(i).Interface()
		if e == nil {
			return "", fmt.Errorf("join: element %d is null", i+1)
		}
		parts[i] = fmt.Sprint(e)
	}
	return strings.Join(parts, sep), nil
}

func has(l any, x any) (bool, error) {
	v, err := listArg("has", l)
	if err != nil {
		return false, err
	}
	for i := range v.Len() {
		if reflect.DeepEqual(v.Index(i).Interface(), x) {
			return true, nil
		}
	}
	return false, nil
}

func title(s string) string {
	var b strings.Builder
	start := true
	for _, r := range s {
		if start {
			r = unicode.ToUpper(r)
		}
		start = unicode.IsSpace(r)
		b.WriteRune(r)
	}
	return b.String()
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var sqlEscapes = strings.NewReplacer(`\`, `\\`, "'", "''")

func sqlquote(s string) string {
	return "'" + sqlEscapes.Replace(s) + "'"
}

var templateErrRe = regexp.MustCompile(`(?s)^(\d+)(?::(\d+))?: (?:executing "(?:[^"\\]|\\.)*" at <(.*?)>: )?(.*)$`)

// parseTemplateError splits an error of the template package for the template
// name into the line, the column, and the message. A parse error has no
// column, so it gets column 1.
func parseTemplateError(name string, err error) (line, col int, msg string, ok bool) {
	m := templateErrRe.FindStringSubmatch(strings.TrimPrefix(err.Error(), "template: "+name+":"))
	if m == nil {
		return 0, 0, "", false
	}
	line, _ = strconv.Atoi(m[1])
	col = 1
	if m[2] != "" {
		col, _ = strconv.Atoi(m[2])
		col++
	}
	msg = m[4]
	if m[3] != "" {
		msg = m[3] + ": " + msg
	}
	return line, col, msg, true
}

// templateError turns an error of the template package into an error with
// the position in file.
func templateError(file string, err error) error {
	line, col, msg, ok := parseTemplateError(file, err)
	if !ok {
		return fmt.Errorf("%s: %w", file, err)
	}
	return yamlx.Errorf(yamlx.Pos{File: file, Line: line, Col: col}, "%s", msg)
}

// templateMessage is the message of an error of the template package, without
// the position.
func templateMessage(name string, err error) string {
	if _, _, msg, ok := parseTemplateError(name, err); ok {
		return msg
	}
	return err.Error()
}
