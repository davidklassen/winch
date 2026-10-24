package project

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	tparse "text/template/parse"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/yamlx"
)

// dataNames are the names that a template can read.
var dataNames = []string{"host"}

// funcs replaces the built-in index, which gives the zero value for a missing
// map key.
var funcs = template.FuncMap{"index": index}

// parseTemplate parses the template text of file and checks the names it
// reads.
func parseTemplate(file string, text []byte) (*template.Template, error) {
	t, err := template.New(file).Option("missingkey=error").Funcs(funcs).Parse(string(text))
	if err != nil {
		return nil, templateError(file, err)
	}
	var errs []error
	for _, d := range t.Templates() {
		c := nameCheck{file: file, text: string(text), main: d.Name() == file}
		c.walk(d.Root, c.main)
		errs = append(errs, c.errs...)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return t, nil
}

// nameCheck checks the first name of each field that reads the data. main is
// true in the template of the file, where $ is the data.
type nameCheck struct {
	file, text string
	main       bool
	errs       []error
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
		start := int(n.Pos)
		if len(n.Ident) > 1 {
			start -= len(n.Ident[0]) + 1
		}
		if top {
			c.check(n.Ident[0], start)
		}
	case *tparse.VariableNode:
		// The position of $.a is the position of .a.
		if c.main && n.Ident[0] == "$" && len(n.Ident) > 1 {
			c.check(n.Ident[1], int(n.Pos)-1)
		}
	}
}

func (c *nameCheck) check(name string, off int) {
	if slices.Contains(dataNames, name) {
		return
	}
	before := c.text[:off]
	pos := yamlx.Pos{File: c.file, Line: strings.Count(before, "\n") + 1, Col: off - strings.LastIndexByte(before, '\n')}
	c.errs = append(c.errs, yamlx.Errorf(pos, "unknown name %q%s", name, yamlx.Suggest(name, dataNames)))
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

var templateErrRe = regexp.MustCompile(`(?s)^(\d+)(?::(\d+))?: (?:executing "(?:[^"\\]|\\.)*" at <(.*?)>: )?(.*)$`)

// templateError turns an error of the template package into an error with
// the position in file. A parse error has no column, so it gets column 1.
func templateError(file string, err error) error {
	m := templateErrRe.FindStringSubmatch(strings.TrimPrefix(err.Error(), "template: "+file+":"))
	if m == nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	line, _ := strconv.Atoi(m[1])
	col := 1
	if m[2] != "" {
		col, _ = strconv.Atoi(m[2])
		col++
	}
	msg := m[4]
	if m[3] != "" {
		msg = m[3] + ": " + msg
	}
	return yamlx.Errorf(yamlx.Pos{File: file, Line: line, Col: col}, "%s", msg)
}

// For returns the step for host h: a file step with a template gets the
// rendered content.
func (st Step) For(h Host) (Step, error) {
	if st.tmpl == nil {
		return st, nil
	}
	short, _, _ := strings.Cut(h.Name, ".")
	data := map[string]any{"host": map[string]any{"name": h.Name, "short": short, "address": h.Address}}
	var b bytes.Buffer
	if err := st.tmpl.Execute(&b, data); err != nil {
		return Step{}, templateError(st.tmpl.Name(), err)
	}
	f := *st.Args.(*module.File)
	// Empty output is empty content, not missing content.
	f.Data = append([]byte{}, b.Bytes()...)
	st.Args = &f
	return st, nil
}
