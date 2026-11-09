// Package tmpl runs templates: text with actions in {{ }} that hold expr
// expressions, and the blocks if, else if, else, and for <name> in <list>.
package tmpl

import (
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/davidklassen/winch/internal/tmpl/parse"
)

type Template struct {
	name  string
	opts  []expr.Option
	print func(any) (string, error)
	Tree  *parse.Tree
}

// ExecError is an error of Execute. Err is a *parse.Error.
type ExecError struct {
	Name string
	Err  error
}

func (e ExecError) Error() string { return e.Err.Error() }

func (e ExecError) Unwrap() error { return e.Err }

func New(name string) *Template {
	return &Template{name: name, print: printValue}
}

func Must(t *Template, err error) *Template {
	if err != nil {
		panic(err)
	}
	return t
}

func (t *Template) Name() string { return t.name }

// Expr adds the options that each expression compiles with, such as
// expr.Env and expr.Function. Call it before Parse.
func (t *Template) Expr(opts ...expr.Option) *Template {
	t.opts = append(t.opts, opts...)
	return t
}

// Print sets the function that gives the text of the value of an action. An
// error of fn stops Execute.
func (t *Template) Print(fn func(any) (string, error)) *Template {
	t.print = fn
	return t
}

// printValue prints as text/template does.
func printValue(v any) (string, error) {
	if v == nil {
		return "<no value>", nil
	}
	return fmt.Sprint(v), nil
}

func (t *Template) Parse(text string) (*Template, error) {
	tree, err := parse.Parse(t.name, text, t.opts...)
	if err != nil {
		return nil, err
	}
	t.Tree = tree
	return t, nil
}

// Execute writes the text of the template for the env data. It does not
// change data.
func (t *Template) Execute(w io.Writer, data any) error {
	if t.Tree == nil {
		return fmt.Errorf("template: %s is not parsed", t.name)
	}
	s := &state{t: t, w: w, env: data}
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() == reflect.Struct {
		p := reflect.New(v.Type())
		p.Elem().Set(v)
		s.env = p.Interface()
		for i := range v.NumField() {
			if f := v.Type().Field(i); f.Tag.Get("expr") == parse.LoopField && f.Type == reflect.TypeFor[[]any]() {
				s.loop = p.Elem().Field(i).Addr().Interface().(*[]any)
			}
		}
	}
	return s.walk(t.Tree.Root, nil)
}

type state struct {
	t    *Template
	w    io.Writer
	vm   vm.VM
	env  any
	loop *[]any
}

func (s *state) error(n *parse.ExprNode, err error) error {
	return ExecError{Name: s.t.name, Err: s.t.Tree.ErrorAt(n.Pos, n.Src, err)}
}

func (s *state) eval(n *parse.ExprNode) (any, error) {
	v, err := s.vm.Run(n.Prog, s.env)
	if err != nil {
		return nil, s.error(n, err)
	}
	return v, nil
}

// walk runs the nodes of list. loop holds the elements of the loops around
// it.
func (s *state) walk(list *parse.ListNode, loop []any) error {
	for _, n := range list.Nodes {
		switch n := n.(type) {
		case *parse.TextNode:
			if _, err := io.WriteString(s.w, n.Text); err != nil {
				return err
			}
		case *parse.ActionNode:
			v, err := s.eval(n.Expr)
			if err != nil {
				return err
			}
			text, err := s.t.print(v)
			if err != nil {
				return s.error(n.Expr, err)
			}
			if _, err := io.WriteString(s.w, text); err != nil {
				return err
			}
		case *parse.IfNode:
			v, err := s.eval(n.Cond)
			if err != nil {
				return err
			}
			ok, isBool := v.(bool)
			if !isBool {
				return s.error(n.Cond, errors.New("if: expected true or false, got "+describe(v)))
			}
			list := n.List
			if !ok {
				list = n.ElseList
			}
			if list == nil {
				continue
			}
			if err := s.walk(list, loop); err != nil {
				return err
			}
		case *parse.ForNode:
			if err := s.walkFor(n, loop); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *state) walkFor(n *parse.ForNode, loop []any) error {
	v, err := s.eval(n.Expr)
	if err != nil {
		return err
	}
	l := reflect.ValueOf(v)
	if l.Kind() != reflect.Slice && l.Kind() != reflect.Array {
		msg := "for takes a list, got " + describe(v)
		if l.Kind() == reflect.Map {
			msg += "; loop through its keys: for k in keys(...)"
		}
		return s.error(n.Expr, errors.New(msg))
	}
	if s.loop == nil {
		return s.error(n.Expr, fmt.Errorf("for needs the data to have the field %s of type []any", parse.LoopField))
	}
	for i := range l.Len() {
		inner := append(loop[:len(loop):len(loop)], l.Index(i).Interface())
		*s.loop = inner
		if err := s.walk(n.List, inner); err != nil {
			return err
		}
	}
	*s.loop = loop
	return nil
}

// describe names a value for an error message.
func describe(v any) string {
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Invalid:
		return "null"
	case reflect.String:
		return fmt.Sprintf("the string %q", v)
	case reflect.Bool:
		return fmt.Sprintf("the boolean %v", v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("the integer %d", v)
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("the number %v", v)
	case reflect.Slice, reflect.Array:
		return "a list"
	case reflect.Map:
		return "a map"
	case reflect.Func:
		return "a function"
	}
	return "a set of fields"
}
