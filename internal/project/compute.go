package project

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"unicode"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/vm"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/yamlx"
)

// computed is a scalar with the !expr or the !tpl tag, compiled at load.
type computed struct {
	pos  yamlx.Pos
	prog *vm.Program
	tmpl *template.Template
	// reads are the variables that it reads by name.
	reads []string
}

// scope is what an expression or a template can read.
type scope struct {
	vars map[string]*Var
	// noItem is the reason that item is not defined, or "" when it is.
	noItem string
	// byName is the error for a read of vars other than by name, or "" when
	// such a read is allowed.
	byName string
}

const itemOutsideLoop = "item is defined only in a step with loop"

type exprEnv struct {
	Vars  map[string]any `expr:"vars"`
	Facts facts.Facts    `expr:"facts"`
	Host  hostEnv        `expr:"host"`
	Item  any            `expr:"item"`
}

type hostEnv struct {
	Name    string         `expr:"name"`
	Short   string         `expr:"short"`
	Address string         `expr:"address"`
	Groups  []string       `expr:"groups"`
	Vars    map[string]any `expr:"vars"`
}

// exprOptions replace keys, values, and toPairs, whose order is random in
// expr, with versions in sorted key order.
var exprOptions = []expr.Option{
	expr.Env(exprEnv{}),
	expr.DisableBuiltin("keys"),
	expr.DisableBuiltin("values"),
	expr.DisableBuiltin("toPairs"),
	sortedFunc("keys", func(k string, v any) any { return k }),
	sortedFunc("values", func(k string, v any) any { return v }),
	sortedFunc("toPairs", func(k string, v any) any { return []any{k, v} }),
}

func sortedFunc(name string, pick func(k string, v any) any) expr.Option {
	return expr.Function(name, func(args ...any) (any, error) {
		m, ok := args[0].(map[string]any)
		if len(args) != 1 || !ok {
			return nil, fmt.Errorf("%s takes one map", name)
		}
		var out []any
		for _, k := range slices.Sorted(maps.Keys(m)) {
			out = append(out, pick(k, m[k]))
		}
		return out, nil
	})
}

func compile(n *yamlx.Node, sc scope) (*computed, error) {
	text, _ := n.Value.(string)
	c := &computed{pos: n.Pos}
	if n.Tag == "!tpl" {
		t, reads, err := parseInline(n.Pos, text, sc)
		if err != nil {
			return nil, err
		}
		c.tmpl, c.reads = t, reads
		return c, nil
	}
	prog, err := expr.Compile(text, exprOptions...)
	if err != nil {
		return nil, yamlx.Errorf(n.Pos, "%s", exprMessage(err, exprNames))
	}
	c.prog = prog
	check := &exprCheck{sc: sc, src: prog.Source(), named: map[ast.Node]bool{}}
	ast.Walk(new(prog.Node()), check)
	check.checkByName()
	if len(check.errs) > 0 {
		var errs []error
		for _, msg := range check.errs {
			errs = append(errs, yamlx.Errorf(n.Pos, "%s", msg))
		}
		return nil, errors.Join(errs...)
	}
	c.reads = check.reads
	return c, nil
}

// exprCheck finds the variables that an expression reads by name, and
// reports undeclared variables, an item that is not defined, and a read of
// vars other than by name where the scope forbids it.
type exprCheck struct {
	sc    scope
	src   file.Source
	reads []string
	errs  []string
	// named are the nodes that a member access with a constant name reads.
	named map[ast.Node]bool
	// whole are the nodes that hold vars: vars, host, and host.vars.
	whole []ast.Node
}

func (c *exprCheck) fail(n ast.Node, msg string) {
	fe := &file.Error{Location: n.Location(), Message: msg}
	c.errs = append(c.errs, msg+snippet(fe.Bind(c.src)))
}

func (c *exprCheck) Visit(np *ast.Node) {
	switch n := (*np).(type) {
	case *ast.IdentifierNode:
		if n.Value == "item" && c.sc.noItem != "" {
			c.fail(n, c.sc.noItem)
		}
		if n.Value == "$env" && c.sc.byName != "" {
			c.fail(n, c.sc.byName)
		}
		if isVars(n) || n.Value == "host" {
			c.whole = append(c.whole, n)
		}
	case *ast.MemberNode:
		if isVars(n) {
			c.whole = append(c.whole, n)
		}
		name, ok := n.Property.(*ast.StringNode)
		if ok {
			c.named[n.Node] = true
		}
		if !ok || !isVars(n.Node) {
			return
		}
		if _, ok := c.sc.vars[name.Value]; !ok {
			c.fail(n, unknownVariable(name.Value, c.sc.vars))
			return
		}
		c.reads = append(c.reads, name.Value)
	}
}

// checkByName reports each read of vars other than by name, when the scope
// forbids it.
func (c *exprCheck) checkByName() {
	if c.sc.byName == "" {
		return
	}
	for _, n := range c.whole {
		if !c.named[n] {
			c.fail(n, c.sc.byName)
		}
	}
}

// isVars reports whether n is vars or host.vars.
func isVars(n ast.Node) bool {
	if id, ok := n.(*ast.IdentifierNode); ok {
		return id.Value == "vars"
	}
	m, ok := n.(*ast.MemberNode)
	if !ok {
		return false
	}
	id, ok := m.Node.(*ast.IdentifierNode)
	prop, ok2 := m.Property.(*ast.StringNode)
	return ok && ok2 && id.Value == "host" && prop.Value == "vars"
}

func unknownVariable(name string, vars map[string]*Var) string {
	return fmt.Sprintf("unknown variable %q%s", name, yamlx.Suggest(name, slices.Sorted(maps.Keys(vars))))
}

var (
	unknownNameRe  = regexp.MustCompile(`^unknown name (\w+)$`)
	unknownFieldRe = regexp.MustCompile(`^type (\w+\.\w+) has no field (\w+)$`)
	exprNames      = []string{"vars", "facts", "host", "item"}
	osFields       = fieldTags(facts.OS{})
	hostFields     = fieldTags(hostEnv{})
	// fieldNames are the fields of the typed data, by the type name in
	// errors of expr.
	fieldNames = map[string]struct {
		noun  string
		names []string
	}{
		"facts.Facts":     {"fact", fieldTags(facts.Facts{})},
		"facts.OS":        {"fact", osFields},
		"project.hostEnv": {"host field", hostFields},
	}
)

// exprMessage returns the message of an expr error, with a suggestion for an
// unknown name, and the snippet.
func exprMessage(err error, names []string) string {
	fe, ok := errors.AsType[*file.Error](err)
	if !ok {
		return err.Error()
	}
	msg := fe.Message
	if m := unknownNameRe.FindStringSubmatch(msg); m != nil {
		msg = fmt.Sprintf("unknown name %q%s", m[1], yamlx.Suggest(m[1], names))
	} else if m := unknownFieldRe.FindStringSubmatch(msg); m != nil {
		if f, ok := fieldNames[m[1]]; ok {
			msg = fmt.Sprintf("unknown %s %q%s", f.noun, m[2], yamlx.Suggest(m[2], f.names))
		}
	}
	return msg + snippet(fe)
}

// snippet returns the snippet of fe: the expression line and a caret line
// under the error. Control characters in the expression become "?".
func snippet(fe *file.Error) string {
	return strings.Map(func(r rune) rune {
		if r != '\n' && (unicode.IsControl(r) || r == '\u2028' || r == '\u2029') {
			return '?'
		}
		return r
	}, fe.Snippet)
}

func fieldTags(v any) []string {
	t := reflect.TypeOf(v)
	var names []string
	for i := range t.NumField() {
		names = append(names, t.Field(i).Tag.Get("expr"))
	}
	return names
}

// eval returns the value for the environment of a host.
func (c *computed) eval(e *Env) (any, error) {
	if c.tmpl != nil {
		var b bytes.Buffer
		if err := c.tmpl.Execute(&b, e.templateData()); err != nil {
			return nil, errors.New(templateMessage(c.tmpl.Name(), err))
		}
		return b.String(), nil
	}
	out, err := expr.Run(c.prog, e.exprEnv())
	if err != nil {
		return nil, errors.New(exprMessage(err, exprNames))
	}
	return out, nil
}

// value is a YAML value whose tagged scalars are computed for each host.
type value struct {
	node     *yamlx.Node
	computed map[*yamlx.Node]*computed
}

// compileValue compiles the tagged scalars of n. It returns nil when n has
// none.
func compileValue(n *yamlx.Node, sc scope) (*value, error) {
	v := &value{node: n, computed: map[*yamlx.Node]*computed{}}
	var errs []error
	var walk func(n *yamlx.Node)
	walk = func(n *yamlx.Node) {
		switch {
		case n.Tag != "":
			c, err := compile(n, sc)
			errs = append(errs, err)
			v.computed[n] = c
		case n.Kind == yamlx.Map:
			for _, p := range n.Pairs {
				walk(p.Value)
			}
		case n.Kind == yamlx.List:
			for _, item := range n.Items {
				walk(item)
			}
		}
	}
	walk(n)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if len(v.computed) == 0 {
		return nil, nil
	}
	return v, nil
}

// reads returns the variables that the value reads by name.
func (v *value) reads() []string {
	var out []string
	for _, c := range v.computed {
		out = append(out, c.reads...)
	}
	return out
}

// eval returns the value for a host, as a tree without tags. An error names
// the key of the computed scalar, or name at the top.
func (v *value) eval(e *Env, name string) (*yamlx.Node, error) {
	return v.evalNode(v.node, e, name)
}

func (v *value) evalNode(n *yamlx.Node, e *Env, name string) (*yamlx.Node, error) {
	if c := v.computed[n]; c != nil {
		out, err := c.eval(e)
		if err != nil {
			return nil, yamlx.Errorf(n.Pos, "%s%s", prefix(name), err)
		}
		res, err := yamlx.FromValue(out, n.Pos)
		if err != nil {
			return nil, yamlx.Errorf(n.Pos, "%s%s", prefix(name), err)
		}
		return res, nil
	}
	out := *n
	switch n.Kind {
	case yamlx.Map:
		out.Pairs = slices.Clone(n.Pairs)
		for i, p := range n.Pairs {
			sub, err := v.evalNode(p.Value, e, p.Key)
			if err != nil {
				return nil, err
			}
			out.Pairs[i].Value = sub
		}
	case yamlx.List:
		out.Items = slices.Clone(n.Items)
		for i, item := range n.Items {
			sub, err := v.evalNode(item, e, name)
			if err != nil {
				return nil, err
			}
			out.Items[i] = sub
		}
	}
	return &out, nil
}

func prefix(name string) string {
	if name == "" {
		return ""
	}
	return name + ": "
}

// describeValue names a Go value for an error message.
func describeValue(v any) string {
	n, err := yamlx.FromValue(v, yamlx.Pos{})
	if err != nil {
		return fmt.Sprintf("a %T", v)
	}
	return yamlx.Describe(n)
}
