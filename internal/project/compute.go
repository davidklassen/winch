package project

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"text/template"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/vm"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

// computed is a scalar with the !expr or the !tpl tag, compiled at load.
type computed struct {
	pos  yamlx.Pos
	prog *vm.Program
	tmpl *template.Template
	// reads are the variables that it reads by name.
	reads []string
	// matches are the calls of match() with a constant pattern.
	matches []matchCall
}

// matchCall is a call of match() with a constant pattern. snippet shows the
// call in the expression.
type matchCall struct {
	pattern string
	snippet string
}

// scope is what an expression or a template can read.
type scope struct {
	// reads logs each read that names a variable, also of a host from
	// match().
	reads *[]varRead
	// noItem is the reason that item is not defined, or "" when it is.
	noItem string
	// sealed is true where a !secret value is allowed: in a default.
	sealed bool
	// noMatch is the reason that match() is not allowed, or "" when it is.
	noMatch string
	// args is true in module arguments: a literal null fails there. The
	// decoder would leave a pointer argument unset for it.
	args bool
}

const itemOutsideLoop = "item is defined only in a step with loop"

const notByName = "a read of vars names the variable, such as vars.nginx_port"

// varRead is a read of a variable by name, or a value of a variable. snippet
// shows the read in an expression.
type varRead struct {
	name    string
	pos     yamlx.Pos
	snippet string
}

type exprEnv struct {
	Vars  map[string]any              `expr:"vars"`
	Facts facts.Facts                 `expr:"facts"`
	Host  hostEnv                     `expr:"host"`
	Item  any                         `expr:"item"`
	Match func(string) ([]any, error) `expr:"match"`
}

type hostEnv struct {
	Name    string         `expr:"name"`
	Short   string         `expr:"short"`
	Address string         `expr:"address"`
	Groups  []string       `expr:"groups"`
	Vars    map[string]any `expr:"vars"`
}

// exprOptions add quote, sqlquote, and json, and replace keys, values, and toPairs, whose order
// is random in expr, with versions in sorted key order.
var exprOptions = []expr.Option{
	expr.Env(exprEnv{}),
	expr.DisableBuiltin("keys"),
	expr.DisableBuiltin("values"),
	expr.DisableBuiltin("toPairs"),
	sortedFunc("keys", func(k string, v any) any { return k }),
	sortedFunc("values", func(k string, v any) any { return v }),
	sortedFunc("toPairs", func(k string, v any) any { return []any{k, v} }),
	expr.Function(readFunc, func(args ...any) (any, error) {
		return args[0], computedError(args[0])
	}),
	expr.Patch(readCheck{}),
	expr.Function("quote", func(args ...any) (any, error) {
		s, ok := args[0].(string)
		if !ok {
			return nil, fmt.Errorf("quote: %s is not a string", describeValue(args[0]))
		}
		return quote(s), nil
	}, quote),
	expr.Function("sqlquote", func(args ...any) (any, error) {
		s, ok := args[0].(string)
		if !ok {
			return nil, fmt.Errorf("sqlquote: %s is not a string", describeValue(args[0]))
		}
		return sqlquote(s), nil
	}, sqlquote),
	expr.Function("json", func(args ...any) (any, error) {
		return toJSON(args[0])
	}, toJSON),
}

// readFunc checks the value of a member read. Its name cannot be written in
// an expression.
const readFunc = "$read"

// readCheck checks each member read and get() that gives a value of unknown
// type: such a value can be the marker of a computed default of a host from
// match().
type readCheck struct{}

func (readCheck) Visit(n *ast.Node) {
	switch m := (*n).(type) {
	case *ast.MemberNode:
		if m.Method {
			return
		}
	case *ast.BuiltinNode:
		if m.Name != "get" {
			return
		}
	default:
		return
	}
	if (*n).Type().Kind() == reflect.Interface {
		ast.Patch(n, &ast.CallNode{Callee: &ast.IdentifierNode{Value: readFunc}, Arguments: []ast.Node{*n}})
	}
}

func sortedFunc(name string, pick func(k string, v any) any) expr.Option {
	return expr.Function(name, func(args ...any) (any, error) {
		m, ok := args[0].(map[string]any)
		if len(args) != 1 || !ok {
			return nil, fmt.Errorf("%s takes one map", name)
		}
		var out []any
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if err := computedError(m[k]); err != nil && name != "keys" {
				return nil, err
			}
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
	for _, r := range check.names {
		r.pos = n.Pos
		*sc.reads = append(*sc.reads, r)
	}
	if len(check.errs) > 0 {
		var errs []error
		for _, msg := range check.errs {
			errs = append(errs, yamlx.Errorf(n.Pos, "%s", msg))
		}
		return nil, errors.Join(errs...)
	}
	c.reads, c.matches = check.reads, check.matches
	return c, nil
}

// exprCheck finds the variables that an expression reads by name, and
// reports $env, an item that is not defined, and a read of vars other than
// by name.
type exprCheck struct {
	sc  scope
	src file.Source
	// reads are the variables of the host that it reads, and names every
	// read that names a variable.
	reads   []string
	names   []varRead
	matches []matchCall
	errs    []string
	// named are the nodes that a member access with a constant name reads.
	named map[ast.Node]bool
	// whole are the nodes that hold vars: vars, host, and host.vars.
	whole []ast.Node
}

func (c *exprCheck) fail(n ast.Node, msg string) {
	c.errs = append(c.errs, msg+c.snippet(n))
}

func (c *exprCheck) snippet(n ast.Node) string {
	fe := &file.Error{Location: n.Location()}
	return fe.Bind(c.src).Snippet
}

func (c *exprCheck) Visit(np *ast.Node) {
	switch n := (*np).(type) {
	case *ast.IdentifierNode:
		if n.Value == "item" && c.sc.noItem != "" {
			c.fail(n, c.sc.noItem)
		}
		if n.Value == "$env" {
			c.fail(n, "$env is not allowed")
		}
		if n.Value == "match" && c.sc.noMatch != "" {
			c.fail(n, c.sc.noMatch)
		}
		if isVars(n) || n.Value == "host" {
			c.whole = append(c.whole, n)
		}
	case *ast.CallNode:
		id, ok := n.Callee.(*ast.IdentifierNode)
		if !ok || id.Value != "match" || len(n.Arguments) != 1 {
			return
		}
		if pattern, ok := n.Arguments[0].(*ast.StringNode); ok {
			c.matches = append(c.matches, matchCall{pattern: pattern.Value, snippet: c.snippet(n)})
		}
	case *ast.MemberNode:
		if isVars(n) {
			c.whole = append(c.whole, n)
		}
		name, ok := n.Property.(*ast.StringNode)
		if ok {
			c.named[n.Node] = true
		}
		if !ok {
			return
		}
		if isVars(n.Node) {
			c.reads = append(c.reads, name.Value)
		}
		if m, peer := unpatched(n.Node).(*ast.MemberNode); isVars(n.Node) || peer && isName(m.Property, "vars") {
			c.names = append(c.names, varRead{name: name.Value, snippet: c.snippet(n)})
		}
	}
}

// checkByName reports each read of vars other than by name.
func (c *exprCheck) checkByName() {
	for _, n := range c.whole {
		if !c.named[n] {
			c.fail(n, notByName)
		}
	}
}

// unpatched returns n without the call of readFunc that readCheck adds.
func unpatched(n ast.Node) ast.Node {
	if c, ok := n.(*ast.CallNode); ok {
		if id, ok := c.Callee.(*ast.IdentifierNode); ok && id.Value == readFunc {
			return c.Arguments[0]
		}
	}
	return n
}

// isName reports whether n is the constant name.
func isName(n ast.Node, name string) bool {
	s, ok := n.(*ast.StringNode)
	return ok && s.Value == name
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
	return ok && id.Value == "host" && isName(m.Property, "vars")
}

func unknownVariable(name string, known map[string]bool) string {
	return fmt.Sprintf("unknown variable %q%s", name, yamlx.Suggest(name, slices.Sorted(maps.Keys(known))))
}

var (
	unknownNameRe  = regexp.MustCompile(`^unknown name (\w+)$`)
	unknownFieldRe = regexp.MustCompile(`^type (\w+\.\w+) has no field (\w+)$`)
	exprNames      = []string{"vars", "facts", "host", "item", "match"}
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
	return msg + fe.Snippet
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
		out, err := e.render(c.tmpl)
		if err != nil {
			return nil, errors.New(templateMessage(c.tmpl.Name(), err))
		}
		return out, nil
	}
	out, err := expr.Run(c.prog, e.exprEnv())
	if err != nil {
		return nil, errors.New(exprMessage(err, exprNames))
	}
	if err := computedError(out); err != nil {
		return nil, err
	}
	return out, nil
}

// value is a YAML value whose tagged scalars are computed for each host.
type value struct {
	node     *yamlx.Node
	computed map[*yamlx.Node]*computed
	// args is true for module arguments, where a computed null fails.
	args bool
}

// compileValue compiles the tagged scalars of n. It returns nil when n has
// none.
func compileValue(n *yamlx.Node, sc scope) (*value, error) {
	v := &value{node: n, args: sc.args, computed: map[*yamlx.Node]*computed{}}
	var errs []error
	var walk func(n *yamlx.Node, name string)
	walk = func(n *yamlx.Node, name string) {
		switch {
		case n.Tag == "!secret" && !sc.sealed:
			errs = append(errs, yamlx.Errorf(n.Pos, "%s!secret is allowed only in variable values; put it in a variable", prefix(name)))
		case n.Tag == "!secret":
		case n.Tag != "":
			c, err := compile(n, sc)
			errs = append(errs, err)
			v.computed[n] = c
		case n.Kind == yamlx.Null && sc.args && name != "":
			errs = append(errs, yamlx.Errorf(n.Pos, "%snull is not a value", prefix(name)))
		case n.Kind == yamlx.Map:
			for _, p := range n.Pairs {
				walk(p.Value, p.Key)
			}
		case n.Kind == yamlx.List:
			for _, item := range n.Items {
				walk(item, name)
			}
		}
	}
	walk(n, "")
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
		if err == nil && out == nil && v.args {
			err = errors.New("the expression gave null")
		}
		if err != nil && e.failed != nil {
			out, err = secret.Placeholder(e.n), nil
			*e.failed = true
		}
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
