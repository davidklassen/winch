package project

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/builtin"
	"github.com/expr-lang/expr/checker"
	"github.com/expr-lang/expr/compiler"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/parser"
	"github.com/expr-lang/expr/vm"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

// computed is a scalar with the !expr or the !tpl tag, compiled at load.
type computed struct {
	pos  yamlx.Pos
	prog *vm.Program
	tmpl *template
	readSet
}

// readSet is what an expression or a template reads.
type readSet struct {
	// reads are the variables that it reads by name.
	reads []string
	// values are the variables whose values it reads.
	values []string
	// peerReads are the variables that it reads of a host from hosts or
	// match().
	peerReads []string
	// matches are the calls of match() with a constant pattern.
	matches []matchCall
	// data is true when it reads a name other than item, and hosts when it
	// reads hosts. item is true when it reads item.
	data, hosts, item bool
}

// matchCall is a call of match() with a constant pattern. snippet shows the
// call in an expression.
type matchCall struct {
	pos     yamlx.Pos
	pattern string
	snippet string
}

// reach is what the reads of hosts and match() of the project can reach:
// every host, or the hosts of the constant patterns.
type reach struct {
	all      bool
	patterns []string
}

// scope is what an expression or a template can read.
type scope struct {
	// reads logs each read that names a variable, also of a host from
	// match().
	reads *[]varRead
	reach *reach
	// noItem is the reason that item is not defined, or "" when it is.
	noItem string
	// inDefault is true in a default: a !secret value is allowed there.
	inDefault bool
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
	Hosts []any                       `expr:"hosts"`
	Item  any                         `expr:"item"`
	Match func(string) ([]any, error) `expr:"match"`
	// Read checks the value of a member read.
	Read func(any) (any, error) `expr:"$read"`
	// Loop holds the elements of the loops of a template, outermost first.
	Loop []any `expr:"$loop"`
}

type hostEnv struct {
	Name    string         `expr:"name"`
	Short   string         `expr:"short"`
	Address string         `expr:"address"`
	Groups  []string       `expr:"groups"`
	Vars    map[string]any `expr:"vars"`
	Facts   facts.Facts    `expr:"facts"`
}

// exprOptions add quote, sqlquote, and json, and replace keys, values, and toPairs, whose order
// is random in expr, with versions in sorted key order. json replaces toJSON.
// join replaces the join of expr, which takes only strings. $get is the get
// of a value of unknown type; readCheck puts it in place of get.
// The optimizer is off here and for require: it folds map(filter(...)) into a
// node that ast.Walk does not visit, and exprCheck would miss what is in it.
var exprOptions = []expr.Option{
	expr.Env(exprEnv{}),
	expr.Optimize(false),
	expr.DisableBuiltin("keys"),
	expr.DisableBuiltin("values"),
	expr.DisableBuiltin("toPairs"),
	expr.DisableBuiltin("toJSON"),
	expr.DisableBuiltin("join"),
	sortedFunc("keys", func(k string, v any) any { return k }),
	sortedFunc("values", func(k string, v any) any { return v }),
	sortedFunc("toPairs", func(k string, v any) any { return []any{k, v} }),
	expr.Function("join", join, new(func(any, any) string), new(func(any) string)),
	expr.Function(getFunc, get, new(func(any, any) any)),
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

// noExprFuncs are the builtins of expr that exprOptions and exprCheck take
// away.
var noExprFuncs = []string{"now", "toJSON"}

func isExprFunc(name string) bool {
	_, ok := builtin.Index[name]
	return slices.Contains([]string{"match", "quote", "sqlquote", "json"}, name) || ok && !slices.Contains(noExprFuncs, name)
}

const (
	readFunc  = "$read"
	getFunc   = "$get"
	loopField = "$loop"
)

// readCheck checks each member read and get() that gives a value of unknown
// type: such a value can be the marker of a computed default of a host from
// hosts or match(). A get() becomes $get, which checks the type of the key,
// where expr cannot check the key at load.
type readCheck struct{}

func (readCheck) Visit(n *ast.Node) {
	switch m := (*n).(type) {
	case *ast.MemberNode:
		if m.Method {
			return
		}
	case *ast.BuiltinNode:
		if m.Name != "get" || len(m.Arguments) != 2 {
			return
		}
		base, key := m.Arguments[0].Type().Kind(), m.Arguments[1].Type().Kind()
		if base == reflect.Interface || key == reflect.Interface && slices.Contains([]reflect.Kind{reflect.Slice, reflect.Array, reflect.String, reflect.Map}, base) {
			get := &ast.CallNode{Callee: &ast.IdentifierNode{Value: getFunc}, Arguments: m.Arguments}
			get.SetLocation(m.Location())
			ast.Patch(n, &ast.CallNode{Callee: &ast.IdentifierNode{Value: readFunc}, Arguments: []ast.Node{get}})
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
		out := []any{}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if err := computedError(m[k]); err != nil && name != "keys" {
				return nil, err
			}
			out = append(out, pick(k, m[k]))
		}
		return out, nil
	})
}

func join(args ...any) (any, error) {
	sep := ""
	if len(args) == 2 {
		s, ok := args[1].(string)
		if !ok {
			return nil, fmt.Errorf("join: the separator must be a string, got %s", describeValue(args[1]))
		}
		sep = s
	}
	list := reflect.ValueOf(args[0])
	if k := list.Kind(); k != reflect.Slice && k != reflect.Array {
		return nil, fmt.Errorf("join: %s is not a list", describeValue(args[0]))
	}
	parts := make([]string, list.Len())
	for i := range parts {
		e := list.Index(i).Interface()
		switch reflect.ValueOf(e).Kind() {
		case reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			parts[i] = fmt.Sprint(e)
		default:
			return nil, fmt.Errorf("join: the element at index %d is %s", i, describeValue(e))
		}
	}
	return strings.Join(parts, sep), nil
}

// get checks the type of the key, then reads with the get of expr.
func get(args ...any) (any, error) {
	from, key := args[0], args[1]
	keyKind := reflect.ValueOf(key).Kind()
	var number bool
	switch keyKind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		number = true
	}
	switch reflect.ValueOf(from).Kind() {
	case reflect.Slice, reflect.Array:
		if !number {
			return nil, fmt.Errorf("get: a list takes a number, got %s", describeValue(key))
		}
	case reflect.String:
		if !number {
			return nil, fmt.Errorf("get: a string takes a number, got %s", describeValue(key))
		}
	case reflect.Map, reflect.Struct:
		if keyKind != reflect.String {
			return nil, fmt.Errorf("get: a map takes a string, got %s", describeValue(key))
		}
	}
	return builtin.Builtins[builtin.Index["get"]].Func(from, key)
}

func compile(n *yamlx.Node, sc scope) (*computed, error) {
	text, _ := n.Value.(string)
	c := &computed{pos: n.Pos}
	if n.Tag == "!tpl" {
		t, err := parseInline(n.Pos, text, sc)
		if err != nil {
			return nil, err
		}
		c.tmpl, c.readSet = t, t.readSet
		return c, nil
	}
	src := file.NewSource(text)
	check, err := checkExpr(text, nil, sc, func(loc file.Location) (yamlx.Pos, string) {
		return n.Pos, (&file.Error{Location: loc}).Bind(src).Snippet
	})
	if err != nil {
		return nil, err
	}
	c.prog, c.readSet = check.prog, check.readSet
	return c, nil
}

// compileExpr compiles the expression src. Each name of loops reads the
// element of that loop in the field $loop of exprEnv.
func compileExpr(src string, loops []string) (*vm.Program, error) {
	config := conf.CreateNew()
	for _, op := range exprOptions {
		op(config)
	}
	for name := range config.Disabled {
		delete(config.Builtins, name)
	}
	config.Check()
	tree, err := parser.ParseWithConfig(src, config)
	if err != nil {
		return nil, err
	}
	var own error
	ast.Walk(&tree.Node, visitor(func(np *ast.Node) {
		if id, ok := (*np).(*ast.IdentifierNode); ok && own == nil && (id.Value == loopField || id.Value == readFunc || id.Value == getFunc) {
			own = (&file.Error{Location: id.Location(), Message: id.Value + " is not allowed"}).Bind(tree.Source)
		}
	}))
	if own != nil {
		return nil, own
	}
	for i, name := range slices.Backward(loops) {
		tree.Node = &ast.VariableDeclaratorNode{
			Name:  name,
			Value: &ast.MemberNode{Node: &ast.IdentifierNode{Value: loopField}, Property: &ast.IntegerNode{Value: i}},
			Expr:  tree.Node,
		}
	}
	if _, err := new(checker.Checker).PatchAndCheck(tree, config); err != nil {
		return nil, err
	}
	return compiler.Compile(tree, config)
}

// checkExpr compiles the expression src with the loop names loops and
// checks what it reads. where gives the position and the snippet of a
// location in src.
func checkExpr(src string, loops []string, sc scope, where func(file.Location) (yamlx.Pos, string)) (*exprCheck, error) {
	prog, err := compileExpr(src, loops)
	if err != nil {
		fe, ok := errors.AsType[*file.Error](err)
		if !ok {
			pos, _ := where(file.Location{})
			return nil, yamlx.Errorf(pos, "%s", exprProblem(err, src, exprNames))
		}
		pos, snippet := where(fe.Location)
		return nil, yamlx.Errorf(pos, "%s%s", exprProblem(err, src, exprNames), snippet)
	}
	check := &exprCheck{sc: sc, where: where, prog: prog, named: map[ast.Node]bool{}, keysOnly: map[ast.Node]bool{}}
	ast.Walk(new(prog.Node()), visitor(func(np *ast.Node) {
		if c, ok := (*np).(*ast.CallNode); ok && len(c.Arguments) == 1 {
			if id, ok := c.Callee.(*ast.IdentifierNode); ok && id.Value == "keys" {
				check.keysOnly[unpatched(c.Arguments[0])] = true
			}
		}
	}))
	ast.Walk(new(prog.Node()), check)
	check.checkByName()
	*sc.reads = append(*sc.reads, check.names...)
	if len(check.errs) > 0 {
		var errs []error
		for _, e := range check.errs {
			errs = append(errs, e)
		}
		return nil, errors.Join(errs...)
	}
	return check, nil
}

// exprCheck finds the variables that an expression reads by name, and
// reports $env, now(), an item that is not defined, and a read of vars other
// than by name. get() with a constant key reads a peer's variable by name.
type exprCheck struct {
	sc    scope
	where func(file.Location) (yamlx.Pos, string)
	prog  *vm.Program
	readSet
	// names holds every read that names a variable.
	names []varRead
	errs  []*yamlx.Error
	// named are the nodes that a member access with a constant name reads.
	named map[ast.Node]bool
	// keysOnly are the nodes whose keys only are read: the argument of
	// keys().
	keysOnly map[ast.Node]bool
	// whole are the nodes that hold vars: vars, host, host.vars, and the
	// vars of a peer.
	whole []ast.Node
}

func (c *exprCheck) fail(n ast.Node, msg string) {
	pos, snippet := c.where(n.Location())
	c.errs = append(c.errs, yamlx.Errorf(pos, "%s%s", msg, snippet))
}

func (c *exprCheck) Visit(np *ast.Node) {
	if isVars(*np) || isPeerVars(*np) {
		c.whole = append(c.whole, *np)
	}
	if base, key, ok := constKey(*np); ok {
		_, member := (*np).(*ast.MemberNode)
		if member || isPeerVars(base) {
			c.named[base] = true
		}
		if member && isVars(base) {
			c.reads = append(c.reads, key)
			if !c.keysOnly[*np] {
				c.values = append(c.values, key)
			}
		}
		if isPeerVars(base) {
			c.peerReads = append(c.peerReads, key)
		}
		if member && isVars(base) || isPeerVars(base) {
			pos, snippet := c.where((*np).Location())
			c.names = append(c.names, varRead{name: key, pos: pos, snippet: snippet})
		}
	}
	switch n := (*np).(type) {
	case *ast.IdentifierNode:
		if slices.Contains(exprNames, n.Value) && n.Value != "item" {
			c.data = true
		}
		if n.Value == "item" {
			c.item = true
		}
		if n.Value == "item" && c.sc.noItem != "" {
			c.fail(n, c.sc.noItem)
		}
		if n.Value == "$env" {
			c.fail(n, "$env is not allowed")
		}
		if n.Value == "now" {
			c.fail(n, "now() is not allowed")
		}
		if n.Value == "hosts" {
			c.hosts = true
			c.sc.reach.all = true
		}
		if n.Value == "host" {
			c.whole = append(c.whole, n)
		}
	case *ast.BuiltinNode:
		if n.Name == "now" {
			c.fail(n, "now() is not allowed")
		}
	case *ast.CallNode:
		id, ok := n.Callee.(*ast.IdentifierNode)
		if !ok || id.Value != "match" || len(n.Arguments) != 1 {
			return
		}
		pattern, ok := n.Arguments[0].(*ast.StringNode)
		if !ok {
			c.sc.reach.all = true
			return
		}
		pos, snippet := c.where(n.Location())
		c.matches = append(c.matches, matchCall{pos: pos, pattern: pattern.Value, snippet: snippet})
		c.sc.reach.patterns = append(c.sc.reach.patterns, pattern.Value)
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

// unpatched returns n without the call of readFunc that readCheck adds, and
// without the chain node of an optional read such as p?.vars.
func unpatched(n ast.Node) ast.Node {
	if c, ok := n.(*ast.ChainNode); ok {
		n = c.Node
	}
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

// isPeerVars reports whether n reads the vars of a value other than the host,
// such as a host from match(): p.vars or get(p, "vars"). A variable named vars
// is not.
func isPeerVars(n ast.Node) bool {
	base, key, ok := constKey(n)
	return ok && key == "vars" && !isVars(n) && !isVars(base)
}

// constKey returns the value and the key of a read with a constant key:
// x.key, x["key"], or get(x, "key").
func constKey(n ast.Node) (ast.Node, string, bool) {
	switch n := n.(type) {
	case *ast.MemberNode:
		if key, ok := n.Property.(*ast.StringNode); ok {
			return unpatched(n.Node), key.Value, true
		}
	case *ast.BuiltinNode:
		if len(n.Arguments) != 2 || n.Name != "get" {
			return nil, "", false
		}
		if key, ok := n.Arguments[1].(*ast.StringNode); ok {
			return unpatched(n.Arguments[0]), key.Value, true
		}
	case *ast.CallNode:
		if id, ok := n.Callee.(*ast.IdentifierNode); !ok || id.Value != getFunc || len(n.Arguments) != 2 {
			return nil, "", false
		}
		if key, ok := n.Arguments[1].(*ast.StringNode); ok {
			return unpatched(n.Arguments[0]), key.Value, true
		}
	}
	return nil, "", false
}

var (
	unknownNameRe  = regexp.MustCompile(`^unknown name (\w+)$`)
	unknownFieldRe = regexp.MustCompile(`^type (\w+\.\w+) has no field (\w+)$`)
	mismatchRe     = regexp.MustCompile(`^invalid operation: (\S+) \(mismatched types (\S+) and (\S+)\)$`)
	// runMismatchRe is the same error when the expression runs.
	runMismatchRe  = regexp.MustCompile(`^invalid operation: (\S+) (\S+) (\S+)$`)
	expectedBoolRe = regexp.MustCompile(`^expected bool, but got (\S+)$`)
	// predicateKeyRe is the text before a ":" that ends a map key at the
	// start of a predicate in braces, which expr does not read as a map.
	predicateKeyRe = regexp.MustCompile(`\{\s*([\pL\pN_$]+|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`[^`]*`" + `)\s*$`)
	// typeWords name the types of expr in messages.
	typeWords  = map[string]string{"string": "a string", "int": "a number", "int64": "a number", "float": "a number", "float64": "a number", "bool": "a boolean", "array": "a list", "map": "a map", "nil": "null"}
	exprNames  = []string{"vars", "facts", "host", "hosts", "item", "match"}
	osFields   = fieldTags(facts.OS{})
	hostFields = fieldTags(hostEnv{})
	// fieldNames are the fields of the typed data, by the type name in
	// errors of expr.
	fieldNames = map[string]struct {
		noun  string
		names []string
	}{
		"facts.Facts":     {"fact", fieldTags(facts.Facts{})},
		"facts.OS":        {"fact", osFields},
		"facts.SSH":       {"fact", fieldTags(facts.SSH{})},
		"facts.Net":       {"fact", fieldTags(facts.Net{})},
		"project.hostEnv": {"host field", hostFields},
	}
)

// exprMessage returns the message of an expr error of the expression src,
// with a suggestion for an unknown name, and the snippet.
func exprMessage(err error, src string, names []string) string {
	msg := exprProblem(err, src, names)
	if fe, ok := errors.AsType[*file.Error](err); ok {
		return msg + fe.Snippet
	}
	return msg
}

// exprProblem returns the message of an expr error of the expression src,
// with a suggestion for an unknown name, without the snippet.
func exprProblem(err error, src string, names []string) string {
	fe, ok := errors.AsType[*file.Error](err)
	if !ok {
		if m := expectedBoolRe.FindStringSubmatch(err.Error()); m != nil && typeWords[m[1]] != "" {
			return "expected true or false, got " + typeWords[m[1]]
		}
		return err.Error()
	}
	msg := fe.Message
	if m := unknownNameRe.FindStringSubmatch(msg); m != nil && m[1] == "toJSON" {
		msg = `unknown name "toJSON"; use json`
	} else if m != nil {
		msg = fmt.Sprintf("unknown name %q%s", m[1], yamlx.Suggest(m[1], names))
	} else if m := unknownFieldRe.FindStringSubmatch(msg); m != nil {
		if f, ok := fieldNames[m[1]]; ok {
			msg = fmt.Sprintf("unknown %s %q%s", f.noun, m[2], yamlx.Suggest(m[2], f.names))
		}
	} else if m := mismatchRe.FindStringSubmatch(msg); m != nil && typeWords[m[2]] != "" && typeWords[m[3]] != "" {
		msg = mismatch(src, fe.From, m[1], typeWords[m[2]], typeWords[m[3]])
	} else if m := runMismatchRe.FindStringSubmatch(msg); m != nil && typeWords[m[1]] != "" && typeWords[m[3]] != "" {
		msg = mismatch(src, fe.From, m[2], typeWords[m[1]], typeWords[m[3]])
	} else if msg == `unexpected token Operator(":")` && fe.From <= utf8.RuneCountInString(src) && predicateKeyRe.MatchString(string([]rune(src)[:fe.From])) {
		msg += "; put a map in parentheses: map(list, ({key: .x}))"
	}
	return msg
}

// mismatch is the message of the operator op at the offset at in src, whose
// operands have the types left and right. A comparison of a name with a
// constant names the type that the constant needs, such as "13" for a string.
func mismatch(src string, at int, op, left, right string) string {
	msg := fmt.Sprintf("%s cannot take %s and %s", op, left, right)
	if !slices.Contains([]string{"==", "!=", "<", ">", "<=", ">="}, op) {
		return msg
	}
	tree, err := parser.Parse(src)
	if err != nil {
		return msg
	}
	var bin *ast.BinaryNode
	ast.Walk(&tree.Node, visitor(func(n *ast.Node) {
		if b, ok := (*n).(*ast.BinaryNode); ok && b.Operator == op && b.Location().From == at {
			bin = b
		}
	}))
	if bin == nil {
		return msg
	}
	name, value, want := bin.Left, bin.Right, left
	if constant(name) {
		name, value, want = value, name, right
	}
	if constant(name) || !constant(value) {
		return msg
	}
	if want == "a boolean" {
		return fmt.Sprintf("%s is a boolean; compare it with true or false", name)
	}
	msg = fmt.Sprintf("%s is %s; compare it with %s", name, want, want)
	sign := ""
	if u, ok := value.(*ast.UnaryNode); ok {
		sign, value = u.Operator, u.Node
	}
	switch v := value.(type) {
	case *ast.IntegerNode:
		if want == "a string" {
			msg += fmt.Sprintf(", such as %q", sign+strconv.Itoa(v.Value))
		}
	case *ast.FloatNode:
		if want == "a string" {
			msg += fmt.Sprintf(", such as %q", sign+strconv.FormatFloat(v.Value, 'f', -1, 64))
		}
	case *ast.StringNode:
		if _, err := strconv.ParseFloat(v.Value, 64); err == nil && want == "a number" {
			msg += ", such as " + v.Value
		}
	}
	return msg
}

// constant reports whether n is a constant, such as 13, -13, or "13".
func constant(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.IntegerNode, *ast.FloatNode, *ast.StringNode, *ast.BoolNode, *ast.NilNode:
		return true
	case *ast.UnaryNode:
		return n.Operator == "-" && constant(n.Node)
	}
	return false
}

type visitor func(*ast.Node)

func (v visitor) Visit(n *ast.Node) { v(n) }

func fieldTags(v any) []string {
	t := reflect.TypeOf(v)
	var names []string
	for i := range t.NumField() {
		names = append(names, t.Field(i).Tag.Get("expr"))
	}
	return names
}

// evalItem returns the value for item. It is for a computed scalar that reads
// no name but item.
func (c *computed) evalItem(item any) (any, error) {
	env := exprEnv{Item: item, Read: func(v any) (any, error) { return v, nil }}
	if c.tmpl != nil {
		return c.tmpl.exec(env)
	}
	return expr.Run(c.prog, env)
}

// eval returns the value for the environment of a host.
func (c *computed) eval(e *Env) (any, error) {
	env, err := e.exprEnv(c.hosts)
	if err != nil {
		return nil, err
	}
	if c.tmpl != nil {
		return c.tmpl.exec(env)
	}
	out, err := expr.Run(c.prog, env)
	if err != nil {
		return nil, errors.New(exprMessage(err, c.prog.Source().String(), exprNames))
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
		case n.Tag == "!secret" && !sc.inDefault:
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

// peerReads returns the variables that the value reads of a host from hosts
// or match().
func (v *value) peerReads() []string {
	var out []string
	for _, c := range v.computed {
		out = append(out, c.peerReads...)
	}
	return out
}

// values returns the variables whose values the value reads.
func (v *value) values() []string {
	var out []string
	for _, c := range v.computed {
		out = append(out, c.values...)
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
			err = errors.New("null is not a value")
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
		if reflect.ValueOf(v).Kind() == reflect.Func {
			return "a function"
		}
		return "a set of fields"
	}
	return yamlx.Describe(n)
}
