package project

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/vm"

	"github.com/davidklassen/winch/internal/yamlx"
)

// template is a parsed template: text with actions in {{ }}. A template file
// has a file name; an inline !tpl value has its position instead.
type template struct {
	file  string
	pos   yamlx.Pos
	text  string
	nodes []tnode
	// readSet holds the reads of all expressions. A field of the elements
	// of a variable x that a loop reads is the value "x.field".
	readSet
}

type tnode interface{}

type textNode string

// exprNode is an expression at the byte offset at of the template text.
type exprNode struct {
	at   int
	src  string
	prog *vm.Program
}

type printNode struct{ exprNode }

// ifNode chooses the body of the first true condition. The body of else has
// a nil condition.
type ifNode struct {
	conds  []*exprNode
	bodies [][]tnode
}

type forNode struct {
	name  string
	list  exprNode
	body  []tnode
	depth int
}

// parseTemplate parses the template file file. item is allowed: the step
// that uses the file decides.
func parseTemplate(file string, text []byte, sc scope) (*template, error) {
	sc.noItem = ""
	return parseText(&template{file: file, text: string(text)}, sc)
}

// parseInline parses the text of a !tpl value at pos.
func parseInline(pos yamlx.Pos, text string, sc scope) (*template, error) {
	return parseText(&template{pos: pos, text: text}, sc)
}

// action is the text inside {{ }}: start is the byte offset of {{, in the
// offset of the text, and trimLeft and trimRight are its trim markers.
type action struct {
	start, in           int
	text                string
	trimLeft, trimRight bool
}

const spaces = " \t\r\n"

func isSpace(b byte) bool { return strings.IndexByte(spaces, b) >= 0 }

// scan splits the template text into text and actions. The end of an action
// is the first }} outside a string literal and outside the braces of a map.
func (t *template) scan() ([]any, error) {
	var out []any
	s := t.text
	i := 0
	for {
		j := strings.Index(s[i:], "{{")
		if j < 0 {
			out = append(out, textNode(s[i:]))
			return out, nil
		}
		out = append(out, textNode(s[i:i+j]))
		a := action{start: i + j, in: i + j + 2}
		if len(s) > a.in+1 && s[a.in] == '-' && isSpace(s[a.in+1]) {
			a.trimLeft = true
			a.in++
		}
		end, err := t.actionEnd(a.start, a.in)
		if err != nil {
			return nil, err
		}
		if end-1 > a.in && s[end-1] == '-' && isSpace(s[end-2]) {
			a.trimRight = true
			a.text = s[a.in : end-1]
		} else {
			a.text = s[a.in:end]
		}
		out = append(out, a)
		i = end + 2
	}
}

// actionEnd returns the offset of the }} that ends the action at start,
// whose text starts at in.
func (t *template) actionEnd(start, in int) (int, error) {
	s := t.text
	depth := 0
	for i := in; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'', '`':
			end := stringEnd(s, i)
			if end < 0 {
				return 0, t.loadError(i, "the string is not closed")
			}
			i = end
		case '{':
			depth++
		case '}':
			if depth == 0 && i+1 < len(s) && s[i+1] == '}' {
				return i, nil
			}
			depth = max(depth-1, 0)
		}
	}
	return 0, t.loadError(start, "{{ is not closed with }}")
}

// stringEnd returns the offset of the quote that closes the string literal
// that starts at i, or -1.
func stringEnd(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch {
		case s[j] == '\\' && q != '`':
			j++
		case s[j] == q:
			return j
		}
	}
	return -1
}

// block is an open if or for while the parser reads its body.
type block struct {
	at   int
	word string
	node tnode
	// body is the list that the next node goes into.
	body *[]tnode
	// done is true after else.
	done bool
}

// forRe matches the text after for: the loop name and the list.
var forRe = regexp.MustCompile(`^\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s`)

// languageWords are the words of expr and of the template blocks, which a
// loop name cannot be.
var languageWords = []string{"true", "false", "nil", "in", "not", "and", "or", "let", "if", "else", "matches", "contains", "startsWith", "endsWith", "for", "end", "range", "with"}

func parseText(t *template, sc scope) (*template, error) {
	parts, err := t.scan()
	if err != nil {
		return nil, err
	}
	for i, p := range parts {
		txt, ok := p.(textNode)
		if !ok {
			continue
		}
		if i > 0 && parts[i-1].(action).trimRight {
			txt = textNode(strings.TrimLeft(string(txt), spaces))
		}
		if i+1 < len(parts) && parts[i+1].(action).trimLeft {
			txt = textNode(strings.TrimRight(string(txt), spaces))
		}
		parts[i] = txt
	}
	var errs []error
	var stack []*block
	top := &t.nodes
	body := func() *[]tnode {
		if len(stack) == 0 {
			return top
		}
		return stack[len(stack)-1].body
	}
	var loops []string
	compile := func(at int, src string) exprNode {
		lead := len(src) - len(strings.TrimLeftFunc(src, unicode.IsSpace))
		at += lead
		src = strings.TrimSpace(src)
		n := exprNode{at: at, src: src}
		if src == "" {
			errs = append(errs, t.loadError(at, "an action needs an expression"))
			return n
		}
		prog, err := t.compileExpr(at, src, loops, sc)
		if err != nil {
			errs = append(errs, err)
		}
		n.prog = prog
		return n
	}
	for _, p := range parts {
		if txt, ok := p.(textNode); ok {
			if txt != "" {
				*body() = append(*body(), txt)
			}
			continue
		}
		a := p.(action)
		lead := len(a.text) - len(strings.TrimLeftFunc(a.text, unicode.IsSpace))
		at := a.in + lead
		word, rest := keyword(a.text[lead:])
		restAt := at + len(word)
		var open *block
		if len(stack) > 0 {
			open = stack[len(stack)-1]
		}
		switch word {
		case "if":
			n := &ifNode{}
			cond := compile(restAt, rest)
			n.conds = append(n.conds, &cond)
			n.bodies = append(n.bodies, nil)
			*body() = append(*body(), n)
			stack = append(stack, &block{at: at, word: "if", node: n, body: &n.bodies[0]})
		case "else":
			var in *ifNode
			if open != nil {
				in, _ = open.node.(*ifNode)
			}
			switch {
			case in == nil:
				errs = append(errs, t.loadError(at, "else without if"))
				continue
			case open.done:
				errs = append(errs, t.loadError(at, "else after else"))
				continue
			}
			var cond *exprNode
			if w, r := keyword(strings.TrimLeftFunc(rest, unicode.IsSpace)); w == "if" {
				c := compile(restAt+len(rest)-len(r), r)
				cond = &c
			} else if strings.TrimSpace(rest) != "" {
				errs = append(errs, t.loadError(restAt, "else takes no expression; use else if"))
			}
			open.done = cond == nil
			in.conds = append(in.conds, cond)
			in.bodies = append(in.bodies, nil)
			open.body = &in.bodies[len(in.bodies)-1]
		case "for":
			m := forRe.FindStringSubmatchIndex(rest)
			name := "_"
			switch {
			case m == nil:
				errs = append(errs, t.loadError(at, "use for <name> in <list>"))
			case slices.Contains(exprNames, rest[m[2]:m[3]]) || slices.Contains(loops, rest[m[2]:m[3]]):
				errs = append(errs, t.loadError(restAt+m[2], fmt.Sprintf("the loop name %s hides a name of the data; choose another name", rest[m[2]:m[3]])))
			case isExprFunc(rest[m[2]:m[3]]) || slices.Contains(noExprFuncs, rest[m[2]:m[3]]):
				errs = append(errs, t.loadError(restAt+m[2], fmt.Sprintf("the loop name %s is a function; choose another name", rest[m[2]:m[3]])))
			case slices.Contains(languageWords, rest[m[2]:m[3]]):
				errs = append(errs, t.loadError(restAt+m[2], fmt.Sprintf("the loop name %s is a word of the language; choose another name", rest[m[2]:m[3]])))
			default:
				name = rest[m[2]:m[3]]
			}
			n := &forNode{name: name, depth: len(loops)}
			if m != nil {
				n.list = compile(restAt+m[1], rest[m[1]:])
			}
			*body() = append(*body(), n)
			stack = append(stack, &block{at: at, word: "for", node: n, body: &n.body})
			loops = append(loops, name)
		case "range", "with":
			use := map[string]string{"range": "for <name> in <list>", "with": "if <expression>"}[word]
			errs = append(errs, t.loadError(at, fmt.Sprintf("a template has no %s; use %s", word, use)))
			stack = append(stack, &block{at: at, word: word, body: new([]tnode)})
		case "end":
			if strings.TrimSpace(rest) != "" {
				errs = append(errs, t.loadError(restAt, "end takes no expression"))
			}
			if open == nil {
				errs = append(errs, t.loadError(at, "end without if or for"))
				continue
			}
			if open.word == "for" {
				loops = loops[:len(loops)-1]
				t.elemValues(open.node.(*forNode))
			}
			stack = stack[:len(stack)-1]
		default:
			n := &printNode{compile(a.in, a.text)}
			*body() = append(*body(), n)
		}
	}
	for _, b := range stack {
		errs = append(errs, t.loadError(b.at, b.word+" is not closed; add {{ end }}"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return t, nil
}

// keyword returns the block word that s starts with, and the text after it.
func keyword(s string) (string, string) {
	for _, w := range []string{"if", "else", "for", "end", "range", "with"} {
		rest, ok := strings.CutPrefix(s, w)
		if ok && (rest == "" || isSpace(rest[0])) {
			return w, rest
		}
	}
	return "", s
}

// compileExpr compiles the expression src at the byte offset at, with the
// loop names loops, and checks it as !expr is checked.
func (t *template) compileExpr(at int, src string, loops []string, sc scope) (*vm.Program, error) {
	where := func(loc file.Location) (yamlx.Pos, string) {
		return t.where(at, loc.From)
	}
	c, err := checkExpr(src, loops, sc, where)
	if err != nil {
		return nil, err
	}
	t.item = t.item || c.item
	t.data = t.data || c.data
	t.hosts = t.hosts || c.hosts
	t.reads = append(t.reads, c.reads...)
	t.values = append(t.values, c.values...)
	t.peerReads = append(t.peerReads, c.peerReads...)
	t.matches = append(t.matches, c.matches...)
	return c.prog, nil
}

// elemValues replaces the values of the list of the loop n, a variable, with
// the fields of its elements that the body reads, when the body reads only
// fields of the element.
func (t *template) elemValues(n *forNode) {
	if n.list.prog == nil {
		return
	}
	list := n.list.prog.Node()
	for {
		d, ok := list.(*ast.VariableDeclaratorNode)
		if !ok {
			break
		}
		list = d.Expr
	}
	base, name, ok := constKey(unpatched(list))
	if !ok || !isVars(base) {
		return
	}
	var fields []string
	if !readsFields(n.body, n.name, &fields) {
		return
	}
	if i := slices.Index(t.values, name); i >= 0 {
		t.values = slices.Delete(t.values, i, i+1)
	}
	for _, f := range fields {
		t.values = append(t.values, name+"."+f)
	}
}

// readsFields adds to fields each field of the loop name that the nodes
// read. It returns false when they read the element whole.
func readsFields(nodes []tnode, name string, fields *[]string) bool {
	expr := func(n *exprNode) bool {
		if n == nil || n.prog == nil {
			return true
		}
		isName := func(n ast.Node) bool {
			id, ok := n.(*ast.IdentifierNode)
			return ok && id.Value == name
		}
		reads, byField := 0, 0
		ast.Walk(new(n.prog.Node()), visitor(func(np *ast.Node) {
			if base, key, ok := constKey(*np); ok && isName(base) {
				byField++
				*fields = append(*fields, key)
			}
			if isName(*np) {
				reads++
			}
		}))
		return reads == byField
	}
	for _, n := range nodes {
		switch n := n.(type) {
		case *printNode:
			if !expr(&n.exprNode) {
				return false
			}
		case *ifNode:
			for i, c := range n.conds {
				if !expr(c) || !readsFields(n.bodies[i], name, fields) {
					return false
				}
			}
		case *forNode:
			if !expr(&n.list) || !readsFields(n.body, name, fields) {
				return false
			}
		}
	}
	return true
}

// where returns the position and the snippet of the rune offset from of the
// expression at the byte offset at.
func (t *template) where(at, from int) (yamlx.Pos, string) {
	fe := (&file.Error{Location: file.Location{From: utf8.RuneCountInString(t.text[:at]) + from}}).Bind(file.NewSource(t.text))
	if t.file == "" {
		return t.pos, fe.Snippet
	}
	return yamlx.Pos{File: t.file, Line: fe.Line, Col: fe.Column + 1}, fe.Snippet
}

// loadError is the error msg at the byte offset at.
func (t *template) loadError(at int, msg string) error {
	pos, snippet := t.where(at, 0)
	return yamlx.Errorf(pos, "%s%s", msg, snippet)
}

// runError is the error msg of the expression n, at the location of err in
// it when err has one. The error of an inline template has no position: the
// value that holds it adds it.
func (t *template) runError(n *exprNode, msg string, err error) error {
	from := 0
	if fe, ok := errors.AsType[*file.Error](err); ok {
		from = fe.From
	}
	pos, snippet := t.where(n.at, from)
	if t.file == "" {
		return errors.New(msg + snippet)
	}
	return yamlx.Errorf(pos, "%s%s", msg, snippet)
}

// exec returns the text of the template for env.
func (t *template) exec(env exprEnv) (string, error) {
	r := runner{t: t, env: &env}
	err := r.run(t.nodes)
	return r.b.String(), err
}

// runner runs the expressions of a template on one machine and one
// environment.
type runner struct {
	t   *template
	b   strings.Builder
	m   vm.VM
	env *exprEnv
}

func (r *runner) eval(n *exprNode) (any, error) {
	out, err := r.m.Run(n.prog, r.env)
	if err != nil {
		return nil, r.t.runError(n, exprProblem(err, n.src, exprNames), err)
	}
	return out, nil
}

func (r *runner) run(nodes []tnode) error {
	t, env := r.t, r.env
	for _, n := range nodes {
		switch n := n.(type) {
		case textNode:
			r.b.WriteString(string(n))
		case *printNode:
			v, err := r.eval(&n.exprNode)
			if err != nil {
				return err
			}
			s, err := printValue(v)
			if err != nil {
				return t.runError(&n.exprNode, err.Error(), nil)
			}
			r.b.WriteString(s)
		case *ifNode:
			for i, c := range n.conds {
				if c != nil {
					v, err := r.eval(c)
					if err != nil {
						return err
					}
					ok, isBool := v.(bool)
					if !isBool {
						return t.runError(c, "if: expected true or false, got "+describeValue(v), nil)
					}
					if !ok {
						continue
					}
				}
				if err := r.run(n.bodies[i]); err != nil {
					return err
				}
				break
			}
		case *forNode:
			v, err := r.eval(&n.list)
			if err != nil {
				return err
			}
			l := reflect.ValueOf(v)
			if l.Kind() != reflect.Slice && l.Kind() != reflect.Array {
				msg := "for takes a list, got " + describeValue(v)
				if l.Kind() == reflect.Map {
					msg += "; loop through its keys: for k in keys(...)"
				}
				return t.runError(&n.list, msg, nil)
			}
			loop := env.Loop[:n.depth:n.depth]
			for i := range l.Len() {
				env.Loop = append(loop, l.Index(i).Interface())
				if err := r.run(n.body); err != nil {
					return err
				}
			}
			env.Loop = loop
		}
	}
	return nil
}

// printValue returns the text of v: a list or a map as JSON.
func printValue(v any) (string, error) {
	if v == nil {
		return "", errors.New("the expression gave null")
	}
	if s, ok := v.(string); ok {
		return s, computedError(s)
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return fmt.Sprint(v), nil
	}
	return toJSON(v)
}

// namePattern returns a pattern for the values of the template: each action
// can give any text.
func (t *template) namePattern() *regexp.Regexp {
	var b strings.Builder
	for _, n := range t.nodes {
		if txt, ok := n.(textNode); ok {
			b.WriteString(regexp.QuoteMeta(string(txt)))
		} else {
			b.WriteString(".*")
		}
	}
	return regexp.MustCompile("^" + b.String() + "$")
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var sqlEscapes = strings.NewReplacer(`\`, `\\`, "'", "''")

func sqlquote(s string) string {
	return "'" + sqlEscapes.Replace(s) + "'"
}

// jsonEscapes escapes the characters that encoding/json keeps and YAML does
// not allow unescaped: control characters and U+FFFE and U+FFFF.
var jsonEscapes = func() *strings.Replacer {
	pairs := []string{"\ufffe", `\ufffe`, "\uffff", `\uffff`}
	for r := rune(0x7f); r <= 0x9f; r++ {
		pairs = append(pairs, string(r), fmt.Sprintf(`\u%04x`, r))
	}
	return strings.NewReplacer(pairs...)
}()

func toJSON(v any) (string, error) {
	if err := computedIn(v); err != nil {
		return "", err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return jsonEscapes.Replace(strings.TrimSuffix(b.String(), "\n")), nil
}
