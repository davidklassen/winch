// Package parse builds the parse trees of templates for package tmpl. An
// action holds an expr expression, compiled with the loop names around it.
package parse

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/checker"
	"github.com/expr-lang/expr/compiler"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/optimizer"
	exprparser "github.com/expr-lang/expr/parser"
	"github.com/expr-lang/expr/vm"
)

// LoopField is the env field that holds the elements of the loops around an
// expression, outermost first. A loop name is a let over its element: expr
// has no other way to give a name a value at run time. An env for a template
// with for needs this field, of type []any.
const LoopField = "$loop"

// Pos is a byte offset in the text of the template.
type Pos int

func (p Pos) Position() Pos { return p }

type Node interface {
	Position() Pos
}

type ListNode struct {
	Pos
	Nodes []Node
}

// TextNode is text outside actions, after trimming.
type TextNode struct {
	Pos
	Text string
}

// ExprNode is an expression: its source, and its program compiled with the
// loop names around it.
type ExprNode struct {
	Pos
	Src  string
	Prog *vm.Program
}

// ActionNode prints the value of its expression.
type ActionNode struct {
	Pos
	Expr *ExprNode
}

// IfNode runs List when Cond is true, else ElseList, which can be nil. An
// else if is an IfNode alone in ElseList.
type IfNode struct {
	Pos
	Cond           *ExprNode
	List, ElseList *ListNode
}

// ForNode runs List for each element of the list of Expr, as Name.
type ForNode struct {
	Pos
	Name string
	Expr *ExprNode
	List *ListNode
}

type Tree struct {
	Name string
	Root *ListNode
	text string
}

// Error is an error at the byte offset Pos of the text of the template Name,
// at line Line and rune column Col. Expr is the source of the expression that
// Err comes from, or "".
type Error struct {
	Name      string
	Pos       Pos
	Line, Col int
	Expr      string
	Err       error
}

func (e *Error) Error() string {
	msg := e.Err.Error()
	if fe, ok := errors.AsType[*file.Error](e.Err); ok {
		msg = fe.Message
	}
	return fmt.Sprintf("template: %s:%d:%d: %s", e.Name, e.Line, e.Col, msg)
}

func (e *Error) Unwrap() error { return e.Err }

// ErrorAt returns the error err of the expression src at pos. The location
// of an expr error in src moves the position there.
func (t *Tree) ErrorAt(pos Pos, src string, err error) *Error {
	if fe, ok := errors.AsType[*file.Error](err); ok {
		r := []rune(src)
		pos += Pos(len(string(r[:min(max(fe.From, 0), len(r))])))
	}
	line, col := t.lineCol(pos)
	return &Error{Name: t.Name, Pos: pos, Line: line, Col: col, Expr: src, Err: err}
}

func (t *Tree) lineCol(pos Pos) (int, int) {
	fe := (&file.Error{Location: file.Location{From: utf8.RuneCountInString(t.text[:pos])}}).Bind(file.NewSource(t.text))
	return fe.Line, fe.Column + 1
}

// ErrorContext returns the location of n, as name:line:col, and the source of
// its expression or its text.
func (t *Tree) ErrorContext(n Node) (location, context string) {
	line, col := t.lineCol(n.Position())
	switch n := n.(type) {
	case *ExprNode:
		context = n.Src
	case *ActionNode:
		context = n.Expr.Src
	case *IfNode:
		context = n.Cond.Src
	case *ForNode:
		context = n.Expr.Src
	case *TextNode:
		context = n.Text
	}
	return fmt.Sprintf("%s:%d:%d", t.Name, line, col), context
}

// Parse parses text. Each expression compiles with opts.
func Parse(name, text string, opts ...expr.Option) (*Tree, error) {
	p := &parser{tree: &Tree{Name: name, Root: &ListNode{}, text: text}, config: newConfig(opts)}
	p.parse()
	if err := errors.Join(p.errs...); err != nil {
		return nil, err
	}
	return p.tree, nil
}

type parser struct {
	tree   *Tree
	config *conf.Config
	errs   []error
	loops  []string
}

func (p *parser) errorf(pos int, format string, args ...any) {
	p.errs = append(p.errs, p.tree.ErrorAt(Pos(pos), "", fmt.Errorf(format, args...)))
}

// action is the text inside {{ }}: start is the byte offset of {{, in the
// offset of the text, and trimLeft and trimRight are its trim markers.
type action struct {
	start, in           int
	text                string
	trimLeft, trimRight bool
}

// text is a part of the template text outside actions, at the offset at.
type text struct {
	at int
	s  string
}

const spaces = " \t\r\n"

func isSpace(b byte) bool { return strings.IndexByte(spaces, b) >= 0 }

// scan splits the template text into text and actions. The end of an action
// is the first }} outside a string literal and outside the braces of a map.
func (p *parser) scan() []any {
	var out []any
	s := p.tree.text
	i := 0
	for {
		j := strings.Index(s[i:], "{{")
		if j < 0 {
			return append(out, text{i, s[i:]})
		}
		out = append(out, text{i, s[i : i+j]})
		a := action{start: i + j, in: i + j + 2}
		if len(s) > a.in+1 && s[a.in] == '-' && isSpace(s[a.in+1]) {
			a.trimLeft = true
			a.in++
		}
		end, ok := p.actionEnd(a.start, a.in)
		if !ok {
			return nil
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
func (p *parser) actionEnd(start, in int) (int, bool) {
	s := p.tree.text
	depth := 0
	for i := in; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'', '`':
			end := stringEnd(s, i)
			if end < 0 {
				p.errorf(i, "the string is not closed")
				return 0, false
			}
			i = end
		case '{':
			depth++
		case '}':
			if depth == 0 && i+1 < len(s) && s[i+1] == '}' {
				return i, true
			}
			depth = max(depth-1, 0)
		}
	}
	p.errorf(start, "{{ is not closed with }}")
	return 0, false
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
	// ifNode is the innermost if of an if block, which else continues.
	ifNode *IfNode
	// list is the list that the next node goes into.
	list *ListNode
	// done is true after else.
	done bool
}

// forRe matches the text after for: the loop name and the list.
var forRe = regexp.MustCompile(`^\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s`)

// languageWords are the words of expr and of the template blocks, which a
// loop name cannot be.
var languageWords = []string{"true", "false", "nil", "in", "not", "and", "or", "let", "if", "else", "matches", "contains", "startsWith", "endsWith", "for", "end", "range", "with"}

func (p *parser) parse() {
	parts := p.scan()
	if parts == nil {
		return
	}
	for i, x := range parts {
		txt, ok := x.(text)
		if !ok {
			continue
		}
		if i > 0 && parts[i-1].(action).trimRight {
			txt.s = strings.TrimLeft(txt.s, spaces)
		}
		if i+1 < len(parts) && parts[i+1].(action).trimLeft {
			txt.s = strings.TrimRight(txt.s, spaces)
		}
		parts[i] = txt
	}
	var stack []*block
	list := func() *ListNode {
		if len(stack) == 0 {
			return p.tree.Root
		}
		return stack[len(stack)-1].list
	}
	for _, x := range parts {
		if txt, ok := x.(text); ok {
			if txt.s != "" {
				list().Nodes = append(list().Nodes, &TextNode{Pos: Pos(txt.at), Text: txt.s})
			}
			continue
		}
		a := x.(action)
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
			n := &IfNode{Pos: Pos(at), Cond: p.compile(restAt, rest), List: &ListNode{Pos: Pos(at)}}
			list().Nodes = append(list().Nodes, n)
			stack = append(stack, &block{at: at, word: "if", ifNode: n, list: n.List})
		case "else":
			switch {
			case open == nil || open.ifNode == nil:
				p.errorf(at, "else without if")
				continue
			case open.done:
				p.errorf(at, "else after else")
				continue
			}
			in := open.ifNode
			in.ElseList = &ListNode{Pos: Pos(at)}
			open.list = in.ElseList
			if w, r := keyword(strings.TrimLeftFunc(rest, unicode.IsSpace)); w == "if" {
				n := &IfNode{Pos: Pos(at), Cond: p.compile(restAt+len(rest)-len(r), r), List: &ListNode{Pos: Pos(at)}}
				in.ElseList.Nodes = []Node{n}
				open.ifNode, open.list = n, n.List
				continue
			}
			if strings.TrimSpace(rest) != "" {
				p.errorf(restAt, "else takes no expression; use else if")
			}
			open.done = true
		case "for":
			m := forRe.FindStringSubmatchIndex(rest)
			name := "_"
			if m == nil {
				p.errorf(at, "use for <name> in <list>")
			} else if p.loopName(restAt+m[2], rest[m[2]:m[3]]) {
				name = rest[m[2]:m[3]]
			}
			n := &ForNode{Pos: Pos(at), Name: name, List: &ListNode{Pos: Pos(at)}}
			if m != nil {
				n.Expr = p.compile(restAt+m[1], rest[m[1]:])
			}
			list().Nodes = append(list().Nodes, n)
			stack = append(stack, &block{at: at, word: "for", list: n.List})
			p.loops = append(p.loops, name)
		case "range", "with":
			use := map[string]string{"range": "for <name> in <list>", "with": "if <expression>"}[word]
			p.errorf(at, "a template has no %s; use %s", word, use)
			stack = append(stack, &block{at: at, word: word, list: &ListNode{}})
		case "end":
			if strings.TrimSpace(rest) != "" {
				p.errorf(restAt, "end takes no expression")
			}
			if open == nil {
				p.errorf(at, "end without if or for")
				continue
			}
			if open.word == "for" {
				p.loops = p.loops[:len(p.loops)-1]
			}
			stack = stack[:len(stack)-1]
		default:
			n := p.compile(a.in, a.text)
			list().Nodes = append(list().Nodes, &ActionNode{Pos: n.Pos, Expr: n})
		}
	}
	for _, b := range stack {
		p.errorf(b.at, "%s is not closed; add {{ end }}", b.word)
	}
}

// loopName reports whether name at the offset at can be a loop name.
func (p *parser) loopName(at int, name string) bool {
	c := p.config
	_, inEnv := c.Env.Get(&c.NtCache, name)
	_, isFunc := c.Functions[name]
	_, isBuiltin := c.Builtins[name]
	switch {
	case inEnv || slices.Contains(p.loops, name):
		p.errorf(at, "the loop name %s hides a name of the data; choose another name", name)
	case isFunc || isBuiltin:
		p.errorf(at, "the loop name %s is a function; choose another name", name)
	case slices.Contains(languageWords, name):
		p.errorf(at, "the loop name %s is a word of the language; choose another name", name)
	default:
		return true
	}
	return false
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

// compile compiles the expression src at the byte offset at.
func (p *parser) compile(at int, src string) *ExprNode {
	at += len(src) - len(strings.TrimLeftFunc(src, unicode.IsSpace))
	n := &ExprNode{Pos: Pos(at), Src: strings.TrimSpace(src)}
	if n.Src == "" {
		p.errorf(at, "an action needs an expression")
		return n
	}
	prog, err := compileExpr(n.Src, p.loops, p.config)
	if err != nil {
		p.errs = append(p.errs, p.tree.ErrorAt(n.Pos, n.Src, err))
	}
	n.Prog = prog
	return n
}

func newConfig(opts []expr.Option) *conf.Config {
	config := conf.CreateNew()
	for _, op := range opts {
		op(config)
	}
	for name := range config.Disabled {
		delete(config.Builtins, name)
	}
	config.Check()
	return config
}

// compileExpr compiles src as expr.Compile does. Each name of loops reads the
// element of its loop in LoopField.
func compileExpr(src string, loops []string, config *conf.Config) (*vm.Program, error) {
	tree, err := exprparser.ParseWithConfig(src, config)
	if err != nil {
		return nil, err
	}
	var own error
	ast.Walk(&tree.Node, visitor(func(np *ast.Node) {
		if id, ok := (*np).(*ast.IdentifierNode); ok && own == nil && id.Value == LoopField {
			own = (&file.Error{Location: id.Location(), Message: LoopField + " is not allowed"}).Bind(tree.Source)
		}
	}))
	if own != nil {
		return nil, own
	}
	for i, name := range slices.Backward(loops) {
		tree.Node = &ast.VariableDeclaratorNode{
			Name:  name,
			Value: &ast.MemberNode{Node: &ast.IdentifierNode{Value: LoopField}, Property: &ast.IntegerNode{Value: i}},
			Expr:  tree.Node,
		}
	}
	if _, err := new(checker.Checker).PatchAndCheck(tree, config); err != nil {
		return nil, err
	}
	if config.Optimize {
		if err := optimizer.Optimize(&tree.Node, config); err != nil {
			if fe, ok := errors.AsType[*file.Error](err); ok {
				return nil, fe.Bind(tree.Source)
			}
			return nil, err
		}
	}
	return compiler.Compile(tree, config)
}

type visitor func(*ast.Node)

func (v visitor) Visit(n *ast.Node) { v(n) }
