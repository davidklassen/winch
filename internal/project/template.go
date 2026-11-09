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
	"unicode/utf8"

	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/file"

	"github.com/davidklassen/winch/internal/tmpl"
	tparse "github.com/davidklassen/winch/internal/tmpl/parse"
	"github.com/davidklassen/winch/internal/yamlx"
)

// template is a parsed template file or !tpl value. A template file has a
// file name; an inline !tpl value has its position instead.
type template struct {
	file string
	pos  yamlx.Pos
	text string
	t    *tmpl.Template
	// readSet holds the reads of all expressions. A field of the elements
	// of a variable x that a loop reads is the value "x.field".
	readSet
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

func parseText(t *template, sc scope) (*template, error) {
	tt, err := tmpl.New(t.file).Expr(exprOptions...).Print(printValue).Parse(t.text)
	if err != nil {
		var errs []error
		for _, e := range joined(err) {
			pe, _ := errors.AsType[*tparse.Error](e)
			errs = append(errs, t.engineError(pe, true))
		}
		return nil, errors.Join(errs...)
	}
	t.t = tt
	var errs []error
	t.check(tt.Tree.Root, sc, &errs)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return t, nil
}

// joined returns the errors that err joins, or err.
func joined(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

// check checks what the expressions of list read, as !expr is checked.
func (t *template) check(list *tparse.ListNode, sc scope, errs *[]error) {
	if list == nil {
		return
	}
	expr := func(n *tparse.ExprNode) {
		where := func(loc file.Location) (yamlx.Pos, string) {
			return t.where(int(n.Pos), loc.From)
		}
		if err := ownNames(n.Src); err != nil {
			*errs = append(*errs, exprError(err, n.Src, where))
			return
		}
		c, err := checkProg(n.Prog, sc, where)
		if err != nil {
			*errs = append(*errs, err)
			return
		}
		t.item = t.item || c.item
		t.data = t.data || c.data
		t.hosts = t.hosts || c.hosts
		t.reads = append(t.reads, c.reads...)
		t.values = append(t.values, c.values...)
		t.peerReads = append(t.peerReads, c.peerReads...)
		t.matches = append(t.matches, c.matches...)
	}
	for _, n := range list.Nodes {
		switch n := n.(type) {
		case *tparse.ActionNode:
			expr(n.Expr)
		case *tparse.IfNode:
			expr(n.Cond)
			t.check(n.List, sc, errs)
			t.check(n.ElseList, sc, errs)
		case *tparse.ForNode:
			expr(n.Expr)
			t.check(n.List, sc, errs)
			t.elemValues(n)
		}
	}
}

// elemValues replaces the values of the list of the loop n, a variable, with
// the fields of its elements that the body reads, when the body reads only
// fields of the element.
func (t *template) elemValues(n *tparse.ForNode) {
	list := n.Expr.Prog.Node()
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
	if !readsFields(n.List, n.Name, &fields) {
		return
	}
	if i := slices.Index(t.values, name); i >= 0 {
		t.values = slices.Delete(t.values, i, i+1)
	}
	for _, f := range fields {
		t.values = append(t.values, name+"."+f)
	}
}

// readsFields adds to fields each field of the loop name that the nodes of
// list read. It returns false when they read the element whole.
func readsFields(list *tparse.ListNode, name string, fields *[]string) bool {
	if list == nil {
		return true
	}
	expr := func(n *tparse.ExprNode) bool {
		isName := func(n ast.Node) bool {
			id, ok := n.(*ast.IdentifierNode)
			return ok && id.Value == name
		}
		reads, byField := 0, 0
		ast.Walk(new(n.Prog.Node()), visitor(func(np *ast.Node) {
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
	for _, n := range list.Nodes {
		switch n := n.(type) {
		case *tparse.ActionNode:
			if !expr(n.Expr) {
				return false
			}
		case *tparse.IfNode:
			if !expr(n.Cond) || !readsFields(n.List, name, fields) || !readsFields(n.ElseList, name, fields) {
				return false
			}
		case *tparse.ForNode:
			if !expr(n.Expr) || !readsFields(n.List, name, fields) {
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

// exec returns the text of the template for env.
func (t *template) exec(env exprEnv) (string, error) {
	var b strings.Builder
	err := t.t.Execute(&b, env)
	if pe, ok := errors.AsType[*tparse.Error](err); ok {
		return "", t.engineError(pe, false)
	}
	return b.String(), err
}

// engineError returns the winch error of the engine error pe. A load error
// of an expression shows a snippet only when expr gives a location. A run
// error of an inline template has no position: the value that holds it adds
// it.
func (t *template) engineError(pe *tparse.Error, load bool) error {
	msg := exprProblem(pe.Err, pe.Expr, exprNames)
	pos, snippet := t.where(int(pe.Pos), 0)
	_, located := errors.AsType[*file.Error](pe.Err)
	switch {
	case load && pe.Expr != "" && !located:
		return yamlx.Errorf(pos, "%s", msg)
	case !load && t.file == "":
		return errors.New(msg + snippet)
	}
	return yamlx.Errorf(pos, "%s%s", msg, snippet)
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
	for _, n := range t.t.Tree.Root.Nodes {
		if txt, ok := n.(*tparse.TextNode); ok {
			b.WriteString(regexp.QuoteMeta(txt.Text))
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
