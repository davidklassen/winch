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

	tpl "github.com/davidklassen/expr-template"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/file"

	"github.com/davidklassen/winch/internal/yamlx"
)

// template is a parsed template file or !tpl value. A template file has a
// file name; an inline !tpl value has its position instead.
type template struct {
	file string
	pos  yamlx.Pos
	text string
	t    *tpl.Template
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
	tt, err := tpl.New(t.file, exprOptions...).Print(printValue).Parse(t.text)
	if err != nil {
		return nil, t.engineError(err, true)
	}
	t.t = tt
	var errs []error
	t.check(tt.Nodes(), sc, nil, &errs)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return t, nil
}

// loopHidden are the names that a loop name must not hide: the fields of the
// data, and $get, which readCheck calls.
var loopHidden = append(fieldTags(exprEnv{}), getFunc)

// check checks what the expressions of nodes read, as !expr is checked.
// loop holds the names of the loops around nodes.
func (t *template) check(nodes []tpl.Node, sc scope, loop []string, errs *[]error) {
	expr := func(e *tpl.Expr) {
		at := e.Location().From
		where := func(loc file.Location) (yamlx.Pos, string) {
			return t.where(at + loc.From)
		}
		src := e.Program.Source().String()
		if err := ownNames(src); err != nil {
			*errs = append(*errs, exprError(err, src, where))
			return
		}
		c, err := checkProg(e.Program, sc, where)
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
	for _, n := range nodes {
		switch n := n.(type) {
		case *tpl.ActionNode:
			expr(n.Expr)
		case *tpl.IfNode:
			expr(n.Cond)
			t.check(n.Body, sc, loop, errs)
			t.check(n.ElseBody, sc, loop, errs)
		case *tpl.ForNode:
			expr(n.Collection)
			inner := slices.Clip(loop)
			for _, name := range []string{n.Key, n.Elem} {
				if name == "" {
					continue
				}
				if slices.Contains(loopHidden, name) || slices.Contains(loop, name) {
					pos, snippet := t.where(t.loopNameAt(n, name))
					*errs = append(*errs, yamlx.Errorf(pos, "the loop name %s hides a name of the data; choose another name%s", name, snippet))
				}
				inner = append(inner, name)
			}
			t.check(n.Body, sc, inner, errs)
			t.elemValues(n)
		}
	}
}

var loopNamesRe = regexp.MustCompile(`^\{\{-?\s*for\s+([^\s,]+)(?:\s*,\s*([^\s,]+))?`)

// loopNameAt returns the rune offset of the loop name name of n, or the
// offset of n when the action has a comment before its names.
func (t *template) loopNameAt(n *tpl.ForNode, name string) int {
	loc := n.Location()
	action := string([]rune(t.text)[loc.From:loc.To])
	m := loopNamesRe.FindStringSubmatchIndex(action)
	for i := 2; m != nil && i < len(m); i += 2 {
		if m[i] >= 0 && action[m[i]:m[i+1]] == name {
			return loc.From + utf8.RuneCountInString(action[:m[i]])
		}
	}
	return loc.From
}

// elemValues replaces the values of the collection of the loop n, a
// variable, with the fields of its elements that the body reads, when the
// body reads only fields of the element.
func (t *template) elemValues(n *tpl.ForNode) {
	base, name, ok := constKey(unpatched(n.Collection.Program.Node()))
	if !ok || !isVars(base) {
		return
	}
	var fields []string
	if !readsFields(n.Body, n.Elem, &fields) {
		return
	}
	if i := slices.Index(t.values, name); i >= 0 {
		t.values = slices.Delete(t.values, i, i+1)
	}
	for _, f := range fields {
		t.values = append(t.values, name+"."+f)
	}
}

// readsFields adds to fields each field of the loop name that nodes read. It
// returns false when they read the element whole.
func readsFields(nodes []tpl.Node, name string, fields *[]string) bool {
	expr := func(e *tpl.Expr) bool {
		isName := func(n ast.Node) bool {
			id, ok := n.(*ast.IdentifierNode)
			return ok && id.Value == name
		}
		reads, byField := 0, 0
		ast.Walk(new(e.Program.Node()), visitor(func(np *ast.Node) {
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
		case *tpl.ActionNode:
			if !expr(n.Expr) {
				return false
			}
		case *tpl.IfNode:
			if !expr(n.Cond) || !readsFields(n.Body, name, fields) || !readsFields(n.ElseBody, name, fields) {
				return false
			}
		case *tpl.ForNode:
			if !expr(n.Collection) || !readsFields(n.Body, name, fields) {
				return false
			}
		}
	}
	return true
}

// where returns the position and the snippet of the rune offset off.
func (t *template) where(off int) (yamlx.Pos, string) {
	fe := (&file.Error{Location: file.Location{From: off}}).Bind(file.NewSource(t.text))
	if t.file == "" {
		return t.pos, fe.Snippet
	}
	return yamlx.Pos{File: t.file, Line: fe.Line, Col: fe.Column + 1}, fe.Snippet
}

// exec returns the text of the template for env.
func (t *template) exec(env exprEnv) (string, error) {
	var b strings.Builder
	if err := t.t.Execute(&b, env); err != nil {
		return "", t.engineError(err, false)
	}
	return b.String(), nil
}

// engineError returns the winch error of the engine error err. A run error
// of an inline template has no position: the value that holds it adds it.
func (t *template) engineError(err error, load bool) error {
	te, ok := errors.AsType[*tpl.Error](err)
	if !ok {
		return err
	}
	off := 0
	for i, line := range strings.SplitAfter(t.text, "\n") {
		if i == te.Line-1 {
			off += te.Column - 1
			break
		}
		off += utf8.RuneCountInString(line)
	}
	if !load {
		off = exprAt(t.t.Nodes(), off)
	}
	msg := t.problem(te.Message, off)
	pos, snippet := t.where(off)
	if !load && t.file == "" {
		return errors.New(msg + snippet)
	}
	return yamlx.Errorf(pos, "%s%s", msg, snippet)
}

// exprAt returns the offset of the expression of the action of nodes that
// starts at the rune offset off, or off. A run error without a position in
// the expression points to the start of its action.
func exprAt(nodes []tpl.Node, off int) int {
	for _, n := range nodes {
		var e *tpl.Expr
		var inner [][]tpl.Node
		switch n := n.(type) {
		case *tpl.ActionNode:
			e = n.Expr
		case *tpl.IfNode:
			e, inner = n.Cond, [][]tpl.Node{n.Body, n.ElseBody}
		case *tpl.ForNode:
			e, inner = n.Collection, [][]tpl.Node{n.Body}
		}
		if e != nil && n.Location().From == off {
			return e.Location().From
		}
		for _, list := range inner {
			if at := exprAt(list, off); at != off {
				return at
			}
		}
	}
	return off
}

var (
	conditionRe = regexp.MustCompile(`^non-bool expression \(type (.+)\) used as condition$`)
	loopRe      = regexp.MustCompile(`^cannot loop over (.+)$`)
	sortRe      = regexp.MustCompile(`^cannot sort keys of `)
	// blockRe is the start of an action up to its expression, and the trim
	// marker at its end.
	blockRe = regexp.MustCompile(`^-?\s*(?:else\s+if\s|if\s|for\s[^}]*?\sin\s)?|\s-$`)
)

// problem returns the message of the engine message msg of the error at the
// rune offset off: the types in words, and the hints of expr errors.
func (t *template) problem(msg string, off int) string {
	if m := conditionRe.FindStringSubmatch(msg); m != nil {
		return "if: expected true or false, got " + typeWord(m[1])
	}
	if m := loopRe.FindStringSubmatch(msg); m != nil {
		return "for takes a list or a map, got " + typeWord(m[1])
	}
	if sortRe.MatchString(msg) {
		return "for: the keys of the map cannot be sorted"
	}
	// The expression of the action around off, with the block words and the
	// trim markers as spaces, so that off keeps its place in it.
	runes := []rune(t.text)
	start := strings.LastIndex(string(runes[:off]), "{{")
	if start < 0 {
		return msg
	}
	start = utf8.RuneCountInString(string(runes[:off])[:start]) + 2
	src, _, _ := strings.Cut(string(runes[start:]), "}}")
	src = blockRe.ReplaceAllStringFunc(src, func(s string) string {
		return strings.Repeat(" ", utf8.RuneCountInString(s))
	})
	return exprProblem(&file.Error{Location: file.Location{From: off - start}, Message: msg}, src, exprNames)
}

// typeWord names the Go type typ of a value in an error message.
func typeWord(typ string) string {
	switch {
	case strings.HasPrefix(typ, "[]"):
		return "a list"
	case strings.HasPrefix(typ, "map["):
		return "a map"
	case strings.HasPrefix(typ, "func("):
		return "a function"
	}
	if w, ok := typeWords[typ]; ok {
		return w
	}
	return "a set of fields"
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
	for _, n := range t.t.Nodes() {
		if txt, ok := n.(*tpl.TextNode); ok {
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
