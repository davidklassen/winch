package tmpl

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/expr-lang/expr"

	"github.com/davidklassen/winch/internal/tmpl/parse"
)

type env struct {
	L    []any          `expr:"l"`
	M    map[string]any `expr:"m"`
	N    int            `expr:"n"`
	On   bool           `expr:"on"`
	S    string         `expr:"s"`
	E    string         `expr:"ending"`
	Loop []any          `expr:"$loop"`
}

var data = env{
	L:  []any{"x", "y"},
	M:  map[string]any{"a": 1, "b": 2},
	N:  80,
	On: true,
	S:  "str",
	E:  "e",
}

func run(t *Template, text string, d any) (string, error) {
	if _, err := t.Parse(text); err != nil {
		return "", err
	}
	var b strings.Builder
	err := t.Execute(&b, d)
	return b.String(), err
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"text", "plain\n", "plain\n"},
		{"empty", "", ""},
		{"empty output", "{{ if false }}x{{ end }}", ""},
		{"print", "{{ l[0] }}-{{ n }}", "x-80"},
		{"number", "{{ n + 1 }}", "81"},
		{"boolean", "{{ on }}", "true"},
		{"nil", "{{ nil }}", "<no value>"},
		{"list", "{{ l }}", "[x y]"},
		{"string with braces", `{{ "a}}b" }}`, "a}}b"},
		{"string with single quotes", `{{ 'a}}b' }}`, "a}}b"},
		{"string with backticks", "{{ `a}}b` }}", "a}}b"},
		{"escaped quote", `{{ "a\"}}b" }}`, `a"}}b`},
		{"map literal", `{{ {"a": {"b": 1}}.a.b }}`, "1"},
		{"if", "{{ if on }}y{{ else }}n{{ end }}", "y"},
		{"if false", "{{ if !on }}y{{ end }}", ""},
		{"else if", "{{ if n == 1 }}a{{ else if n == 80 }}b{{ else }}c{{ end }}", "b"},
		{"else if to else", "{{ if n == 1 }}a{{ else if n == 2 }}b{{ else }}c{{ end }}", "c"},
		{"else if without else", "{{ if n == 1 }}a{{ else if n == 2 }}b{{ end }}", ""},
		{"for", "{{ for x in l }}[{{ x }}]{{ end }}", "[x][y]"},
		{"for over keys", "{{ for k in sort(keys(m)) }}{{ k }}={{ m[k] }};{{ end }}", "a=1;b=2;"},
		{"for over an empty list", "{{ for x in [] }}x{{ end }}", ""},
		{"for across lines", "{{ for x in\n  l }}{{ x }}{{ end }}", "xy"},
		{"for with tabs", "{{ for\tx\tin\tl }}{{ x }}{{ end }}", "xy"},
		{"nested for", "{{ for x in l }}{{ for y in l }}{{ x }}{{ y }} {{ end }}{{ end }}", "xx xy yx yy "},
		{"if in for", "{{ for x in l }}{{ if x == \"y\" }}{{ x }}{{ end }}{{ end }}", "y"},
		{"for in else", "{{ if !on }}{{ else }}{{ for x in l }}{{ x }}{{ end }}{{ end }}", "xy"},
		{"data in for", "{{ for x in l }}{{ s }}{{ end }}", "strstr"},
		{"outer name after an inner loop", "{{ for x in l }}{{ for y in [1] }}{{ end }}{{ x }}{{ end }}", "xy"},
		{"loop name after its loop", "{{ for x in l }}{{ end }}{{ for x in 2..3 }}{{ x }}{{ end }}", "23"},
		{"trim", "a  {{- l[0] -}}  b", "axb"},
		{"trim newlines", "{{ for x in l -}}\n  {{ x }}\n{{- end }}\n", "xy\n"},
		{"trim at start", "{{- l[0] }}", "x"},
		{"trim at end", "{{ l[0] -}}", "x"},
		{"trim both empty text", "\n{{- l[0] -}}\n", "x"},
		{"minus without space", "{{-3}}", "-3"},
		{"minus before braces", "{{ 5 -3 }}", "2"},
		{"name that starts with a block word", "{{ ending }}", "e"},
		{"loop name that starts with a block word", "{{ for iface in l }}{{ iface }}{{ end }}", "xy"},
		{"backslash in backticks", "{{ `a\\` }}", `a\`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(New("t").Expr(expr.Env(env{})), tt.text, data)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestExecutePointer(t *testing.T) {
	d := data
	got, err := run(New("t").Expr(expr.Env(env{})), "{{ for x in l }}{{ x }}{{ end }}", &d)
	if err != nil {
		t.Fatal(err)
	}
	if got != "xy" {
		t.Errorf("got %q, want %q", got, "xy")
	}
	if d.Loop != nil {
		t.Errorf("Execute changed the data: %v", d.Loop)
	}
	if _, err := run(New("t").Expr(expr.Env(env{})), "{{ for x in l }}{{ x + 1 }}{{ end }}", &d); err == nil {
		t.Fatal("no error")
	}
	if d.Loop != nil {
		t.Errorf("Execute with an error changed the data: %v", d.Loop)
	}
}

func TestExecuteWithoutLoopField(t *testing.T) {
	_, err := run(New("t"), "{{ for x in [1] }}{{ x }}{{ end }}", map[string]any{})
	want := "template: t:1:13: for needs the data to have the field $loop of type []any"
	if err == nil || err.Error() != want {
		t.Errorf("got  %v\nwant %s", err, want)
	}
}

func TestExecuteBeforeParse(t *testing.T) {
	if err := New("t").Execute(io.Discard, data); err == nil {
		t.Error("no error")
	}
}

func TestDisabledBuiltin(t *testing.T) {
	got, err := run(New("t").Expr(expr.Env(env{}), expr.DisableBuiltin("len")), "{{ for len in l }}{{ len }}{{ end }}", data)
	if err != nil {
		t.Fatal(err)
	}
	if got != "xy" {
		t.Errorf("got %q, want %q", got, "xy")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"unclosed if", "a\n{{ if true }}x", "template: t:2:4: if is not closed; add {{ end }}"},
		{"unclosed for", "{{ for x in l }}{{ if true }}{{ end }}", "template: t:1:4: for is not closed; add {{ end }}"},
		{"stray end", "x {{ end }}", "template: t:1:6: end without if or for"},
		{"stray else", "{{ else }}", "template: t:1:4: else without if"},
		{"else in for", "{{ for x in l }}{{ else }}{{ end }}", "template: t:1:20: else without if"},
		{"else after else", "{{ if true }}{{ else }}{{ else }}{{ end }}", "template: t:1:27: else after else"},
		{"else with an expression", "{{ if true }}{{ else x }}{{ end }}", "template: t:1:21: else takes no expression; use else if"},
		{"end with an expression", "{{ if true }}{{ end x }}", "template: t:1:20: end takes no expression"},
		{"empty action", "{{ }}", "template: t:1:4: an action needs an expression"},
		{"empty if", "{{ if }}{{ end }}", "template: t:1:7: an action needs an expression"},
		{"unclosed action", "a {{ l", "template: t:1:3: {{ is not closed with }}"},
		{"unclosed action with a trim marker", "a {{- l", "template: t:1:3: {{ is not closed with }}"},
		{"unclosed string", `{{ "a }}`, "template: t:1:4: the string is not closed"},
		{"unknown name", "a\n{{ nn }}", "template: t:2:4: unknown name nn"},
		{"unknown name in an expression", "{{ n + nme }}", "template: t:1:8: unknown name nme"},
		{"for without in", "{{ for l }}{{ end }}", "template: t:1:4: use for <name> in <list>"},
		{"loop name hides data", "{{ for s in l }}{{ end }}", "template: t:1:8: the loop name s hides a name of the data; choose another name"},
		{"loop name hides a loop", "{{ for x in l }}{{ for x in l }}{{ end }}{{ end }}", "template: t:1:24: the loop name x hides a name of the data; choose another name"},
		{"loop name is a builtin", "{{ for len in l }}{{ end }}", "template: t:1:8: the loop name len is a function; choose another name"},
		{"loop name is a function", "{{ for f in l }}{{ end }}", "template: t:1:8: the loop name f is a function; choose another name"},
		{"loop name true", "{{ for true in l }}{{ end }}", "template: t:1:8: the loop name true is a word of the language; choose another name"},
		{"loop name end", "{{ for end in l }}{{ end }}", "template: t:1:8: the loop name end is a word of the language; choose another name"},
		{"loop name outside its loop", "{{ for x in l }}{{ end }}{{ x }}", "template: t:1:29: unknown name x"},
		{"loop field", "{{ for x in l }}{{ $loop[0] }}{{ end }}", "template: t:1:20: $loop is not allowed"},
		{"range", "{{ range l }}{{ end }}", "template: t:1:4: a template has no range; use for <name> in <list>"},
		{"with", "{{ with m }}x{{ end }}", "template: t:1:4: a template has no with; use if <expression>"},
		{"two errors", "{{ range l }}{{ . }}{{ end }}", "template: t:1:4: a template has no range; use for <name> in <list>\ntemplate: t:1:17: unexpected token Operator(\".\")"},
		{"column after multi-byte characters", "é→ {{ nn }}", "template: t:1:7: unknown name nn"},
		{"trim marker without space", "{{ 3-}}", "template: t:1:5: unexpected token EOF"},
		{"closing brace of no map", "{{ n } }}", "template: t:1:6: unexpected token Bracket(\"}\")"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := expr.Function("f", func(...any) (any, error) { return nil, nil })
			_, err := New("t").Expr(expr.Env(env{}), f).Parse(tt.text)
			if err == nil {
				t.Fatal("no error")
			}
			if err.Error() != tt.want {
				t.Errorf("got  %q\nwant %q", err, tt.want)
			}
			if _, ok := errors.AsType[*parse.Error](err); !ok {
				t.Errorf("%T is not a *parse.Error", err)
			}
		})
	}
}

func TestExecError(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"run error", "a\nb {{ n + l[0] }}", "template: t:2:8: invalid operation: int + string"},
		{"for over a map", "{{ for k in m }}{{ end }}", "template: t:1:13: for takes a list, got a map; loop through its keys: for k in keys(...)"},
		{"for over a string", "{{ for k in s }}{{ end }}", `template: t:1:13: for takes a list, got the string "str"`},
		{"if takes a boolean", "{{ if l }}x{{ end }}", "template: t:1:7: if: expected true or false, got a list"},
		{"else if takes a boolean", "{{ if false }}{{ else if n }}x{{ end }}", "template: t:1:26: if: expected true or false, got the integer 80"},
		{"error in a loop", "{{ for x in l }}{{ x + 1 }}{{ end }}", "template: t:1:22: invalid operation: string + int"},
		{"column after multi-byte characters", "é→ {{ n + l[0] }}", "template: t:1:9: invalid operation: int + string"},
		{"if takes a boolean, got null", "{{ if nil }}x{{ end }}", "template: t:1:7: if: expected true or false, got null"},
		{"if takes a boolean, got a number", "{{ if 1.5 }}x{{ end }}", "template: t:1:7: if: expected true or false, got the number 1.5"},
		{"for takes a list, got a boolean", "{{ for x in on }}{{ end }}", "template: t:1:13: for takes a list, got the boolean true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(New("t").Expr(expr.Env(env{})), tt.text, data)
			e, ok := errors.AsType[ExecError](err)
			if !ok {
				t.Fatalf("got %v, want an ExecError", err)
			}
			if e.Name != "t" {
				t.Errorf("Name is %q, want t", e.Name)
			}
			if _, ok := e.Err.(*parse.Error); !ok {
				t.Errorf("Err is %T, want *parse.Error", e.Err)
			}
			if _, ok := errors.AsType[*parse.Error](err); !ok {
				t.Error("errors.As finds no *parse.Error")
			}
			if err.Error() != tt.want {
				t.Errorf("got  %q\nwant %q", err, tt.want)
			}
		})
	}
}

func TestPrint(t *testing.T) {
	print := func(v any) (string, error) {
		if v == nil {
			return "", errors.New("the expression gave null")
		}
		b, err := json.Marshal(v)
		return string(b), err
	}
	tests := []struct {
		name string
		text string
		want string
	}{
		{"list", "{{ l }}", `["x","y"]`},
		{"map", "{{ m }}", `{"a":1,"b":2}`},
		{"string", "{{ s }}", `"str"`},
		{"nil", "a {{ nil }}", "error: template: t:1:6: the expression gave null"},
		{"nil element", "{{ for x in [1, nil] }}{{ x }}{{ end }}", "error: template: t:1:27: the expression gave null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(New("t").Expr(expr.Env(env{})).Print(print), tt.text, data)
			if err != nil {
				got = "error: " + err.Error()
			}
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestTree(t *testing.T) {
	tm, err := New("t").Expr(expr.Env(env{})).Parse("a\n{{ if on }}{{ n }}{{ end }}")
	if err != nil {
		t.Fatal(err)
	}
	if tm.Name() != "t" {
		t.Errorf("Name() is %q, want t", tm.Name())
	}
	nodes := tm.Tree.Root.Nodes
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}
	if n, ok := nodes[0].(*parse.TextNode); !ok || n.Text != "a\n" {
		t.Errorf("first node is %#v, want the text a", nodes[0])
	}
	n, ok := nodes[1].(*parse.IfNode)
	if !ok {
		t.Fatalf("second node is %T, want *parse.IfNode", nodes[1])
	}
	if n.Cond.Src != "on" || n.Cond.Prog == nil {
		t.Errorf("condition is %q with program %v", n.Cond.Src, n.Cond.Prog)
	}
	contexts := []struct {
		node     parse.Node
		loc, ctx string
	}{
		{nodes[0], "t:1:1", "a\n"},
		{n, "t:2:4", "on"},
		{n.List.Nodes[0], "t:2:15", "n"},
	}
	for _, c := range contexts {
		if loc, ctx := tm.Tree.ErrorContext(c.node); loc != c.loc || ctx != c.ctx {
			t.Errorf("ErrorContext of %T gives %q, %q; want %q, %q", c.node, loc, ctx, c.loc, c.ctx)
		}
	}
	f, err := New("t").Expr(expr.Env(env{})).Parse("{{ for x in l }}{{ end }}")
	if err != nil {
		t.Fatal(err)
	}
	if loc, ctx := f.Tree.ErrorContext(f.Tree.Root.Nodes[0]); loc != "t:1:4" || ctx != "l" {
		t.Errorf("ErrorContext of a for gives %q, %q; want t:1:4, l", loc, ctx)
	}
}

func TestMust(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Must did not panic")
		}
	}()
	Must(New("t").Parse("{{ if }}"))
}
