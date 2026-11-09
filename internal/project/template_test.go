package project

import (
	"testing"
)

const engineVars = `  l: [x, y]
  m: {b: 2, a: 1}
  port: 80
  on: true
  users: [{name: a, pass: p}, {name: b}]
`

// spec: Templates and expressions
func TestTemplateEngine(t *testing.T) {
	const at = "recipes/r/templates/t.tmpl:"
	tests := []struct {
		name string
		text string
		want string
	}{
		{"split on braces", `{{ join(split("a}}b", "}}"), "-") }}`, "a-b"},
		{"list prints as JSON", "{{ vars.l }}", `["x","y"]`},
		{"map prints as JSON", "{{ vars.m }}", `{"a":1,"b":2}`},
		{"for over keys", "{{ for k in keys(vars.m) }}{{ k }}={{ vars.m[k] }};{{ end }}", "a=1;b=2;"},
		{"keys of an empty map", "{{ keys({}) }} {{ values({}) }}", "[] []"},
		{"null", "a\n{{ vars.m.nope }}", "error: " + at + "2:4: the expression gave null\n | {{ vars.m.nope }}\n | ...^"},
		{"null element", "{{ for x in [1, nil] }}{{ x }}{{ end }}", "error: " + at + "1:27: the expression gave null\n | {{ for x in [1, nil] }}{{ x }}{{ end }}\n | ..........................^"},
		{"run error position", "a\nb {{ vars.port + vars.l[0] }}", "error: " + at + "2:16: + cannot take a number and a string\n | b {{ vars.port + vars.l[0] }}\n | ...............^"},
		{"for over a map", "{{ for k in vars.m }}{{ end }}", "error: " + at + "1:13: for takes a list, got a map; loop through its keys: for k in keys(...)\n | {{ for k in vars.m }}{{ end }}\n | ............^"},
		{"if takes a boolean", "{{ if vars.l }}x{{ end }}", "error: " + at + "1:7: if: expected true or false, got a list\n | {{ if vars.l }}x{{ end }}\n | ......^"},
		{"unclosed if", "a\n{{ if true }}x", "load error: " + at + "2:4: if is not closed; add {{ end }}\n | {{ if true }}x\n | ...^"},
		{"stray end", "x {{ end }}", "load error: " + at + "1:6: end without if or for\n | x {{ end }}\n | .....^"},
		{"empty action", "{{ }}", "load error: " + at + "1:4: an action needs an expression\n | {{ }}\n | ...^"},
		{"unclosed action", "a {{ vars.l", "load error: " + at + "1:3: {{ is not closed with }}\n | a {{ vars.l\n | ..^"},
		{"unclosed string", `{{ "a }}`, "load error: " + at + "1:4: the string is not closed\n | {{ \"a }}\n | ...^"},
		{"unknown name", "a\n{{ hots }}", "load error: " + at + "2:4: unknown name \"hots\"; did you mean \"host\"?\n | {{ hots }}\n | ...^"},
		{"unknown name in an expression", "{{ vars.l[0] + nme }}", "load error: " + at + "1:16: unknown name \"nme\"\n | {{ vars.l[0] + nme }}\n | ...............^"},
		{"loop name hides data", "{{ for vars in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name vars hides a name of the data; choose another name\n | {{ for vars in vars.l }}{{ end }}\n | .......^"},
		{"vars not by name", "{{ for x in vars }}{{ end }}", "load error: " + at + "1:13: a read of vars names the variable, such as vars.nginx_port\n | {{ for x in vars }}{{ end }}\n | ............^"},
		{"range", "{{ range vars.l }}{{ . }}{{ end }}", "load error: " + at + "1:4: a template has no range; use for <name> in <list>\n | {{ range vars.l }}{{ . }}{{ end }}\n | ...^\n" + at + "1:22: unexpected token Operator(\".\")\n | {{ range vars.l }}{{ . }}{{ end }}\n | .....................^"},
		{"loop name item", "{{ for item in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name item hides a name of the data; choose another name\n | {{ for item in vars.l }}{{ end }}\n | .......^"},
		{"loop name now", "{{ for now in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name now is a function; choose another name\n | {{ for now in vars.l }}{{ end }}\n | .......^"},
		{"loop field", "{{ for x in vars.l }}{{ $loop[0] }}{{ end }}", "load error: " + at + "1:25: $loop is not allowed\n | {{ for x in vars.l }}{{ $loop[0] }}{{ end }}\n | ........................^"},
		{"read function", "{{ $read(vars.l) }}", "load error: " + at + "1:4: $read is not allowed\n | {{ $read(vars.l) }}\n | ...^"},
		{"column after multi-byte characters", "é→ {{ vars.m.nope }}", "error: " + at + "1:7: the expression gave null\n | é→ {{ vars.m.nope }}\n | ......^"},
		{"line after multi-byte characters", "é\n→ {{ vars.port + vars.l[0] }}", "error: " + at + "2:16: + cannot take a number and a string\n | → {{ vars.port + vars.l[0] }}\n | ...............^"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, engineVars, "  - file:\n      path: /a\n      template: t.tmpl\n",
				map[string]string{"recipes/r/templates/t.tmpl": tt.text})
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// spec: Templates and expressions
func TestInlineTemplate(t *testing.T) {
	tests := []struct {
		name string
		tpl  string
		want string
	}{
		{"print", `'{{ vars.l[1] }}'`, "y"},
		{"for", `'{{ for x in vars.l }}{{ x }},{{ end }}'`, "x,y,"},
		{"null", `'a {{ vars.m.nope }}'`, "error: recipes/r/recipe.yaml:4:16: content: the expression gave null\n | a {{ vars.m.nope }}\n | .....^"},
		{"load error", `'{{ if true }}'`, "load error: recipes/r/recipe.yaml:4:16: if is not closed; add {{ end }}\n | {{ if true }}\n | ...^"},
		{"item outside a loop", `'{{ item }}'`, "load error: recipes/r/recipe.yaml:4:16: item is defined only in a step with loop\n | {{ item }}\n | ...^"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, engineVars, "  - file:\n      path: /a\n      content: !tpl "+tt.tpl+"\n", nil)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// spec: Templates and expressions
func TestTemplateItem(t *testing.T) {
	step := "  - file:\n      path: !tpl /srv/{{ item }}\n      template: t.tmpl\n    loop: [a]\n"
	if got := evalOne(t, engineVars, step, map[string]string{"recipes/r/templates/t.tmpl": "{{ item }}"}); got != "a" {
		t.Errorf("got %q, want %q", got, "a")
	}
	got := evalOne(t, engineVars, "  - file:\n      path: /a\n      template: t.tmpl\n", map[string]string{"recipes/r/templates/t.tmpl": "{{ item }}"})
	want := "load error: recipes/r/recipe.yaml:4:17: template: t.tmpl reads item; item is defined only in a step with loop"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
