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
		{"text", "plain\n", "plain\n"},
		{"empty output", "{{ if false }}x{{ end }}", ""},
		{"print", "{{ vars.l[0] }}-{{ host.name }}", "x-web1"},
		{"number", "{{ vars.port + 1 }}", "81"},
		{"boolean", "{{ vars.on }}", "true"},
		{"string with braces", `{{ "a}}b" }}`, "a}}b"},
		{"split on braces", `{{ join(split("a}}b", "}}"), "-") }}`, "a-b"},
		{"map literal", `{{ {"a": {"b": 1}}.a.b }}`, "1"},
		{"list prints as JSON", "{{ vars.l }}", `["x","y"]`},
		{"map prints as JSON", "{{ vars.m }}", `{"a":1,"b":2}`},
		{"if", "{{ if vars.on }}y{{ else }}n{{ end }}", "y"},
		{"if false", "{{ if !vars.on }}y{{ end }}", ""},
		{"else if", "{{ if vars.port == 1 }}a{{ else if vars.port == 80 }}b{{ else }}c{{ end }}", "b"},
		{"else if chain to else", "{{ if vars.port == 1 }}a{{ else if vars.port == 2 }}b{{ else }}c{{ end }}", "c"},
		{"for", "{{ for x in vars.l }}[{{ x }}]{{ end }}", "[x][y]"},
		{"for over keys", "{{ for k in keys(vars.m) }}{{ k }}={{ vars.m[k] }};{{ end }}", "a=1;b=2;"},
		{"for over an empty list", "{{ for x in [] }}x{{ end }}", ""},
		{"keys of an empty map", "{{ keys({}) }} {{ values({}) }}", "[] []"},
		{"for across lines", "{{ for x in\n  vars.l }}{{ x }}{{ end }}", "xy"},
		{"for with tabs", "{{ for\tx\tin\tvars.l }}{{ x }}{{ end }}", "xy"},
		{"nested for", "{{ for x in vars.l }}{{ for y in vars.l }}{{ x }}{{ y }} {{ end }}{{ end }}", "xx xy yx yy "},
		{"if in for", "{{ for u in vars.users }}{{ if u.pass != nil }}{{ u.name }}{{ end }}{{ end }}", "a"},
		{"data in for", "{{ for x in vars.l }}{{ host.name }}{{ end }}", "web1web1"},
		{"loop name after its loop", "{{ for x in vars.l }}{{ end }}{{ for x in vars.m.b..3 }}{{ x }}{{ end }}", "23"},
		{"trim", "a  {{- vars.l[0] -}}  b", "axb"},
		{"trim newlines", "{{ for x in vars.l -}}\n  {{ x }}\n{{- end }}\n", "xy\n"},
		{"trim at start", "{{- vars.l[0] }}", "x"},
		{"trim at end", "{{ vars.l[0] -}}", "x"},
		{"trim both empty text", "\n{{- vars.l[0] -}}\n", "x"},
		{"minus without space", "{{-3}}", "-3"},
		{"minus before braces", "{{ 5 -3 }}", "2"},
		{"missing key in if", "{{ if vars.m.nope != nil }}y{{ else }}n{{ end }}", "n"},
		{"null", "a\n{{ vars.m.nope }}", "error: " + at + "2:4: the expression gave null\n | {{ vars.m.nope }}\n | ...^"},
		{"null element", "{{ for x in [1, nil] }}{{ x }}{{ end }}", "error: " + at + "1:27: the expression gave null\n | {{ for x in [1, nil] }}{{ x }}{{ end }}\n | ..........................^"},
		{"run error position", "a\nb {{ vars.port + vars.l[0] }}", "error: " + at + "2:16: + cannot take a number and a string\n | b {{ vars.port + vars.l[0] }}\n | ...............^"},
		{"for over a map", "{{ for k in vars.m }}{{ end }}", "error: " + at + "1:13: for takes a list, got a map; loop through its keys: for k in keys(...)\n | {{ for k in vars.m }}{{ end }}\n | ............^"},
		{"if takes a boolean", "{{ if vars.l }}x{{ end }}", "error: " + at + "1:7: if: expected true or false, got a list\n | {{ if vars.l }}x{{ end }}\n | ......^"},
		{"unclosed if", "a\n{{ if true }}x", "load error: " + at + "2:4: if is not closed; add {{ end }}\n | {{ if true }}x\n | ...^"},
		{"unclosed for", "{{ for x in vars.l }}{{ if true }}{{ end }}", "load error: " + at + "1:4: for is not closed; add {{ end }}\n | {{ for x in vars.l }}{{ if true }}{{ end }}\n | ...^"},
		{"stray end", "x {{ end }}", "load error: " + at + "1:6: end without if or for\n | x {{ end }}\n | .....^"},
		{"stray else", "{{ else }}", "load error: " + at + "1:4: else without if\n | {{ else }}\n | ...^"},
		{"else in for", "{{ for x in vars.l }}{{ else }}{{ end }}", "load error: " + at + "1:25: else without if\n | {{ for x in vars.l }}{{ else }}{{ end }}\n | ........................^"},
		{"else after else", "{{ if true }}{{ else }}{{ else }}{{ end }}", "load error: " + at + "1:27: else after else\n | {{ if true }}{{ else }}{{ else }}{{ end }}\n | ..........................^"},
		{"empty action", "{{ }}", "load error: " + at + "1:4: an action needs an expression\n | {{ }}\n | ...^"},
		{"empty if", "{{ if }}{{ end }}", "load error: " + at + "1:7: an action needs an expression\n | {{ if }}{{ end }}\n | ......^"},
		{"unclosed action", "a {{ vars.l", "load error: " + at + "1:3: {{ is not closed with }}\n | a {{ vars.l\n | ..^"},
		{"unclosed action with a trim marker", "a {{- vars.l", "load error: " + at + "1:3: {{ is not closed with }}\n | a {{- vars.l\n | ..^"},
		{"unclosed string", `{{ "a }}`, "load error: " + at + "1:4: the string is not closed\n | {{ \"a }}\n | ...^"},
		{"unknown name", "a\n{{ hots }}", "load error: " + at + "2:4: unknown name \"hots\"; did you mean \"host\"?\n | {{ hots }}\n | ...^"},
		{"unknown name in an expression", "{{ vars.l[0] + nme }}", "load error: " + at + "1:16: unknown name \"nme\"\n | {{ vars.l[0] + nme }}\n | ...............^"},
		{"loop name hides data", "{{ for vars in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name vars hides a name of the data; choose another name\n | {{ for vars in vars.l }}{{ end }}\n | .......^"},
		{"loop name hides a loop", "{{ for x in vars.l }}{{ for x in vars.l }}{{ end }}{{ end }}", "load error: " + at + "1:29: the loop name x hides a name of the data; choose another name\n | {{ for x in vars.l }}{{ for x in vars.l }}{{ end }}{{ end }}\n | ............................^"},
		{"loop name is a function", "{{ for len in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name len is a function; choose another name\n | {{ for len in vars.l }}{{ end }}\n | .......^"},
		{"for without in", "{{ for vars.l }}{{ end }}", "load error: " + at + "1:4: use for <name> in <list>\n | {{ for vars.l }}{{ end }}\n | ...^"},
		{"loop name outside its loop", "{{ for x in vars.l }}{{ end }}{{ x }}", "load error: " + at + "1:34: unknown name \"x\"\n | {{ for x in vars.l }}{{ end }}{{ x }}\n | .................................^"},
		{"vars not by name", "{{ for x in vars }}{{ end }}", "load error: " + at + "1:13: a read of vars names the variable, such as vars.nginx_port\n | {{ for x in vars }}{{ end }}\n | ............^"},
		{"range", "{{ range vars.l }}{{ . }}{{ end }}", "load error: " + at + "1:4: a template has no range; use for <name> in <list>\n | {{ range vars.l }}{{ . }}{{ end }}\n | ...^\n" + at + "1:22: unexpected token Operator(\".\")\n | {{ range vars.l }}{{ . }}{{ end }}\n | .....................^"},
		{"with", "{{ with vars.m }}x{{ end }}", "load error: " + at + "1:4: a template has no with; use if <expression>\n | {{ with vars.m }}x{{ end }}\n | ...^"},
		{"else with an expression", "{{ if true }}{{ else x }}{{ end }}", "load error: " + at + "1:21: else takes no expression; use else if\n | {{ if true }}{{ else x }}{{ end }}\n | ....................^"},
		{"loop name item", "{{ for item in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name item hides a name of the data; choose another name\n | {{ for item in vars.l }}{{ end }}\n | .......^"},
		{"loop name true", "{{ for true in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name true is a word of the language; choose another name\n | {{ for true in vars.l }}{{ end }}\n | .......^"},
		{"loop name end", "{{ for end in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name end is a word of the language; choose another name\n | {{ for end in vars.l }}{{ end }}\n | .......^"},
		{"loop name now", "{{ for now in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name now is a function; choose another name\n | {{ for now in vars.l }}{{ end }}\n | .......^"},
		{"loop field", "{{ for x in vars.l }}{{ $loop[0] }}{{ end }}", "load error: " + at + "1:25: $loop is not allowed\n | {{ for x in vars.l }}{{ $loop[0] }}{{ end }}\n | ........................^"},
		{"read function", "{{ $read(vars.l) }}", "load error: " + at + "1:4: $read is not allowed\n | {{ $read(vars.l) }}\n | ...^"},
		{"column after multi-byte characters", "é→ {{ vars.m.nope }}", "error: " + at + "1:7: the expression gave null\n | é→ {{ vars.m.nope }}\n | ......^"},
		{"line after multi-byte characters", "é\n→ {{ vars.port + vars.l[0] }}", "error: " + at + "2:16: + cannot take a number and a string\n | → {{ vars.port + vars.l[0] }}\n | ...............^"},
		{"end with an expression", "{{ if true }}{{ end x }}", "load error: " + at + "1:20: end takes no expression\n | {{ if true }}{{ end x }}\n | ...................^"},
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
