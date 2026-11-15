package project

import (
	"testing"
)

const engineVars = `  l: [x, y]
  m: {b: 2, a: 1}
  mm: {e: 5, c: 3, a: 1, d: 4, b: 2}
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
		{"for over a map", "{{ for v in vars.mm }}{{ v }};{{ end }}", "1;2;3;4;5;"},
		{"for key and value over a map", "{{ for k, v in vars.m }}{{ k }}={{ v }};{{ end }}", "a=1;b=2;"},
		{"for index and element over a list", "{{ for i, x in vars.l }}{{ i }}={{ x }};{{ end }}", "0=x;1=y;"},
		{"map keys that cannot be sorted", "{{ for k, v in groupBy([1, \"a\"], #) }}{{ end }}", "error: " + at + "1:16: for: the keys of the map cannot be sorted\n | {{ for k, v in groupBy([1, \"a\"], #) }}{{ end }}\n | ...............^"},
		{"for over a string", "{{ for x in vars.l[0] }}{{ end }}", "error: " + at + "1:13: for takes a list or a map, got a string\n | {{ for x in vars.l[0] }}{{ end }}\n | ............^"},
		{"comment", "a{{ /* note */ }}b {{- /* x */ -}} c", "abc"},
		{"comparison hint", "{{- if facts.os.version == 13 -}}x{{ end }}", "load error: " + at + "1:25: facts.os.version is a string; compare it with a string, such as \"13\"\n | {{- if facts.os.version == 13 -}}x{{ end }}\n | ........................^"},
		{"comparison hint in a loop", "{{ for x in vars.l }}{{ vars.port < \"8\" }}{{ end }}", "error: " + at + "1:35: vars.port is a number; compare it with a number, such as 8\n | {{ for x in vars.l }}{{ vars.port < \"8\" }}{{ end }}\n | ..................................^"},
		{"comparison hint in a for list", "{{ for k, v in [facts.os.version == 13] }}{{ end }}", "load error: " + at + "1:34: facts.os.version is a string; compare it with a string, such as \"13\"\n | {{ for k, v in [facts.os.version == 13] }}{{ end }}\n | .................................^"},
		{"comparison hint in else if", "{{ if true }}{{ else if facts.os.version == 13 }}{{ end }}", "load error: " + at + "1:42: facts.os.version is a string; compare it with a string, such as \"13\"\n | {{ if true }}{{ else if facts.os.version == 13 }}{{ end }}\n | .........................................^"},
		{"null in an if", "{{ if true }}{{ vars.m.nope }}{{ end }}", "error: " + at + "1:17: the expression gave null\n | {{ if true }}{{ vars.m.nope }}{{ end }}\n | ................^"},
		{"if takes a map", "{{ if vars.m }}x{{ end }}", "error: " + at + "1:7: if: expected true or false, got a map\n | {{ if vars.m }}x{{ end }}\n | ......^"},
		{"for over the host", "{{ for x in host }}{{ end }}", "load error: " + at + "1:13: for takes a list or a map, got a set of fields\n | {{ for x in host }}{{ end }}\n | ............^"},
		{"for over a function", "{{ for x in match }}{{ end }}", "load error: " + at + "1:13: for takes a list or a map, got a function\n | {{ for x in match }}{{ end }}\n | ............^"},
		{"unknown name in a for list", "{{ for x in zzz }}{{ end }}", "load error: " + at + "1:13: unknown name \"zzz\"\n | {{ for x in zzz }}{{ end }}\n | ............^"},
		{"unknown name in a loop body", "{{ for x in vars.l }}{{ zzz }}{{ end }}", "load error: " + at + "1:25: unknown name \"zzz\"\n | {{ for x in vars.l }}{{ zzz }}{{ end }}\n | ........................^"},
		{"loop name outside its loop", "{{ for x in vars.l }}{{ end }}{{ x }}", "load error: " + at + "1:34: unknown name \"x\"\n | {{ for x in vars.l }}{{ end }}{{ x }}\n | .................................^"},
		{"if takes a boolean", "{{ if vars.l }}x{{ end }}", "error: " + at + "1:7: if: expected true or false, got a list\n | {{ if vars.l }}x{{ end }}\n | ......^"},
		{"unclosed if", "a\n{{ if true }}x", "load error: " + at + "2:1: unclosed if\n | {{ if true }}x\n | ^"},
		{"stray end", "x {{ end }}", "load error: " + at + "1:3: unexpected {{end}}\n | x {{ end }}\n | ..^"},
		{"empty action", "{{ }}", "load error: " + at + "1:1: empty action\n | {{ }}\n | ^"},
		{"unclosed action", "a {{ vars.l", "load error: " + at + "1:3: unclosed action\n | a {{ vars.l\n | ..^"},
		{"unclosed string", `{{ "a }}`, "load error: " + at + "1:1: literal not terminated\n | {{ \"a }}\n | ^"},
		{"unknown name", "a\n{{ hots }}", "load error: " + at + "2:4: unknown name \"hots\"; did you mean \"host\"?\n | {{ hots }}\n | ...^"},
		{"unknown name in an expression", "{{ vars.l[0] + nme }}", "load error: " + at + "1:16: unknown name \"nme\"\n | {{ vars.l[0] + nme }}\n | ...............^"},
		{"loop name hides data", "{{ for vars in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name vars hides a name of the data; choose another name\n | {{ for vars in vars.l }}{{ end }}\n | .......^"},
		{"loop key name hides data", "{{ for host, x in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name host hides a name of the data; choose another name\n | {{ for host, x in vars.l }}{{ end }}\n | .......^"},
		{"loop name after a comment", "a {{ for /* c */ host in vars.l }}{{ end }}", "load error: " + at + "1:3: the loop name host hides a name of the data; choose another name\n | a {{ for /* c */ host in vars.l }}{{ end }}\n | ..^"},
		{"loop name $get", "{{ for $get in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name $get hides a name of the data; choose another name\n | {{ for $get in vars.l }}{{ end }}\n | .......^"},
		{"loop name hides an outer loop name", "{{ for x in vars.l }}{{ for i, x in vars.l }}{{ end }}{{ end }}", "load error: " + at + "1:32: the loop name x hides a name of the data; choose another name\n | {{ for x in vars.l }}{{ for i, x in vars.l }}{{ end }}{{ end }}\n | ...............................^"},
		{"vars not by name", "{{ for x in vars }}{{ end }}", "load error: " + at + "1:13: a read of vars names the variable, such as vars.nginx_port\n | {{ for x in vars }}{{ end }}\n | ............^"},
		{"range", "{{ range vars.l }}{{ . }}{{ end }}", "load error: " + at + "1:10: unexpected token Identifier(\"vars\")\n | {{ range vars.l }}{{ . }}{{ end }}\n | .........^"},
		{"loop name item", "{{ for item in vars.l }}{{ end }}", "load error: " + at + "1:8: the loop name item hides a name of the data; choose another name\n | {{ for item in vars.l }}{{ end }}\n | .......^"},
		{"loop name of a function", "{{ for upper in vars.l }}{{ upper }}{{ end }}", "xy"},
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
		{"load error", `'{{ if true }}'`, "load error: recipes/r/recipe.yaml:4:16: unclosed if\n | {{ if true }}\n | ^"},
		{"for over a map", `'{{ for k, v in vars.m }}{{ k }}={{ v }};{{ end }}'`, "a=1;b=2;"},
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
