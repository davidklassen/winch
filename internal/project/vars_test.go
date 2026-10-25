package project

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
)

var debian13 = facts.Facts{OS: facts.OS{ID: "debian", Version: "13", Codename: "trixie"}}

var varsProject = map[string]string{
	"winch.yaml": `name: acme
inventory: inventories/test.yaml
vars:
  domain:
  mail_server: false
  admins: [root]
  greeting: !tpl "hello {{ .host.short }}"
`,
	"inventories/test.yaml": `hosts:
  mail.acme.com:
    address: 192.0.2.10
    vars:
      web_port: 8080
  monitor.acme.com: {}
groups:
  all:
    user: admin
    vars:
      domain: acme.com
  mail:
    hosts: [mail.acme.com]
    user: root
    vars:
      mail_server: true
      web_sites: [a, b]
`,
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - recipe: web
      - file:
          path: /etc/motd
          content: !tpl "{{ .vars.greeting }} in {{ index .host.groups 1 }}\n"
        when: !expr 'len(host.groups) > 1'
  - name: mail
    hosts: mail
    steps:
      - file:
          path: !tpl /etc/mail/{{ .item.name }}
          content: !expr item.text
        loop:
          - {name: a, text: "A\n"}
          - name: !expr host.short
            text: !tpl "{{ .vars.domain }}\n"
`,
	"recipes/web/recipe.yaml": `vars:
  web_port: 80
  web_sites: []
  web_name: !expr 'vars.mail_server ? vars.domain : host.name'
  web_title: !expr 'upper(vars.web_name)'
steps:
  - file:
      path: !tpl /etc/web/{{ .item }}.conf
      template: site.tmpl
    loop: !expr vars.web_sites
  - name: Mail only
    file:
      path: /etc/web/mail
      content: !tpl "{{ .vars.web_title }}\n"
    when: !expr vars.mail_server
  - file:
      path: /etc/web/port
      content: !expr 'string(vars.web_port) + " " + facts.os.codename + " " + vars.tools_name + "\n"'
`,
	"recipes/tools/recipe.yaml":       "vars:\n  tools_name: !expr 'vars.web_name + \"-tools\"'\nsteps: []\n",
	"recipes/web/templates/site.tmpl": "server {{ .item }} {{ .vars.web_port }} {{ join .host.groups \",\" }}\n",
}

func describeVars(p *Project) string {
	var b strings.Builder
	for _, h := range p.Inventory.Hosts {
		vars, _ := json.Marshal(h.Vars)
		fmt.Fprintf(&b, "host %s user=%s groups=%s vars=%s\n", h.Name, h.User, strings.Join(h.Groups, ","), vars)
	}
	for _, s := range p.Pipeline.Stages {
		var names []string
		for _, h := range s.Targets {
			names = append(names, h.Name)
		}
		fmt.Fprintf(&b, "stage %s targets=%s\n", s.Name, strings.Join(names, ","))
	}
	return b.String()
}

// spec: Variables; Variables/Sources; Inventory; Inventory/Host patterns; Steps; Templates and expressions/When they run; CLI/Errors
func TestLoadVars(t *testing.T) {
	inv := varsProject["inventories/test.yaml"]
	web := varsProject["recipes/web/recipe.yaml"]
	tests := []struct {
		name  string
		files map[string]string
		set   []string
	}{
		{name: "valid"},
		{name: "set", set: []string{"vars.mail_server=true", "vars.admins=[root, david]"}},
		{name: "set-undeclared", set: []string{"vars.mail_sever=true"}},
		{name: "set-not-vars", set: []string{"mail_server=true"}},
		{name: "set-null", set: []string{"vars.mail_server="}},
		{name: "set-tag", set: []string{"vars.mail_server=!expr x"}},
		{name: "undeclared-in-expr", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "vars.web_port) +", "vars.web_prot) +", 1),
		}},
		{name: "undeclared-in-tpl", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "{{ .vars.web_title }}", "{{ .vars.web_titel }}", 1),
		}},
		{name: "undeclared-in-template-file", files: map[string]string{
			"recipes/web/templates/site.tmpl": "{{ .vars.web_prot }}\n",
		}},
		{name: "undeclared-in-inventory", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "web_port: 8080", "web_prot: 8080", 1),
		}},
		{name: "undeclared-in-host-vars", files: map[string]string{
			"winch.yaml": strings.Replace(varsProject["winch.yaml"], ".host.short", ".host.vars.domian", 1),
		}},
		{name: "missing-required", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "    vars:\n      domain: acme.com\n", "", 1),
		}},
		{name: "missing-required-recipe", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80\n", "web_port: 80\n  web_cert:\n", 1),
		}},
		{name: "null-in-inventory", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "domain: acme.com", "domain:", 1),
		}},
		{name: "two-declarations", files: map[string]string{
			"winch.yaml": varsProject["winch.yaml"] + "  web_port: 81\n",
		}},
		{name: "two-declarations-in-recipes", files: map[string]string{
			"recipes/a/recipe.yaml":   "vars:\n  a_b_x: 1\nsteps: []\n",
			"recipes/a_b/recipe.yaml": "vars:\n  a_b_x: 2\nsteps: []\n",
		}},
		{name: "bad-variable-name", files: map[string]string{
			"winch.yaml": varsProject["winch.yaml"] + "  Bad-Name: 1\n",
		}},
		{name: "recipe-variable-prefix", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80\n", "web_port: 80\n  port: 81\n", 1),
		}},
		{name: "cycle", files: map[string]string{
			"winch.yaml": varsProject["winch.yaml"] + "  a: !expr vars.b\n  b: !tpl '{{ .vars.c }}'\n  c: !expr 'vars[\"a\"]'\n",
		}},
		{name: "cycle-through-host-vars", files: map[string]string{
			"winch.yaml": varsProject["winch.yaml"] + "  a: !expr host.vars.a\n",
		}},
		{name: "unknown-name-in-expr", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr var.mail_server", 1),
		}},
		{name: "unknown-host-field", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, ": host.name'", ": host.nmae'", 1),
		}},
		{name: "unknown-host-field-in-template", files: map[string]string{
			"recipes/web/templates/site.tmpl": "{{ .host.nmae }} {{ .facts.os.idd }}\n",
		}},
		{name: "unknown-fact", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "facts.os.codename", "facts.os.codenam", 1),
		}},
		{name: "item-outside-loop", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "path: /etc/web/port", "path: !expr item", 1),
		}},
		{name: "item-in-when", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "loop: !expr vars.web_sites", "loop: !expr vars.web_sites\n    when: !expr 'item != \"\"'", 1),
		}},
		{name: "item-in-loop", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "loop: !expr vars.web_sites", "loop: !expr '[item]'", 1),
		}},
		{name: "item-in-default", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !expr item", 1),
		}},
		{name: "item-in-template-without-loop", files: map[string]string{
			"recipes/web/recipe.yaml": web + "  - file:\n      path: /etc/web/x\n      template: site.tmpl\n",
		}},
		{name: "when-untagged", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: vars.mail_server", 1),
		}},
		{name: "when-boolean", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: true", 1),
		}},
		{name: "loop-string", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "loop: !expr vars.web_sites", "loop: vars.web_sites", 1),
		}},
		{name: "loop-map", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "loop: !expr vars.web_sites", "loop: {a: b}", 1),
		}},
		{name: "loop-on-recipe-step", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    steps:\n      - recipe: web\n        loop: [a]\n",
		}},
		{name: "recipe-step-when", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    steps:\n      - recipe: web\n        when: !expr vars.mail_server\n",
		}},
		{name: "expr-syntax", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr vars.mail_server ==", 1),
		}},
		{name: "tpl-syntax", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "{{ .vars.web_title }}", "{{ .vars.web_title ", 1),
		}},
		{name: "computed-template-in-stage", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    steps:\n      - file:\n          path: /a\n          template: !tpl '{{ .host.short }}.tmpl'\n",
		}},
		{name: "computed-arg-type", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    steps:\n      - file:\n          path: !expr host.name\n          mode: 0644\n          contnet: x\n",
		}},
		{name: "unknown-host-in-group", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "hosts: [mail.acme.com]", "hosts: [mail.acme.con]", 1),
		}},
		{name: "host-and-group-name", files: map[string]string{
			"inventories/test.yaml": inv + "  monitor.acme.com:\n    hosts: []\n",
		}},
		{name: "group-conflict", files: map[string]string{
			"inventories/test.yaml": inv + "  web:\n    hosts: [mail.acme.com]\n    user: deploy\n    vars:\n      web_sites: [c]\n",
		}},
		{name: "group-same-value", files: map[string]string{
			"inventories/test.yaml": inv + "  web:\n    hosts: [mail.acme.com]\n    vars:\n      web_sites: [a, b]\n",
		}},
		{name: "host-resolves-group-conflict", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "web_port: 8080", "web_port: 8080\n      web_sites: [z]", 1) +
				"  web:\n    hosts: [mail.acme.com]\n    vars:\n      web_sites: [c]\n",
		}},
		{name: "set-resolves-group-conflict", set: []string{"vars.web_sites=[q]"}, files: map[string]string{
			"inventories/test.yaml": inv + "  web:\n    hosts: [mail.acme.com]\n    vars:\n      web_sites: [c]\n",
		}},
		{name: "args-tagged", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    steps:\n      - file: !expr '{\"path\": \"/x\", \"source\": \"a\"}'\n",
		}},
		{name: "group-beats-all-no-merge", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "domain: acme.com", "domain: acme.com\n      web_sites: [x, y, z]\n      mail_server: {a: 1}", 1) +
				"  web:\n    hosts: [monitor.acme.com]\n    vars:\n      mail_server: {b: 2}\n",
		}},
		{name: "computed-source-in-stage", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    steps:\n      - file:\n          path: /a\n          source: !expr host.name\n",
		}},
		{name: "host-user-resolves-group-conflict", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "address: 192.0.2.10", "address: 192.0.2.10\n    user: own", 1) +
				"  web:\n    hosts: [mail.acme.com]\n    user: deploy\n",
		}},
		{name: "group-and-host-order", files: map[string]string{
			"inventories/test.yaml": inv + "  zeta:\n    hosts: [monitor.acme.com, mail.acme.com]\n  alpha:\n    hosts: [mail.acme.com]\n",
			"pipelines/site.yaml":   "stages:\n  - name: web\n    hosts: zeta\n    steps: []\n",
		}},
		{name: "missing-required-recipe-in-group", files: map[string]string{
			"recipes/web/recipe.yaml":   strings.Replace(web, "web_port: 80\n", "web_port: 80\n  web_cert:\n", 1),
			"inventories/test.yaml":     strings.Replace(inv, "web_port: 8080", "web_port: 8080\n      web_cert: x", 1),
			"pipelines/site.yaml":       "stages:\n  - name: web\n    hosts: mail\n    steps:\n      - recipe: web\n  - name: b\n    hosts: monitor.acme.com\n    steps:\n      - recipe: other\n",
			"recipes/other/recipe.yaml": "vars:\n  other_x:\nsteps: []\n",
		}},
		{name: "nested-tag-in-inventory", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "web_sites: [a, b]", "web_sites: [a, !expr b]", 1),
		}},
		{name: "nested-tag-in-set", set: []string{"vars.admins=[!tpl x]"}},
		{name: "tpl-item-outside-loop", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "content: !tpl \"{{ .vars.web_title }}\\n\"", "content: !tpl \"{{ .item }}\"", 1),
		}},
		{name: "unused-recipe-broken", files: map[string]string{
			"recipes/unused/recipe.yaml": "steps:\n  - fiel: {}\n",
		}},
		{name: "tag-in-inventory", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "web_port: 8080", "web_port: !expr 8080", 1),
		}},
		{name: "empty-group", files: map[string]string{
			"inventories/test.yaml": inv + "  empty:\n    hosts: []\n",
			"pipelines/site.yaml":   "stages:\n  - name: web\n    hosts: empty\n    steps: []\n",
		}},
		{name: "unknown-group", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: mial\n    steps: []\n",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, with(varsProject, tt.files))
			p, err := Load(dir, "", "site", tt.set)
			got := ""
			if err != nil {
				got = err.Error() + "\n"
			} else {
				got = describeVars(p)
			}
			golden.Assert(t, filepath.Join("testdata", "vars", tt.name+".golden"), []byte(got))
		})
	}
}

// evalAll returns the evaluated module steps of every host, stage by stage.
func evalAll(t *testing.T, p *Project) string {
	t.Helper()
	var b strings.Builder
	envs := map[string]*Env{}
	for _, h := range p.Inventory.Hosts {
		env, err := p.Start(h, debian13)
		if err != nil {
			fmt.Fprintf(&b, "%s: %v\n", h.Name, err)
			continue
		}
		envs[h.Name] = env
	}
	for _, s := range p.Pipeline.Stages {
		for _, h := range s.Targets {
			env := envs[h.Name]
			if env == nil {
				continue
			}
			fmt.Fprintf(&b, "%s %s\n", h.Name, s.Name)
			for _, st := range s.Steps {
				todo := []Step{st}
				if st.Recipe != nil {
					ok, err := st.Runs(env)
					if err != nil {
						fmt.Fprintf(&b, "  error: %v\n", err)
						continue
					}
					if !ok {
						fmt.Fprintf(&b, "  recipe %s skipped\n", st.Recipe.Name)
						continue
					}
					todo = st.Recipe.Steps
				}
				for _, rs := range todo {
					steps, err := rs.Eval(env)
					if err != nil {
						fmt.Fprintf(&b, "  error: %v\n", err)
						continue
					}
					if steps == nil {
						fmt.Fprintf(&b, "  skipped at %s\n", rs.Pos)
					}
					for _, es := range steps {
						describeStep(&b, "  ", es)
					}
				}
			}
		}
	}
	return b.String()
}

// spec: Templates and expressions/Data; Variables; Variables/Sources; Steps; Inventory
func TestEval(t *testing.T) {
	tests := []struct {
		name  string
		set   []string
		files map[string]string
	}{
		{name: "two-hosts"},
		{name: "set", set: []string{"vars.web_sites=[x]", "vars.web_port=9000"}},
		{name: "expr-snippet", files: map[string]string{
			"pipelines/site.yaml": strings.Replace(varsProject["pipelines/site.yaml"], "'len(host.groups) > 1'", "'host.groups[1] == \"mail\"'", 1),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Load(writeProject(t, with(varsProject, tt.files)), "", "site", tt.set)
			if err != nil {
				t.Fatal(err)
			}
			golden.Assert(t, filepath.Join("testdata", "eval", tt.name+".golden"), []byte(evalAll(t, p)))
		})
	}
}

// evalOne loads a project with one stage step and returns the content of the
// first evaluated step on host web1, or the error.
func evalOne(t *testing.T, vars, step string, files map[string]string) string {
	t.Helper()
	all := map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nvars:\n" + vars,
		"inventories/test.yaml": "hosts:\n  web1:\n    address: 192.0.2.1\n",
		"pipelines/site.yaml":   stage("      - recipe: r\n"),
		"recipes/r/recipe.yaml": recipe(step),
	}
	for k, v := range files {
		all[k] = v
	}
	p, err := Load(writeProject(t, all), "", "site", nil)
	if err != nil {
		return "load error: " + err.Error()
	}
	env, err := p.Start(p.Inventory.Hosts[0], debian13)
	if err != nil {
		return "error: " + err.Error()
	}
	steps, err := p.Pipeline.Stages[0].Steps[0].Recipe.Steps[0].Eval(env)
	if err != nil {
		return "error: " + err.Error()
	}
	if len(steps) == 0 {
		return "no steps"
	}
	return string(steps[0].Args.(*module.File).Data)
}

const valueVars = `  early: !expr 'vars.late + 1'
  late: 2
  f: 8.0
  f2: 8.5
  i: 80
  b: true
  l: [a, b]
  ports: [22, 25]
  m: {k: v, a: 1}
  s: "yes"
  nothing: !expr vars.m.nope
`

// spec: Templates and expressions/Data; Templates and expressions/Template functions; Variables
func TestValues(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"float", "{{ .vars.f }} {{ .vars.f2 }}", "8 8.5"},
		{"int and bool", "{{ .vars.i }} {{ .vars.b }}", "80 true"},
		{"list and map", "{{ .vars.l }} {{ .vars.m }}", "[a b] map[a:1 k:v]"},
		{"join", "{{ join .vars.l \", \" }}|{{ join .vars.ports \",\" }}", "a, b|22,25"},
		{"has", "{{ has .vars.l \"a\" }} {{ has .vars.l \"z\" }} {{ has .vars.ports 22 }}", "true false true"},
		{"title", "{{ title \"hello mail  world\" }}", "Hello Mail  World"},
		{"host groups", "{{ .host.groups }}", "[all]"},
		{"host vars", "{{ .host.vars.i }} {{ .host.address }}", "80 192.0.2.1"},
		{"has keeps types", "{{ has .vars.ports \"22\" }}", "false"},
		{"facts", "{{ .facts.os.id }} {{ .facts.os.version }}", "debian 13"},
		{"missing key", "{{ .vars.m.nope }}", `error: recipes/r/templates/t.tmpl:1:9: .vars.m.nope: map has no entry for key "nope"`},
		{"variable without a value", "{{ .vars.nothing }}", `error: recipes/r/templates/t.tmpl:1:9: .vars.nothing: map has no entry for key "nothing"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, valueVars, "  - file:\n      path: /a\n      template: t.tmpl\n",
				map[string]string{"recipes/r/templates/t.tmpl": tt.text})
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// spec: Templates and expressions; Templates and expressions/Data
func TestExprValues(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want string
	}{
		{"keys are sorted", `join(keys(vars.m), ",")`, "a,k"},
		{"values follow the keys", `join(map(values(vars.m), string(#)), ",")`, "1,v"},
		{"missing key is nil", `vars.m.nope == nil ? "nil" : "set"`, "nil"},
		{"pairs follow the keys", `join(map(toPairs(vars.m), #[0] + "=" + string(#[1])), ",")`, "a=1,k=v"},
		{"no value is nil", `vars.nothing == nil ? "nil" : "set"`, "nil"},
		{"types", `string(vars.i + 1) + string(vars.f2) + string(vars.b)`, "818.5true"},
		{"host", `host.name + " " + host.short + " " + host.address + " " + join(host.groups, ",") + " " + string(host.vars.i)`, "web1 web1 192.0.2.1 all 80"},
		{"defaults in dependency order", `string(vars.early)`, "3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, valueVars, "  - file:\n      path: /a\n      content: !expr '"+strings.ReplaceAll(tt.expr, "'", "''")+"'\n", nil)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// spec: Templates and expressions/When they run; Steps; Modules/file, dir, link
func TestEvalErrors(t *testing.T) {
	tests := []struct {
		name  string
		vars  string
		step  string
		files map[string]string
		want  string
	}{
		{name: "when is a string", step: "  - file:\n      path: /a\n      content: x\n    when: !expr vars.s\n",
			want: `error: recipes/r/recipe.yaml:5:11: when: must be true or false, got the string "yes"`},
		{name: "when is false", step: "  - file:\n      path: /a\n      content: !expr 1 + vars.s\n    when: !expr vars.s == \"no\"\n",
			want: "no steps"},
		{name: "loop is nil", step: "  - file:\n      path: /a\n      content: x\n    loop: !expr vars.m.nope\n",
			want: "error: recipes/r/recipe.yaml:5:11: loop: must be a list, got null"},
		{name: "loop is a map", step: "  - file:\n      path: /a\n      content: x\n    loop: !expr vars.m\n",
			want: "error: recipes/r/recipe.yaml:5:11: loop: must be a list, got a map"},
		{name: "empty loop", step: "  - file:\n      path: /a\n      content: x\n    loop: []\n",
			want: "no steps"},
		{name: "path not absolute", step: "  - file:\n      path: !tpl '{{ .vars.s }}'\n      content: x\n",
			want: "error: recipes/r/recipe.yaml:3:13: path: must be an absolute path"},
		{name: "path not clean", step: "  - file:\n      path: !tpl '/etc/{{ .vars.s }}/'\n      content: x\n",
			want: `error: recipes/r/recipe.yaml:3:13: path: must be a clean path, such as "/etc/yes"`},
		{name: "content not a string", step: "  - file:\n      path: /a\n      content: !expr vars.l\n",
			want: "error: recipes/r/recipe.yaml:4:16: content: expected a string, got a list"},
		{name: "expression fails", step: "  - file:\n      path: /a\n      content: !expr 1 + vars.s\n",
			want: "error: recipes/r/recipe.yaml:4:16: content: invalid operation: int + string\n | 1 + vars.s\n | ..^"},
		{name: "default fails", vars: "  bad: !expr 1 + vars.s\n", step: "  - file:\n      path: /a\n      content: x\n",
			want: "error: winch.yaml:15:8: variable \"bad\": invalid operation: int + string\n | 1 + vars.s\n | ..^"},
		{name: "computed template", step: "  - file:\n      path: /a\n      template: !tpl '{{ .vars.s }}.tmpl'\n",
			files: map[string]string{"recipes/r/templates/yes.tmpl": "{{ .vars.i }}"},
			want:  "80"},
		{name: "missing computed template", step: "  - file:\n      path: /a\n      template: !tpl '{{ .vars.i }}.tmpl'\n",
			files: map[string]string{"recipes/r/templates/yes.tmpl": "x"},
			want:  "error: recipes/r/recipe.yaml:4:17: template: recipes/r/templates/80.tmpl does not exist"},
		{name: "computed source", step: "  - file:\n      path: /a\n      source: !expr item\n    loop: [a.txt]\n",
			files: map[string]string{"recipes/r/files/a.txt": "A\n"},
			want:  "A\n"},
		{name: "missing computed source", step: "  - file:\n      path: /a\n      source: !expr vars.s\n",
			want: "error: recipes/r/recipe.yaml:4:15: source: recipes/r/files/yes does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, valueVars+tt.vars, tt.step, tt.files)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// spec: Variables ("unless when skips the recipe step there"); Running a pipeline/Plan
func TestStartRecipeWhen(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nvars:\n  on: false\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2:\n    vars:\n      on: true\n",
		"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - recipe: r
        when: !expr vars.on
`,
		"recipes/r/recipe.yaml": "require:\n  - !expr 'facts.os.id == \"ubuntu\"'\nvars:\n  r_x:\nsteps: []\n",
	}
	p, err := Load(writeProject(t, files), "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, h := range p.Inventory.Hosts {
		_, err := p.Start(h, debian13)
		got = append(got, fmt.Sprintf("%s: %v", h.Name, err))
	}
	want := []string{
		"web1: <nil>",
		`web2: recipes/r/recipe.yaml:2:5: recipe r requires facts.os.id == "ubuntu"; the host has os.id "debian", os.version "13", os.codename "trixie"`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	files["recipes/r/recipe.yaml"] = "vars:\n  r_x:\nsteps: []\n"
	p, err = Load(writeProject(t, files), "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Start(p.Inventory.Hosts[1], debian13)
	if want := `pipelines/site.yaml:5:9: recipe r: variable "r_x" is required and has no value on web2`; err == nil || err.Error() != want {
		t.Errorf("web2: got %v, want %s", err, want)
	}
}
