package project

import (
	"encoding/json"
	"fmt"
	"maps"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
)

var debian13 = facts.Facts{OS: facts.OS{ID: "debian", Version: "13", Codename: "trixie", Arch: "amd64"}}

var varsProject = map[string]string{
	"winch.yaml": `name: acme
inventory: test
vars:
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
		{name: "read-without-value", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "    vars:\n      domain: acme.com\n", "", 1),
		}},
		{name: "declaration-without-default", files: map[string]string{
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
		{name: "when-in-vars", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr '\"web_port\" in vars'", 1),
		}},
		{name: "when-vars-item", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr 'vars[item] != \"\"'", 1),
		}},
		{name: "when-keys-vars", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr 'len(keys(vars)) > 0'", 1),
		}},
		{name: "when-in-host-vars", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr '\"domain\" in host.vars'", 1),
		}},
		{name: "when-host-vars-by-name", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr 'host.vars[\"mail_server\"]'", 1),
		}},
		{name: "when-env", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr '$env.vars.mail_server'", 1),
		}},
		{name: "when-now", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr 'now().Year() > 2000'", 1),
		}},
		{name: "arg-env", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "content: !expr 'string(vars.web_port)", "content: !expr 'string($env.vars.web_port)", 1),
		}},
		{name: "loop-env", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "loop: !expr vars.web_sites", "loop: !expr $env.vars.web_sites", 1),
		}},
		{name: "default-env", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !expr $env.vars.domain", 1),
		}},
		{name: "when-whole-host", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr 'json(host) != \"\"'", 1),
		}},
		{name: "to-json", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "when: !expr vars.mail_server", "when: !expr 'toJSON(vars.mail_server) != \"\"'", 1),
		}},
		{name: "default-tpl-dot", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !tpl '{{ . }}'", 1),
		}},
		{name: "default-tpl-dollar", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !tpl '{{ $ }}'", 1),
		}},
		{name: "default-tpl-with-host", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !tpl '{{ with .host }}{{ .vars.domain }}{{ end }}'", 1),
		}},
		{name: "loop-keys-vars", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "loop: !expr vars.web_sites", "loop: !expr keys(vars)", 1),
		}},
		{name: "default-len-vars", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !expr len(vars)", 1),
		}},
		{name: "default-tpl-range-vars", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !tpl '{{ range .vars }}x{{ end }}'", 1),
		}},
		{name: "default-tpl-index-vars", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !tpl '{{ index .vars \"domain\" }}'", 1),
		}},
		{name: "default-tpl-get-vars", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "web_port: 80", "web_port: !tpl '{{ get .vars \"domain\" }}'", 1),
		}},
		{name: "arg-vars-item", files: map[string]string{
			"recipes/web/recipe.yaml": strings.Replace(web, "path: !tpl /etc/web/{{ .item }}.conf", "path: !expr '\"/etc/web/\" + vars[item]'", 1),
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
			p, err := Load(t.Context(), dir, "", "site", tt.set, Keys{})
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

// spec: Variables/Sources
func TestSetValues(t *testing.T) {
	tests := []struct {
		set     string
		want    any
		wantErr string
	}{
		{set: "Hello # world", wantErr: `--set vars.domain=Hello # world: YAML drops the comment; quote it: "Hello # world"`},
		{set: "[a, b] # c", wantErr: `--set vars.domain=[a, b] # c: YAML drops the comment; quote it: "[a, b] # c"`},
		{set: "8.0", wantErr: `--set vars.domain=8.0: YAML reads 8.0 as 8; quote it: "8.0"`},
		{set: "1.10", wantErr: `--set vars.domain=1.10: YAML reads 1.10 as 1.1; quote it: "1.10"`},
		{set: "0123", wantErr: `--set vars.domain=0123: YAML reads 0123 as 123; quote it: "0123"`},
		{set: "[1, 1.10]", wantErr: `--set vars.domain=[1, 1.10]: YAML reads 1.10 as 1.1; quote it: "1.10"`},
		{set: "a: b", wantErr: `--set vars.domain=a: b: YAML reads a map; quote it: "a: b"`},
		{set: `"8.0" # x`, wantErr: `--set vars.domain="8.0" # x: YAML drops the comment; quote it: "\"8.0\" # x"`},
		{set: "#tag", wantErr: `--set vars.domain=#tag: YAML reads null; quote it: "#tag"`},
		{set: "null", wantErr: `--set vars.domain=null: YAML reads null; quote it: "null"`},
		{set: "Hello\nWorld", wantErr: "--set vars.domain=Hello\nWorld: YAML changes the text; quote it: \"Hello\\nWorld\""},
		{set: "|", wantErr: `--set vars.domain=|: YAML changes the text; quote it: "|"`},
		{set: "-", wantErr: `--set vars.domain=-: YAML changes the text; quote it: "-"`},
		{set: "Hello ", wantErr: `--set vars.domain=Hello : YAML changes the text; quote it: "Hello "`},
		{set: "[{a: 1.10}]", wantErr: `--set vars.domain=[{a: 1.10}]: YAML reads 1.10 as 1.1; quote it: "1.10"`},
		{set: "0x1F", wantErr: `--set vars.domain=0x1F: YAML reads 0x1F as 31; quote it: "0x1F"`},
		{set: "1e3", wantErr: `--set vars.domain=1e3: YAML reads 1e3 as 1000; quote it: "1e3"`},
		{set: "+5", wantErr: `--set vars.domain=+5: YAML reads +5 as 5; quote it: "+5"`},
		{set: `"Hello\nWorld"`, want: "Hello\nWorld"},
		{set: `"-"`, want: "-"},
		{set: "false", want: false},
		{set: `"Hello # world"`, want: "Hello # world"},
		{set: `"8.0"`, want: "8.0"},
		{set: `'1.10'`, want: "1.10"},
		{set: `"0123"`, want: "0123"},
		{set: `"a: b"`, want: "a: b"},
		{set: "Hello#world", want: "Hello#world"},
		{set: "8", want: 8},
		{set: "-3", want: -3},
		{set: "1.5", want: 1.5},
		{set: "true", want: true},
		{set: "[a, 2]", want: []any{"a", 2}},
	}
	for _, tt := range tests {
		t.Run(tt.set, func(t *testing.T) {
			p, err := Load(t.Context(), writeProject(t, varsProject), "", "site", []string{"vars.domain=" + tt.set}, Keys{})
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Inventory.Hosts[0].Vars["domain"]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("value %#v, want %#v", got, tt.want)
			}
		})
	}
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
			p, err := Load(t.Context(), writeProject(t, with(varsProject, tt.files)), "", "site", tt.set, Keys{})
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
		"winch.yaml":            "name: acme\ninventory: test\nvars:\n" + vars,
		"inventories/test.yaml": "hosts:\n  web1:\n    address: 192.0.2.1\n",
		"pipelines/site.yaml":   stage("      - recipe: r\n"),
		"recipes/r/recipe.yaml": recipe(step),
	}
	for k, v := range files {
		all[k] = v
	}
	p, err := Load(t.Context(), writeProject(t, all), "", "site", nil, Keys{})
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
	f, ok := steps[0].Args.(*module.File)
	if !ok {
		return "no error"
	}
	return string(f.Data)
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
		{"facts", "{{ .facts.os.id }} {{ .facts.os.version }} {{ .facts.os.codename }} {{ .facts.os.arch }}", "debian 13 trixie amd64"},
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

// spec: Templates and expressions/Template functions
func TestQuote(t *testing.T) {
	values := []string{"", "a b", "it's", "''", "x; echo pwned", "a\nb", "$HOME $(id) `id`", `\ "`}
	for _, v := range values {
		vars := "  v: " + strconv.Quote(v) + "\n"
		for kind, content := range map[string]string{
			"tpl":  `!tpl "printf %s {{ quote .vars.v }}"`,
			"expr": `!expr '"printf %s " + quote(vars.v)'`,
		} {
			t.Run(fmt.Sprintf("%s %q", kind, v), func(t *testing.T) {
				cmd := evalOne(t, vars, "  - file:\n      path: /a\n      content: "+content+"\n", nil)
				if strings.HasPrefix(cmd, "error: ") || strings.HasPrefix(cmd, "load error: ") {
					t.Fatal(cmd)
				}
				out, err := exec.Command("sh", "-c", cmd).Output()
				if err != nil {
					t.Fatalf("sh -c %q: %v", cmd, err)
				}
				if string(out) != v {
					t.Errorf("sh -c %q\ngot  %q\nwant %q", cmd, out, v)
				}
			})
		}
	}
}

// spec: Templates and expressions/Template functions
func TestSQLQuote(t *testing.T) {
	tests := []struct{ value, want string }{
		{"", "''"},
		{"secret", "'secret'"},
		{"it's", "'it''s'"},
		{`a\b`, `'a\\b'`},
		{`\'`, `'\\'''`},
		{"a\nb", "'a\nb'"},
	}
	for _, tt := range tests {
		vars := "  v: " + strconv.Quote(tt.value) + "\n"
		for kind, content := range map[string]string{
			"tpl":  `!tpl "{{ sqlquote .vars.v }}"`,
			"expr": `!expr sqlquote(vars.v)`,
		} {
			t.Run(fmt.Sprintf("%s %q", kind, tt.value), func(t *testing.T) {
				got := evalOne(t, vars, "  - file:\n      path: /a\n      content: "+content+"\n", nil)
				if got != tt.want {
					t.Errorf("got  %q\nwant %q", got, tt.want)
				}
			})
		}
	}
}

// spec: Templates and expressions/Template functions
func TestJSON(t *testing.T) {
	tests := []struct{ value, want string }{
		{`""`, `""`},
		{`plain`, `"plain"`},
		{`'say "hi"'`, `"say \"hi\""`},
		{`'a\b'`, `"a\\b"`},
		{`"a\nb\r\tc"`, `"a\nb\r\tc"`},
		{`"\x01\x1f\x7f\u0085"`, `"\u0001\u001f\u007f\u0085"`},
		{`"\u2028\u2029"`, `"\u2028\u2029"`},
		{`"\uFFFE\uFFFF"`, `"\ufffe\uffff"`},
		{`grüße 日本`, `"grüße 日本"`},
		{`"<a&b> it's / ok"`, `"<a&b> it's / ok"`},
		{`80`, `80`},
		{`8.5`, `8.5`},
		{`true`, `true`},
		{`[a, 1, "x\"y", [], {}]`, `["a",1,"x\"y",[],{}]`},
		{`{b: [1, 2], a: {"k\n": "v\\"}, "ü": null}`, `{"a":{"k\n":"v\\"},"b":[1,2],"ü":null}`},
	}
	for _, tt := range tests {
		vars := "  v: " + tt.value + "\n"
		var want any
		if err := yaml.Unmarshal([]byte(tt.value), &want); err != nil {
			t.Fatal(err)
		}
		for kind, content := range map[string]string{
			"tpl":  `!tpl "{{ json .vars.v }}"`,
			"expr": `!expr json(vars.v)`,
		} {
			t.Run(fmt.Sprintf("%s %s", kind, tt.value), func(t *testing.T) {
				got := evalOne(t, vars, "  - file:\n      path: /a\n      content: "+content+"\n", nil)
				if got != tt.want {
					t.Fatalf("got  %s\nwant %s", got, tt.want)
				}
				var fromJSON, fromYAML any
				if err := json.Unmarshal([]byte(got), &fromJSON); err != nil {
					t.Fatalf("not JSON: %v", err)
				}
				if err := yaml.Unmarshal([]byte(got), &fromYAML); err != nil {
					t.Fatalf("not YAML: %v", err)
				}
				if !reflect.DeepEqual(fromYAML, want) {
					t.Errorf("YAML reads %#v, want %#v", fromYAML, want)
				}
			})
		}
	}
}

// spec: Templates and expressions/Template functions
func TestGet(t *testing.T) {
	const vars = "  peers:\n    - {name: a}\n    - {name: b, endpoint: \"192.0.2.2:51820\"}\n  l: [a]\n"
	tests := []struct{ name, text, want string }{
		{"optional key", `{{ range .vars.peers }}{{ .name }}{{ with get . "endpoint" }} {{ . }}{{ end }};{{ end }}`, "a;b 192.0.2.2:51820;"},
		{"missing key prints null", `{{ range .vars.peers }}{{ get . "endpoint" }}{{ end }}`,
			`error: recipes/r/recipe.yaml:4:16: content: get . "endpoint": the value is null`},
		{"not a map", `{{ get .vars.l "endpoint" }}`,
			`error: recipes/r/recipe.yaml:4:16: content: get .vars.l "endpoint": error calling get: get: a list is not a map`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, vars, "  - file:\n      path: /a\n      content: !tpl '"+tt.text+"'\n", nil)
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
		{"facts", `facts.os.id + " " + facts.os.version + " " + facts.os.codename + " " + facts.os.arch`, "debian 13 trixie amd64"},
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
		{name: "control character in a computed path", step: "  - file:\n      path: !tpl \"/etc/{{ .vars.s }}\\n\"\n      content: x\n",
			want: "error: recipes/r/recipe.yaml:3:13: path: has a control character"},
		{name: "content not a string", step: "  - file:\n      path: /a\n      content: !expr vars.l\n",
			want: "error: recipes/r/recipe.yaml:4:16: content: expected a string, got a list"},
		{name: "expression fails", step: "  - file:\n      path: /a\n      content: !expr 1 + vars.s\n",
			want: "error: recipes/r/recipe.yaml:4:16: content: invalid operation: int + string\n | 1 + vars.s\n | ..^"},
		{name: "quote of a number", step: "  - file:\n      path: /a\n      content: !expr quote(vars.i)\n",
			want: "error: recipes/r/recipe.yaml:4:16: content: quote: the integer 80 is not a string\n | quote(vars.i)\n | ^"},
		{name: "sqlquote of a number", step: "  - file:\n      path: /a\n      content: !expr sqlquote(vars.i)\n",
			want: "error: recipes/r/recipe.yaml:4:16: content: sqlquote: the integer 80 is not a string\n | sqlquote(vars.i)\n | ^"},
		{name: "json of infinity", vars: "  inf: .inf\n", step: "  - file:\n      path: /a\n      content: !expr json(vars.inf)\n",
			want: "error: recipes/r/recipe.yaml:4:16: content: json: unsupported value: +Inf\n | json(vars.inf)\n | ^"},
		{name: "default fails", vars: "  bad: !expr 1 + vars.s\n", step: "  - file:\n      path: /a\n      content: !expr vars.bad\n",
			want: "error: winch.yaml:15:8: variable \"bad\": invalid operation: int + string\n | 1 + vars.s\n | ..^"},
		{name: "when fails before a default", vars: "  bad: !expr 1 + vars.s\n", step: "  - file:\n      path: /a\n      content: !expr vars.bad\n    when: !expr 'vars.l[5] == \"x\"'\n",
			want: "error: recipes/r/recipe.yaml:5:11: when: index out of range: 5 (array length is 2)\n | vars.l[5] == \"x\"\n | ......^"},
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
		{name: "missing template beside a computed path", step: "  - file:\n      path: !tpl /etc/{{ .vars.s }}\n      template: htp.conf\n",
			want: "load error: recipes/r/recipe.yaml:4:17: template: recipes/r/templates/htp.conf does not exist"},
		{name: "missing source beside a computed path", step: "  - file:\n      path: !tpl /etc/{{ .vars.s }}\n      source: nothere.txt\n",
			want: "load error: recipes/r/recipe.yaml:4:15: source: recipes/r/files/nothere.txt does not exist"},
		{name: "missing unit source beside a computed name", step: "  - unit:\n      name: !tpl '{{ .vars.s }}.service'\n      source: nothere.service\n",
			want: "load error: recipes/r/recipe.yaml:4:15: source: recipes/r/files/nothere.service does not exist"},
		{name: "unclean source beside a computed path", step: "  - file:\n      path: !tpl /etc/{{ .vars.s }}\n      source: ../x\n",
			want: `load error: recipes/r/recipe.yaml:4:15: source: must be a clean relative path, such as "a/b.conf"`},
		{name: "unclean template beside a computed path", step: "  - file:\n      path: !tpl /etc/{{ .vars.s }}\n      template: ./t.tmpl\n",
			files: map[string]string{"recipes/r/templates/t.tmpl": "x"},
			want:  `load error: recipes/r/recipe.yaml:4:17: template: must be a clean relative path, such as "a/b.conf"`},
		{name: "unclean unit source beside a computed name", step: "  - unit:\n      name: !tpl '{{ .vars.s }}.service'\n      source: /a.service\n",
			want: `load error: recipes/r/recipe.yaml:4:15: source: must be a clean relative path, such as "a/b.conf"`},
		{name: "template reads item beside a computed path", step: "  - file:\n      path: !tpl /etc/{{ .vars.s }}\n      template: t.tmpl\n",
			files: map[string]string{"recipes/r/templates/t.tmpl": "{{ .item }}"},
			want:  "load error: recipes/r/recipe.yaml:4:17: template: t.tmpl reads .item; item is defined only in a step with loop"},
		{name: "computed unit content", step: "  - unit:\n      name: a.service\n      content: !tpl '{{ .vars.s }}'\n",
			want: "no error"},
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

// spec: Templates and expressions/Data
func TestArgNull(t *testing.T) {
	tests := []struct {
		name string
		step string
		want string
	}{
		{name: "service running", step: "  - service:\n      name: app\n      enabled: true\n      running: !expr vars.m.runing\n",
			want: "error: recipes/r/recipe.yaml:5:16: running: the expression gave null"},
		{name: "pointer", step: "  - file:\n      path: /a\n      content: x\n      validate: !expr vars.nothing\n",
			want: "error: recipes/r/recipe.yaml:5:17: validate: the expression gave null"},
		{name: "string", step: "  - file:\n      path: !expr vars.nothing\n      content: x\n",
			want: "error: recipes/r/recipe.yaml:3:13: path: the expression gave null"},
		{name: "list", step: "  - user:\n      name: a\n      authorized_keys: !expr vars.nothing\n",
			want: "error: recipes/r/recipe.yaml:4:24: authorized_keys: the expression gave null"},
		{name: "list element", step: "  - pkg:\n      name: [a, !expr vars.nothing]\n",
			want: "error: recipes/r/recipe.yaml:3:17: name: the expression gave null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, valueVars, tt.step, nil)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// spec: Templates and expressions/Data
func TestTemplateNull(t *testing.T) {
	const vars = "  nm: {k: null, d: {j: null}}\n  nl: [a, null]\n"
	tests := []struct {
		name string
		text string
		// want is the content, or the error without the position.
		want string
		// col is the column of the error in the template file.
		col int
	}{
		{"depth 0", "{{ range .vars.nl }}{{ . }}{{ end }}", ".: the value is null", 24},
		{"depth 1", "{{ .vars.nm.k }}", ".vars.nm.k: the value is null", 4},
		{"depth 1 list", "{{ index .vars.nl 1 }}", "index .vars.nl 1: the value is null", 4},
		{"depth 2", "{{ .vars.nm.d.j }}", ".vars.nm.d.j: the value is null", 4},
		{"variable", "{{ $x := .vars.nm.k }}{{ $x }}", "$x: the value is null", 26},
		{"defined template", "{{ define \"x\" }}{{ .k }}{{ end }}{{ template \"x\" .vars.nm }}", ".k: the value is null", 20},
		{"join", "{{ join .vars.nl \",\" }}", "join .vars.nl \",\": error calling join: join: element 2 is null", 4},
		{"condition", "{{ if .vars.nm.k }}set{{ else }}null{{ end }}", "null", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name+" file", func(t *testing.T) {
			got := evalOne(t, vars, "  - file:\n      path: /a\n      template: t.tmpl\n",
				map[string]string{"recipes/r/templates/t.tmpl": tt.text})
			want := tt.want
			if tt.col > 0 {
				want = fmt.Sprintf("error: recipes/r/templates/t.tmpl:1:%d: %s", tt.col, tt.want)
			}
			if got != want {
				t.Errorf("got  %q\nwant %q", got, want)
			}
		})
		t.Run(tt.name+" tpl", func(t *testing.T) {
			got := evalOne(t, vars, "  - file:\n      path: /a\n      content: !tpl '"+tt.text+"'\n", nil)
			want := tt.want
			if tt.col > 0 {
				want = "error: recipes/r/recipe.yaml:4:16: content: " + tt.want
			}
			if got != want {
				t.Errorf("got  %q\nwant %q", got, want)
			}
		})
	}
}

// spec: Steps
func TestLoopNull(t *testing.T) {
	tests := []struct {
		name string
		loop string
		want string
	}{
		{"literal", "[a, null]", "error: recipes/r/recipe.yaml:5:15: loop: element 2 is null"},
		{"expression", "!expr vars.nl", "error: recipes/r/recipe.yaml:5:11: loop: element 2 is null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, "  nl: [a, null]\n", "  - file:\n      path: !tpl '/srv/{{ .item }}'\n      content: x\n    loop: "+tt.loop+"\n", nil)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// spec: Variables ("unless when skips the recipe step there"); Running a pipeline/Plan
func TestStartRecipeWhen(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nvars:\n  on: false\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2:\n    vars:\n      on: true\n",
		"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - recipe: r
        when: !expr vars.on
`,
		"recipes/r/recipe.yaml": "require:\n  - !expr 'facts.os.id == \"ubuntu\"'\nsteps: []\n",
	}
	p, err := Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
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
	files["recipes/r/recipe.yaml"] = "steps:\n  - file:\n      path: /x\n      content: !expr vars.r_x\n"
	files["inventories/test.yaml"] = "hosts:\n  web1: {}\n  web2:\n    vars:\n      on: true\n  web3:\n    vars:\n      on: true\n      r_x: a\n"
	p, err = Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 2} {
		if _, err := p.Start(p.Inventory.Hosts[i], debian13); err != nil {
			t.Errorf("%s: %v", p.Inventory.Hosts[i].Name, err)
		}
	}
	_, err = p.Start(p.Inventory.Hosts[1], debian13)
	if want := `recipes/r/recipe.yaml:2:5: variable "r_x" has no value on host web2`; err == nil || err.Error() != want {
		t.Errorf("web2: got %v, want %s", err, want)
	}
}

// spec: Variables ("A host evaluates only the defaults that it uses")
func TestStartOnlyRunningDefaults(t *testing.T) {
	files := map[string]string{
		"winch.yaml": "name: acme\ninventory: test\nvars:\n  site_title: !expr 'upper(vars.tools_a)'\n",
		"inventories/test.yaml": `hosts:
  web1: {}
  mail1:
    vars:
      postfix_domain: acme.com
`,
		"recipes/web/recipe.yaml":         "vars:\n  web_name: !expr host.name\nsteps:\n  - file:\n      path: !expr '\"/etc/motd-\" + vars.tools_suffix'\n      template: motd.tmpl\n",
		"recipes/web/templates/motd.tmpl": "{{ .vars.tools_motd }} {{ .vars.site_title }} {{ .vars.web_name }}\n",
		"recipes/tools/recipe.yaml":       "vars:\n  tools_motd: !tpl \"hi {{ .host.name }}\"\n  tools_path: !expr '\"/etc/\" + host.name'\n  tools_a: !expr 'vars.tools_name + \"!\"'\n  tools_name: !expr host.name\n  tools_on: true\n  tools_list: [a]\n  tools_suffix: x\nsteps: []\n",
		"recipes/postfix/recipe.yaml":     "vars:\n  postfix_mailname: !tpl \"mail.{{ .vars.postfix_domain }}\"\nsteps:\n  - file:\n      path: /etc/mailname\n      content: !expr vars.postfix_mailname\n",
	}
	want := map[string]string{
		"web1":  `{"site_title":"WEB1!","tools_a":"web1!","tools_list":["a"],"tools_motd":"hi web1","tools_name":"web1","tools_on":true,"tools_path":"/etc/web1","tools_suffix":"x","web_name":"web1"}`,
		"mail1": `{"postfix_domain":"acme.com","postfix_mailname":"mail.acme.com","site_title":"MAIL1!","tools_a":"mail1!","tools_list":["a"],"tools_motd":"hi mail1","tools_name":"mail1","tools_on":true,"tools_path":"/etc/mail1","tools_suffix":"x","web_name":"mail1"}`,
	}
	tests := []struct {
		name     string
		pipeline string
	}{
		{name: "hosts", pipeline: `stages:
  - name: web
    hosts: all
    steps:
      - recipe: web
        when: !expr vars.tools_on
      - file:
          path: !expr 'vars.tools_path + "/" + item'
          content: ""
        loop: !expr vars.tools_list
  - name: mail
    hosts: mail1
    steps:
      - recipe: postfix
`},
		{name: "when", pipeline: `stages:
  - name: web
    hosts: all
    steps:
      - recipe: web
        when: !expr vars.tools_on
      - file:
          path: !expr 'vars.tools_path + "/" + item'
          content: ""
        loop: !expr vars.tools_list
  - name: mail
    hosts: all
    steps:
      - recipe: postfix
        when: !expr 'host.name == "mail1"'
      - file:
          path: /etc/mailname
          content: !expr vars.postfix_mailname
        when: !expr 'host.name == "mail1"'
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files["pipelines/site.yaml"] = tt.pipeline
			p, err := Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			for _, h := range p.Inventory.Hosts {
				env, err := p.Start(h, debian13)
				if err != nil {
					t.Errorf("%s: %v", h.Name, err)
					continue
				}
				got, _ := json.Marshal(env.vars[0])
				if string(got) != want[h.Name] {
					t.Errorf("%s: got  %s\nwant %s", h.Name, got, want[h.Name])
				}
			}
		})
	}
}

// spec: Variables ("A host evaluates only the defaults that it uses: the defaults that the `when` of each step reads, the defaults that the steps which run on it read, and the defaults that those read.")
func TestStartUsedDefaults(t *testing.T) {
	base := map[string]string{
		"winch.yaml": "name: acme\ninventory: test\nvars:\n  admins: []\n  first_admin: !expr 'vars.admins[0]'\n",
		"inventories/test.yaml": `hosts:
  web1:
    vars:
      nginx_tls: true
      nginx_domains: [example.com]
  web2: {}
`,
		"pipelines/site.yaml":            stage("      - recipe: nginx\n"),
		"recipes/nginx/templates/a.tmpl": "{{ .vars.nginx_a }}\n",
		"recipes/nginx/templates/b.tmpl": "{{ .vars.nginx_b }}\n",
	}
	const recipeVars = `vars:
  nginx_tls: false
  nginx_domains: []
  nginx_cert_path: !expr '"/etc/letsencrypt/live/" + vars.nginx_domains[0] + "/fullchain.pem"'
  nginx_first: !expr 'vars.nginx_domains[0]'
  nginx_a: a
  nginx_b: b
`
	const tlsStep = `  - name: TLS config
    file:
      path: /etc/nginx/tls.conf
      content: !tpl "ssl_certificate {{ .vars.nginx_cert_path }};\n"
    when: !expr vars.nginx_tls
`
	tests := []struct {
		name  string
		steps string
		files map[string]string
		want  map[string]string
	}{
		{name: "when", steps: tlsStep, want: map[string]string{
			"web1": `{"nginx_cert_path":"/etc/letsencrypt/live/example.com/fullchain.pem","nginx_domains":["example.com"],"nginx_tls":true}`,
			"web2": `{"nginx_tls":false}`,
		}},
		{name: "template", steps: tlsStep + "  - file:\n      path: /etc/a\n      template: a.tmpl\n", want: map[string]string{
			"web1": `{"nginx_a":"a","nginx_cert_path":"/etc/letsencrypt/live/example.com/fullchain.pem","nginx_domains":["example.com"],"nginx_tls":true}`,
			"web2": `{"nginx_a":"a","nginx_tls":false}`,
		}},
		{name: "skipped-template", steps: tlsStep + "  - file:\n      path: /etc/nginx/tls2.conf\n      template: tls.tmpl\n    when: !expr vars.nginx_tls\n",
			files: map[string]string{"recipes/nginx/templates/tls.tmpl": "{{ .vars.nginx_cert_path }}\n"}, want: map[string]string{
				"web1": `{"nginx_cert_path":"/etc/letsencrypt/live/example.com/fullchain.pem","nginx_domains":["example.com"],"nginx_tls":true}`,
				"web2": `{"nginx_tls":false}`,
			}},
		{name: "template-expr", steps: tlsStep + "  - file:\n      path: /etc/a\n      template: !expr '\"a.tmpl\"'\n", want: map[string]string{
			"web1": `{"nginx_a":"a","nginx_b":"b","nginx_cert_path":"/etc/letsencrypt/live/example.com/fullchain.pem","nginx_domains":["example.com"],"nginx_tls":true}`,
			"web2": `{"nginx_a":"a","nginx_b":"b","nginx_tls":false}`,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := with(base, tt.files)
			files["recipes/nginx/recipe.yaml"] = recipeVars + "steps:\n" + tt.steps
			p, err := Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			for _, h := range p.Inventory.Hosts {
				env, err := p.Start(h, debian13)
				if err != nil {
					t.Errorf("%s: %v", h.Name, err)
					continue
				}
				got, _ := json.Marshal(env.vars[0])
				if string(got) != tt.want[h.Name] {
					t.Errorf("%s: got  %s\nwant %s", h.Name, got, tt.want[h.Name])
				}
				steps, err := p.Pipeline.Stages[0].Steps[0].Recipe.Steps[0].Eval(env)
				var data []string
				for _, s := range steps {
					data = append(data, string(s.Args.(*module.File).Data))
				}
				var want []string
				if h.Name == "web1" {
					want = []string{"ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n"}
				}
				if err != nil || !slices.Equal(data, want) {
					t.Errorf("%s: TLS config: got %q, %v; want %q", h.Name, data, err, want)
				}
			}
		})
	}
}

var readsProject = map[string]string{
	"winch.yaml":            "name: acme\ninventory: test\nvars:\n  port: 80\n",
	"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      domain: a.com\n      key: k1\n  web2: {}\n",
	"inventories/prod.yaml": "hosts:\n  web9:\n    vars:\n      relay: r.com\n",
	"pipelines/site.yaml":   "stages:\n  - name: a\n    hosts: web1\n    steps:\n      - recipe: r\n",
	"recipes/r/recipe.yaml": `steps:
  - file:
      path: /etc/domain
      content: !expr 'vars.domain + ":" + string(vars.port)'
  - file:
      path: /etc/relay
      content: !expr vars.relay
    when: !expr 'host.name == "web9"'
  - file:
      path: /etc/peers
      content: !expr 'join(map(match("all"), string(.vars.key)), ",")'
`,
}

// spec: Variables
func TestReadsDeclare(t *testing.T) {
	r := readsProject["recipes/r/recipe.yaml"]
	inv := readsProject["inventories/test.yaml"]
	tests := []struct {
		name  string
		files map[string]string
		set   []string
		want  string
	}{
		{name: "reads without declarations"},
		{name: "an unread inventory value", files: map[string]string{
			"inventories/test.yaml": inv + "groups:\n  all:\n    vars:\n      domian: b.com\n",
		}, want: `inventories/test.yaml:10:7: unknown variable "domian"; did you mean "domain"?`},
		{name: "a misspelled read", files: map[string]string{
			"recipes/r/recipe.yaml": strings.Replace(r, "vars.domain +", "vars.domian +", 1),
		}, want: `recipes/r/recipe.yaml:4:16: unknown variable "domian"; did you mean "domain"?`},
		{name: "a misspelled read in a template", files: map[string]string{
			"recipes/r/recipe.yaml":      r + "  - file:\n      path: /etc/t\n      template: t.tmpl\n",
			"recipes/r/templates/t.tmpl": "x {{ .vars.domian }}\n",
		}, want: `recipes/r/templates/t.tmpl:1:11: unknown variable "domian"; did you mean "domain"?`},
		{name: "an unread value of a recipe step", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: web1\n    steps:\n      - recipe: r\n        vars:\n          domian: x\n",
		}, want: `pipelines/site.yaml:7:11: unknown variable "domian"; did you mean "domain"?`},
		{name: "an unread --set value", set: []string{"vars.domian=x"},
			want: `--set vars.domian=x: unknown variable "domian"; did you mean "domain"?`},
		{name: "a declaration without a default", files: map[string]string{
			"winch.yaml": "name: acme\ninventory: test\nvars:\n  port: 80\n  domain:\n",
		}, want: `winch.yaml:5:3: variable "domain": a variable without a default has no declaration; remove it`},
		{name: "with .vars in a step", files: map[string]string{
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/w\n      content: !tpl '{{ with .vars }}{{ .domain }}{{ end }}'\n",
		}, want: `recipes/r/recipe.yaml:14:16: a read of vars names the variable, such as vars.nginx_port`},
		{name: "vars[item] in a step", files: map[string]string{
			"recipes/r/recipe.yaml": r + "  - file:\n      path: !expr '\"/etc/\" + vars[item]'\n      content: x\n    loop: [domain]\n",
		}, want: `recipes/r/recipe.yaml:13:13: a read of vars names the variable, such as vars.nginx_port`},
		{name: "with .host in a step", files: map[string]string{
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/w\n      content: !tpl '{{ with .host }}{{ .name }}{{ end }}'\n",
		}, want: `recipes/r/recipe.yaml:14:16: a read of vars names the variable, such as vars.nginx_port`},
		{name: "reads of peers in a template", files: map[string]string{
			"inventories/test.yaml":      strings.Replace(inv, "key: k1", "key: k1\n      role: a\n      zone: b\n      rack: c", 1),
			"recipes/r/recipe.yaml":      r + "  - file:\n      path: /etc/t\n      template: t.tmpl\n",
			"recipes/r/templates/t.tmpl": "{{ range .vars.peers }}{{ .vars.role }}{{ end }}{{ $p := index .vars.peers 0 }}{{ $p.vars.zone }}{{ (index .vars.peers 0).vars.rack }}\n",
			"pipelines/site.yaml":        "stages:\n  - name: a\n    hosts: web1\n    steps:\n      - recipe: r\n        vars:\n          peers: !expr match(\"all\")\n",
		}},
		{name: "a peer read under filter of match", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "key: k1", "key: k1\n      peer_key: p1", 1),
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/p\n      content: !expr 'join(map(filter(match(\"all\"), .name != host.name), .vars.peer_key), \",\")'\n",
		}},
		{name: "a misspelled peer read under filter of match", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "key: k1", "key: k1\n      peer_key: p1", 1),
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/p\n      content: !expr 'join(map(filter(match(\"all\"), .name != host.name), .vars.peer_kye), \",\")'\n",
		}, want: `recipes/r/recipe.yaml:14:16: unknown variable "peer_kye"; did you mean "peer_key"?`},
		{name: "keys of a peer's vars", files: map[string]string{
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'join(map(match(\"all\"), join(keys(.vars), \" \")), \",\")'\n",
		}, want: `recipes/r/recipe.yaml:14:16: a read of vars names the variable, such as vars.nginx_port`},
		{name: "get of a peer's vars by a computed key", files: map[string]string{
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'join(map(match(\"all\"), string(get(.vars, item))), \",\")'\n    loop: [key]\n",
		}, want: `recipes/r/recipe.yaml:14:16: a read of vars names the variable, such as vars.nginx_port`},
		{name: "a peer's whole vars", files: map[string]string{
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'string(match(\"all\")[0].vars)'\n",
		}, want: `recipes/r/recipe.yaml:14:16: a read of vars names the variable, such as vars.nginx_port`},
		{name: "get of the key vars of a peer", files: map[string]string{
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'join(keys(get(match(\"all\")[0], \"vars\")), \",\")'\n",
		}, want: `recipes/r/recipe.yaml:14:16: a read of vars names the variable, such as vars.nginx_port`},
		{name: "get of a peer's vars by name", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "key: k1", "key: k1\n      peer_key: p1", 1),
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'join(map(match(\"all\"), string(get(.vars, \"peer_key\"))), \",\")'\n",
		}},
		{name: "get of a peer's optional vars by name", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "key: k1", "key: k1\n      peer_key: p1", 1),
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'string(get(match(\"all\")[0]?.vars, \"peer_key\"))'\n",
		}},
		{name: "a misspelled get of a peer's vars", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "key: k1", "key: k1\n      peer_key: p1", 1),
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'join(map(match(\"all\"), string(get(.vars, \"peer_kye\"))), \",\")'\n",
		}, want: `recipes/r/recipe.yaml:14:16: unknown variable "peer_kye"; did you mean "peer_key"?`},
		{name: "a variable named vars", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "key: k1", "key: k1\n      vars: {a: 1}", 1),
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'string(vars.vars) + string(vars.vars.a)'\n",
		}},
		{name: "get of the own vars by name", files: map[string]string{
			"recipes/r/recipe.yaml": r + "  - file:\n      path: /etc/k\n      content: !expr 'string(get(vars, \"key\"))'\n",
		}, want: `recipes/r/recipe.yaml:14:16: a read of vars names the variable, such as vars.nginx_port`},
		{name: "a value name with upper case", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "key: k1", "key: k1\n      Port: 1", 1),
			"recipes/r/recipe.yaml": strings.Replace(r, "string(vars.port)", "string(vars.Port)", 1),
		}, want: `inventories/test.yaml:6:7: variable "Port": a variable name has only lowercase letters, digits, and _`},
		{name: "a --set name with upper case", set: []string{"vars.Port=1"}, files: map[string]string{
			"recipes/r/recipe.yaml": strings.Replace(r, "string(vars.port)", "string(vars.Port)", 1),
		}, want: `--set vars.Port=1: variable "Port": a variable name has only lowercase letters, digits, and _`},
		{name: "a value read only in a broken pipeline that does not run", files: map[string]string{
			"inventories/test.yaml": strings.Replace(inv, "key: k1", "key: k1\n      relay2: x", 1),
			"pipelines/other.yaml":  "bogus: 1\nstages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: /x\n          content: !expr vars.relay2\n",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := maps.Clone(readsProject)
			maps.Copy(files, tt.files)
			_, err := Load(t.Context(), writeProject(t, files), "", "site", tt.set, Keys{})
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("load error: %v", err)
			case tt.want != "" && (err == nil || !strings.HasPrefix(err.Error(), tt.want)):
				t.Fatalf("got  %v\nwant %s", err, tt.want)
			}
		})
	}
}

// spec: Variables ("A variable without a default needs a value on each host where a step ... reads it")
func TestReadsNeedValue(t *testing.T) {
	tests := []struct {
		name, pipeline string
		want           []string
	}{
		{"both hosts read", "stages:\n  - name: a\n    hosts: all\n    steps:\n      - recipe: r\n",
			[]string{"web1: <nil>", `web2: recipes/r/recipe.yaml:2:5: variable "domain" has no value on host web2`}},
		{"one host reads", "stages:\n  - name: a\n    hosts: web1\n    steps:\n      - recipe: r\n",
			[]string{"web1: <nil>", "web2: <nil>"}},
		{"when skips the recipe", "stages:\n  - name: a\n    hosts: all\n    steps:\n      - recipe: r\n        when: !expr 'host.name == \"web1\"'\n",
			[]string{"web1: <nil>", "web2: <nil>"}},
		{"a when reads", "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: /x\n          content: x\n        when: !expr vars.domain != \"\"\n",
			[]string{"web1: <nil>", `web2: pipelines/site.yaml:8:15: variable "domain" has no value on host web2`}},
		{"a default reads", "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: /x\n          content: !expr vars.url\n",
			[]string{"web1: <nil>", `web2: pipelines/site.yaml:5:9: variable "domain" has no value on host web2`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := maps.Clone(readsProject)
			files["winch.yaml"] += "  url: !tpl 'https://{{ .vars.domain }}'\n"
			files["pipelines/site.yaml"] = tt.pipeline
			p, err := Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, h := range p.Inventory.Hosts {
				_, err := p.Start(h, debian13)
				got = append(got, fmt.Sprintf("%s: %v", h.Name, err))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}
