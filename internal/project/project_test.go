package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
)

var base = map[string]string{
	"winch.yaml": "name: acme\ninventory: inventories/test.yaml\n",
	"inventories/test.yaml": `hosts:
  web1:
    address: 192.0.2.1
  web2:
    user: deploy
groups:
  all:
    user: admin
`,
	"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: hi
  - name: one
    hosts: web2
    steps:
      - file:
          path: /etc/issue
          absent: true
`,
}

func writeProject(t *testing.T, override map[string]string) string {
	t.Helper()
	files := fstest.MapFS{}
	for name, content := range base {
		files[name] = &fstest.MapFile{Data: []byte(content)}
	}
	for name, content := range override {
		files[name] = &fstest.MapFile{Data: []byte(content)}
		if content == "" {
			delete(files, name)
		}
	}
	dir := t.TempDir()
	if err := os.CopyFS(dir, files); err != nil {
		t.Fatal(err)
	}
	return dir
}

func describe(p *Project) string {
	var b strings.Builder
	fmt.Fprintf(&b, "project %s, inventory %s\n", p.Name, p.Inventory.File)
	for _, h := range p.Inventory.Hosts {
		fmt.Fprintf(&b, "host %s address=%s user=%s\n", h.Name, h.Address, h.User)
	}
	fmt.Fprintf(&b, "pipeline %s\n", p.Pipeline.Name)
	for _, s := range p.Pipeline.Stages {
		var names []string
		for _, h := range s.Targets {
			names = append(names, h.Name)
		}
		fmt.Fprintf(&b, "stage %s hosts=%s targets=%s\n", s.Name, s.Hosts, strings.Join(names, ","))
		for _, st := range s.Steps {
			describeStep(&b, "  ", st)
			if st.Recipe == nil {
				continue
			}
			for _, r := range st.Recipe.Require {
				fmt.Fprintf(&b, "    require %s at %s\n", r.Text, r.Pos)
			}
			for _, rs := range st.Recipe.Steps {
				describeStep(&b, "    ", rs)
			}
		}
	}
	return b.String()
}

func describeStep(b *strings.Builder, indent string, st Step) {
	name := ""
	if st.Name != "" {
		name = fmt.Sprintf(" name=%q", st.Name)
	}
	if st.Recipe != nil {
		fmt.Fprintf(b, "%srecipe %s%s at %s\n", indent, st.Recipe.Name, name, st.Pos)
		return
	}
	args, _ := json.Marshal(st.Args)
	data := ""
	if f, ok := st.Args.(*module.File); ok && f.Data != nil {
		c := *f
		c.Data = nil
		args, _ = json.Marshal(&c)
		data = fmt.Sprintf(" data=%q", f.Data)
	}
	fmt.Fprintf(b, "%s%s %s%s%s at %s\n", indent, st.Module, strings.Replace(string(args), `,"data":null`, "", 1), data, name, st.Pos)
}

func result(p *Project, err error) []byte {
	if err != nil {
		return []byte(err.Error() + "\n")
	}
	return []byte(describe(p))
}

// spec: Project layout; Inventory; Inventory/Host patterns; Pipelines; Steps
func TestLoad(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		inventory string
		pipeline  string
	}{
		{name: "valid"},
		{name: "inventory-flag", files: map[string]string{
			"winch.yaml":            "name: acme\n",
			"inventories/prod.yaml": "hosts:\n  web2: {}\n",
		}, inventory: "inventories/prod.yaml"},
		{name: "flag-beats-default", files: map[string]string{
			"inventories/prod.yaml": "hosts:\n  web2: {}\n",
		}, inventory: "inventories/prod.yaml"},
		{name: "no-inventory", files: map[string]string{"winch.yaml": "name: acme\n"}},
		{name: "missing-inventory-file", inventory: "inventories/nope.yaml"},
		{name: "missing-default-inventory", files: map[string]string{"winch.yaml": "name: acme\ninventory: inventories/prdo.yaml\n"}},
		{name: "pipeline-name-with-dots", pipeline: "web.v2", files: map[string]string{"pipelines/web.v2.yaml": "stages:\n  - {name: a, hosts: all, steps: []}\n"}},
		{name: "no-winch-yaml", files: map[string]string{"winch.yaml": ""}},
		{name: "no-name", files: map[string]string{"winch.yaml": "inventory: inventories/test.yaml\n"}},
		{name: "winch-unknown-key", files: map[string]string{"winch.yaml": "name: acme\ninventroy: x\n"}},
		{name: "host-unknown-key", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    adress: 1.2.3.4\n"}},
		{name: "all-with-hosts", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1: {}\ngroups:\n  all:\n    hosts: [web1]\n"}},
		{name: "other-group", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\ngroups:\n  web:\n    hosts: [web2]\n    user: x\n"}},
		{name: "bad-address", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    address: a$(id)b\n  web2:\n    address: -oProxyCommand=x\n  web3:\n    address: fe80::1%eth0\n"}},
		{name: "address-port", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    address: 192.0.2.1:22\n  web2:\n    address: \"[2001:db8::1]\"\n  web3:\n    address: mail.acme.com:2222\n  web4:\n    address: 2001:db8::1\n  web5:\n    address: fe80::1%eth0\n"}},
		{name: "same-address", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    address: 192.0.2.1\n  web2:\n    address: 192.0.2.1\n  web3: {}\n  web4:\n    address: web3\n  web5:\n    address: 192.0.2.5\n  web6:\n    address: MAIL.acme.com\n  web7:\n    address: mail.acme.com\n"}},
		{name: "host-named-all", files: map[string]string{"inventories/test.yaml": "hosts:\n  all: {}\n"}},
		{name: "empty-inventory", files: map[string]string{"inventories/test.yaml": "hosts: {}\n"}},
		{name: "host-name-number", files: map[string]string{"inventories/test.yaml": "hosts:\n  1234: {}\n  1.5: {}\n  web2: {}\n"}},
		{name: "group-member-number", files: map[string]string{"inventories/test.yaml": "hosts:\n  \"1234\": {}\n  web2: {}\ngroups:\n  db:\n    hosts: [1234, 0x1F, 1.5]\n"}},
		{name: "host-name-quoted", files: map[string]string{"inventories/test.yaml": "hosts:\n  \"1234\": {}\n  web2: {}\ngroups:\n  db:\n    hosts: [\"1234\"]\n"}},
		{name: "unknown-pipeline", pipeline: "sit"},
		{name: "bad-pipeline-name", pipeline: "../winch"},
		{name: "unknown-pipeline-yml", pipeline: "web", files: map[string]string{"pipelines/web.yml": stage("")}},
		{name: "duplicate-stage", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps: []\n  - name: a\n    hosts: all\n    steps: []\n"}},
		{name: "pipeline-without-stages", files: map[string]string{"pipelines/site.yaml": "stages: []\n"}},
		{name: "stage-missing-hosts", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    steps: []\n"}},
		{name: "unknown-stage-host", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: web3\n    steps: []\n"}},
		{name: "unknown-module", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - fiel:\n          path: /x\n"}},
		{name: "two-modules", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file: {path: /x, content: a}\n        pkg: {name: x}\n"}},
		{name: "empty-step", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - {}\n"}},
		{name: "step-not-map", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file\n"}},
		{name: "file-no-content", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: /x\n"}},
		{name: "file-content-and-absent", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: /x\n          content: a\n          absent: true\n"}},
		{name: "file-relative-path", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: x\n          content: a\n"}},
		{name: "link-dot-dot-target", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - link: {path: /srv/x, target: a/../b}\n      - link: {path: /srv/y, target: ../a/../b}\n      - link: {path: /srv/z, target: ../lib/x}\n"}},
		{name: "path-dot-dot", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n" +
			"      - file: {path: /srv/app/../conf, content: a}\n" +
			"      - file: {path: /.., content: a}\n" +
			"      - dir: {path: /srv/app/../conf}\n" +
			"      - dir: {path: /..}\n" +
			"      - link: {path: /srv/app/../conf, target: /x}\n" +
			"      - link: {path: /.., target: /x}\n" +
			"      - dir: {path: /var/www/}\n"}},
		{name: "service-unit-names", files: map[string]string{"pipelines/site.yaml": stage(
			"      - service: {name: \"nginx@\", running: true}\n" +
				"      - service: {name: \"@foo\", running: true}\n" +
				"      - service: {name: getty@.service, enabled: true}\n" +
				"      - service: {name: " + strings.Repeat("a", 248) + ", running: true}\n" +
				"      - service: {name: getty@tty1, running: true}\n" +
				"      - service: {name: a@b@c, running: true}\n" +
				"      - service: {name: nginx, running: true}\n")}},
		{name: "owner-group-numbers", files: map[string]string{"pipelines/site.yaml": stage(
			"      - file: {path: /a, content: a, owner: -1}\n" +
				"      - file: {path: /b, content: a, owner: 1.5}\n" +
				"      - dir: {path: /c, owner: 0x3e7}\n" +
				"      - dir: {path: /d, group: 0o750}\n" +
				"      - dir: {path: /e, owner: +999}\n" +
				"      - dir: {path: /f, owner: 999, group: \"999\"}\n")}},
		{name: "owner-group-names", files: map[string]string{"pipelines/site.yaml": stage(
			"      - file: {path: /a, content: a, owner: \"www-data:www-data\"}\n" +
				"      - file: {path: /b, content: a, group: a/b}\n" +
				"      - dir: {path: /c, owner: \"a b\"}\n" +
				"      - dir: {path: /d, group: -x}\n" +
				"      - dir: {path: /e, owner: \"a\\tb\"}\n" +
				"      - dir: {path: /f, owner: www-data, group: ssl-cert}\n")}},
		{name: "file-bad-mode", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: /x\n          content: a\n          mode: 0644\n"}},
		{name: "modules", files: map[string]string{"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - pkg:
          name: [nginx, curl]
          recommends: false
      - dir:
          path: /var/www/demo
      - link:
          path: /etc/nginx/sites-enabled/demo
          target: /etc/nginx/sites-available/demo
      - service:
          name: nginx
          running: true
          enabled: true
`}},
		{name: "module-errors", files: map[string]string{"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - pkg:
          name: Nginx
      - dir:
          path: www
      - link:
          path: /a
      - service:
          name: nginx
`}},
		{name: "errors-in-two-files", files: map[string]string{
			"winch.yaml":          "name: acme\ninventory: inventories/test.yaml\nfoo: 1\n",
			"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    bar: 1\n    steps: []\n",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, tt.files)
			pipeline := tt.pipeline
			if pipeline == "" {
				pipeline = "site"
			}
			p, err := Load(t.Context(), dir, tt.inventory, pipeline, nil, Keys{})
			golden.Assert(t, filepath.Join("testdata", "load", tt.name+".golden"), result(p, err))
		})
	}
}

// spec: CLI
func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		inventory string
	}{
		{name: "valid"},
		{name: "all-inventories", files: map[string]string{
			"winch.yaml":            "name: acme\n",
			"inventories/prod.yaml": "hosts:\n  web1: {}\n",
			"inventories/test.yaml": "hosts:\n  web3: {}\n",
			"pipelines/site.yaml":   "stages:\n  - name: a\n    hosts: web2\n    steps: []\n",
		}},
		{name: "named-inventory-only", files: map[string]string{
			"winch.yaml":            "name: acme\n",
			"inventories/prod.yaml": "hosts:\n  web1: {}\n",
			"pipelines/site.yaml":   "stages:\n  - name: a\n    hosts: web2\n    steps: []\n",
		}, inventory: "inventories/test.yaml"},
		{name: "every-pipeline", files: map[string]string{
			"pipelines/other.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - pkg: {}\n",
		}},
		{name: "recipe-error-once", files: map[string]string{
			"pipelines/site.yaml":       stage("      - recipe: nginx\n"),
			"pipelines/other.yaml":      stage("      - recipe: nginx\n"),
			"recipes/nginx/recipe.yaml": "stpes: []\n",
		}},
		{name: "recipe-twice-in-one-inventory", files: map[string]string{
			"winch.yaml":              "name: acme\n",
			"inventories/a.yaml":      "hosts:\n  web1: {}\n",
			"inventories/b.yaml":      "hosts:\n  web2: {}\n",
			"pipelines/site.yaml":     "stages:\n  - name: a\n    hosts: all\n    steps:\n      - recipe: pkg\n  - name: b\n    hosts: web2\n    steps:\n      - recipe: pkg\n",
			"recipes/pkg/recipe.yaml": "steps:\n  - pkg:\n      name: curl\n",
			"inventories/test.yaml":   "",
		}},
		{name: "no-inventories", files: map[string]string{
			"winch.yaml":            "name: acme\n",
			"inventories/test.yaml": "",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, tt.files)
			got := "ok\n"
			if _, err := Validate(dir, tt.inventory, nil); err != nil {
				got = err.Error() + "\n"
			}
			golden.Assert(t, filepath.Join("testdata", "validate", tt.name+".golden"), []byte(got))
		})
	}
}

// spec: CLI
func TestValidateNamesYML(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pipelines/web.yml":           stage(""),
		"recipes/nginx/recipe.yaml":   "steps: []\n",
		"recipes/nginx/vars.yml":      "vars: {}\n",
		"recipes/nginx/files/a.yml":   "a: 1\n",
		"recipes/nginx/templates.yml": "a: 1\n",
	})
	warnings, err := Validate(dir, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, w := range warnings {
		got = append(got, w.Error())
	}
	want := []string{
		"pipelines/web.yml:1:1: winch reads only .yaml files in pipelines/; rename it to web.yaml",
		"recipes/nginx/templates.yml:1:1: winch reads only recipe.yaml in a recipe directory",
		"recipes/nginx/vars.yml:1:1: winch reads only recipe.yaml in a recipe directory",
	}
	if !slices.Equal(got, want) {
		t.Errorf("warnings\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

var nginx = map[string]string{
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - name: Web server
        recipe: nginx
      - file:
          path: /etc/issue
          content: x
`,
	"recipes/nginx/recipe.yaml": `require:
  - !expr 'facts.os.id == "debian" and facts.os.version == "13"'
  - !expr 'facts.os.codename in ["bookworm", "trixie"]'
steps:
  - pkg:
      name: nginx
  - name: Site
    file:
      path: /etc/nginx/sites-available/default
      template: sites/default.tmpl
  - file:
      path: /etc/nginx/snippets/tls.conf
      source: snippets/tls.conf
`,
	"recipes/nginx/templates/sites/default.tmpl": "server_name {{ .host.name }};\n",
	"recipes/nginx/files/snippets/tls.conf":      "ssl_protocols TLSv1.3;\n",
	"recipes/pkg/recipe.yaml":                    "steps:\n  - pkg:\n      name: curl\n",
}

func with(base map[string]string, files map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range files {
		out[k] = v
	}
	return out
}

func stage(steps string) string {
	return "stages:\n  - name: web\n    hosts: all\n    steps:\n" + steps
}

func recipe(steps string) string {
	return "steps:\n" + steps
}

// spec: Recipes; Pipelines; Steps; Templates and expressions/When they run; Modules/file, dir, link
func TestLoadRecipes(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{name: "recipe"},
		{name: "recipe-named-like-module", files: map[string]string{
			"pipelines/site.yaml": stage("      - recipe: pkg\n"),
		}},
		{name: "unknown-recipe", files: map[string]string{
			"pipelines/site.yaml": stage("      - recipe: ngnix\n"),
		}},
		{name: "bad-recipe-name", files: map[string]string{
			"pipelines/site.yaml": stage("      - recipe: ../nginx\n"),
		}},
		{name: "empty-recipe-name", files: map[string]string{
			"pipelines/site.yaml": stage("      - recipe: \"\"\n"),
		}},
		{name: "step-key-typo", files: map[string]string{
			"pipelines/site.yaml": stage("      - recpie: nginx\n      - nmae: x\n        pkg:\n          name: curl\n"),
		}},
		{name: "require-not-a-list", files: map[string]string{
			"recipes/nginx/recipe.yaml": "require: !expr 'facts.os.id == \"debian\"'\nsteps: []\n",
		}},
		{name: "template-names-in-branches", files: map[string]string{
			"recipes/nginx/recipe.yaml": recipe("  - file:\n      path: /a\n      template: bad.tmpl\n"),
			"recipes/nginx/templates/bad.tmpl": "{{ if .vars.x }}a{{ end }}{{ range .vars.l }}b{{ end }}\n" +
				"{{ .hots.name.x }} {{ $.hots }}\n" +
				"{{ define \"row\" }}{{ $.name }}{{ .y }}{{ end }}{{ template \"row\" .host }}\n",
		}},
		{name: "template-parse-error-mid-line", files: map[string]string{
			"recipes/nginx/recipe.yaml":        recipe("  - file:\n      path: /a\n      template: bad.tmpl\n"),
			"recipes/nginx/templates/bad.tmpl": "a {{ .host.name ) }}\n",
		}},
		{name: "recipe-without-file", files: map[string]string{
			"pipelines/site.yaml":       stage("      - recipe: empty\n"),
			"recipes/empty/files/a.txt": "a",
		}},
		{name: "recipe-yml", files: map[string]string{
			"pipelines/site.yaml":      stage("      - recipe: empty\n"),
			"recipes/empty/recipe.yml": "steps: []\n",
		}},
		{name: "recipe-unknown-key", files: map[string]string{
			"recipes/nginx/recipe.yaml": "stpes: []\n",
		}},
		{name: "recipe-in-recipe", files: map[string]string{
			"recipes/nginx/recipe.yaml": recipe("  - recipe: pkg\n"),
		}},
		{name: "recipe-step-with-module", files: map[string]string{
			"pipelines/site.yaml": stage("      - recipe: nginx\n        pkg:\n          name: x\n"),
		}},
		{name: "recipe-step-other-key", files: map[string]string{
			"pipelines/site.yaml": stage("      - recipe: nginx\n        foo: 1\n"),
		}},
		{name: "missing-template", files: map[string]string{
			"recipes/nginx/recipe.yaml": recipe("  - file:\n      path: /a\n      template: nope.tmpl\n"),
		}},
		{name: "missing-source", files: map[string]string{
			"recipes/nginx/recipe.yaml": recipe("  - file:\n      path: /a\n      source: nope.conf\n"),
		}},
		{name: "source-is-directory", files: map[string]string{
			"recipes/nginx/recipe.yaml": recipe("  - file:\n      path: /a\n      source: snippets\n"),
		}},
		{name: "template-parse-error", files: map[string]string{
			"recipes/nginx/recipe.yaml":        recipe("  - file:\n      path: /a\n      template: bad.tmpl\n"),
			"recipes/nginx/templates/bad.tmpl": "line 1\n{{ if .host.name }}\n",
		}},
		{name: "template-unknown-name", files: map[string]string{
			"recipes/nginx/recipe.yaml":        recipe("  - file:\n      path: /a\n      template: bad.tmpl\n"),
			"recipes/nginx/templates/bad.tmpl": "a\n  {{ .vars.domain }}\n{{ with .host }}{{ .x }}{{ $.hots.name }}{{ end }}\n",
		}},
		{name: "template-in-stage", files: map[string]string{
			"pipelines/site.yaml": stage("      - file:\n          path: /a\n          template: a.tmpl\n      - file:\n          path: /b\n          source: b\n"),
		}},
		{name: "require-untagged", files: map[string]string{
			"recipes/nginx/recipe.yaml": "require:\n  - facts.os.id == \"debian\"\nsteps: []\n",
		}},
		{name: "require-errors", files: map[string]string{
			"recipes/nginx/recipe.yaml": "require:\n  - !expr 'facts.os.id =='\n  - !expr 'fact.os.id == \"debian\"'\n  - !expr 'facts.os.idd == \"debian\"'\n  - !expr facts.os.id\n  - !expr 'facts.os.version == 13'\nsteps: []\n",
		}},
		{name: "require-snippet", files: map[string]string{
			"recipes/nginx/recipe.yaml": "require:\n  - !expr facts.os.id == \"debian\" &&& true\nsteps: []\n",
		}},
		{name: "require-snippet-control-characters", files: map[string]string{
			"recipes/nginx/recipe.yaml": "require:\n  - !expr \"\\\"\\e[2J\\\" + 1\"\nsteps: []\n",
		}},
		{name: "recipe-twice-in-stage", files: map[string]string{
			"pipelines/site.yaml": stage("      - recipe: pkg\n      - recipe: pkg\n"),
		}},
		{name: "recipe-in-overlapping-stages", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - recipe: pkg\n  - name: b\n    hosts: web2\n    steps:\n      - recipe: pkg\n",
		}},
		{name: "recipe-in-separate-stages", files: map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: web1\n    steps:\n      - recipe: pkg\n  - name: b\n    hosts: web2\n    steps:\n      - recipe: pkg\n",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, with(nginx, tt.files))
			p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
			golden.Assert(t, filepath.Join("testdata", "load", tt.name+".golden"), result(p, err))
		})
	}
}

// spec: Templates and expressions/Data; Templates and expressions/When they run; Modules/file, dir, link
func TestRender(t *testing.T) {
	binary := string([]byte{0, 1, 0xfe, 0xff, '\r', '\n', 0x80})
	tests := []struct {
		name     string
		template string
		want     map[string]string
	}{
		{"host fields", "{{ .host.name }} {{ .host.short }} {{ .host.address }}\n", map[string]string{
			"web1.acme.com": "web1.acme.com web1 192.0.2.1\n",
			"web2":          "web2 web2 web2\n",
		}},
		{"no trailing newline", "{{ .host.short }}", map[string]string{"web2": "web2"}},
		{"with and dollar", "{{ with .host }}{{ .short }}-{{ $.host.name }}{{ end }}", map[string]string{"web1.acme.com": "web1-web1.acme.com"}},
		{"missing key", "a\n b {{ with .host }}{{ .nme }}{{ end }}\n", map[string]string{
			"web1.acme.com": "error: recipes/r/templates/t.tmpl:2:23: .nme: map has no entry for key \"nme\"",
		}},
		{"source bytes", "", map[string]string{"web2": binary}},
		{"range over a map", "{{ range $k, $v := .host }}{{ $k }}={{ $v }};{{ end }}", map[string]string{"web2": "address=web2;groups=[all];name=web2;short=web2;vars=map[];"}},
		{"index", "{{ index .host \"short\" }}", map[string]string{"web2": "web2"}},
		{"index of a missing key", "{{ index .host \"nme\" }}", map[string]string{
			"web2": "error: recipes/r/templates/t.tmpl:1:4: index .host \"nme\": error calling index: map has no entry for key \"nme\"",
		}},
		{"empty output", "{{ if false }}x{{ end }}", map[string]string{"web2": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := "  - file:\n      path: /a\n      template: t.tmpl\n"
			if tt.template == "" {
				step = "  - file:\n      path: /a\n      source: s.bin\n"
			}
			dir := writeProject(t, map[string]string{
				"inventories/test.yaml":      "hosts:\n  web1.acme.com:\n    address: 192.0.2.1\n  web2: {}\n",
				"pipelines/site.yaml":        stage("      - recipe: r\n"),
				"recipes/r/recipe.yaml":      recipe(step),
				"recipes/r/templates/t.tmpl": tt.template,
				"recipes/r/files/s.bin":      binary,
			})
			p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			st := p.Pipeline.Stages[0].Steps[0].Recipe.Steps[0]
			for _, h := range p.Inventory.Hosts {
				want, ok := tt.want[h.Name]
				if !ok {
					continue
				}
				got := ""
				env, err := p.Start(h, debian13)
				if err != nil {
					t.Fatal(err)
				}
				if es, err := st.Eval(env); err != nil {
					got = "error: " + err.Error()
				} else if len(es) != 1 {
					got = fmt.Sprintf("%d steps", len(es))
				} else {
					got = string(es[0].Args.(*module.File).Data)
				}
				if got != want {
					t.Errorf("%s: got %q, want %q", h.Name, got, want)
				}
			}
		})
	}
}

// spec: Recipes
func TestSourceLinkOutOfRecipe(t *testing.T) {
	dir := writeProject(t, with(nginx, map[string]string{
		"recipes/nginx/recipe.yaml": recipe("  - file:\n      path: /a\n      source: key\n"),
		"secret":                    "private key\n",
	}))
	if err := os.Symlink("../../../secret", filepath.Join(dir, "recipes/nginx/files/key")); err != nil {
		t.Fatal(err)
	}
	_, err := Load(t.Context(), dir, "", "site", nil, Keys{})
	if err == nil || !strings.Contains(err.Error(), "recipes/nginx/recipe.yaml:4:15: source: read recipes/nginx/files/key:") {
		t.Errorf("a source link out of the recipe: %v", err)
	}
}
