package project

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/yamlx"
)

// spec: YAML; CLI/Errors
func FuzzValidate(f *testing.F) {
	f.Add(base["winch.yaml"], base["inventories/test.yaml"], base["pipelines/site.yaml"], "steps: []\n")
	f.Add(base["winch.yaml"], base["inventories/test.yaml"], stage("      - recipe: r\n"), recipe("  - pkg:\n      name: curl\n    notify: reload\n"))
	f.Add(base["winch.yaml"], base["inventories/test.yaml"], stage("      - recipe: r\n"), "steps:\n  - cmd: !tpl \"echo {{ .x }}\"\nhandlers:\n  - name: reload\n    service:\n      name: nginx\n      state: reloaded\n")
	f.Add(base["winch.yaml"], "hosts:\n  web1:\n    vars:\n      a: &x [1, *x]\n", base["pipelines/site.yaml"], "")
	f.Add(base["winch.yaml"], base["inventories/test.yaml"], stage("      - file:\n          path: /a\n          content: !expr 'vars.x +'\n        when: !expr 'host.name =='\n"), "")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("../../examples", name))
		if err != nil {
			f.Fatal(err)
		}
		return string(b)
	}
	f.Add(read("caddy/winch.yaml"), "", "", "")
	// A demo recipe loads as recipe r, with the variables it reads.
	config := base["winch.yaml"] + "vars:\n  domain: example.com\n  admin_email: a@example.com\n"
	for _, r := range []string{"certbot", "leftovers", "nftables", "ssh", "unattended_upgrades", "unbound"} {
		f.Add(config, base["inventories/test.yaml"], stage("      - recipe: r\n"), strings.ReplaceAll(read("demo/recipes/"+r+"/recipe.yaml"), r+"_", "r_"))
	}
	// A fuzz worker runs one input at a time, so the inputs share dir.
	dir := f.TempDir()
	for _, sub := range []string{"inventories", "pipelines", "recipes/r"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			f.Fatal(err)
		}
	}
	f.Fuzz(func(t *testing.T, config, inventory, pipeline, rcp string) {
		for name, data := range map[string]string{
			"winch.yaml":            config,
			"inventories/test.yaml": inventory,
			"pipelines/site.yaml":   pipeline,
			"recipes/r/recipe.yaml": rcp,
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		warnings, err := Validate(dir, "", nil)
		checkPositions(t, err)
		for _, w := range warnings {
			checkPositions(t, w)
		}
	})
}

// checkPositions fails when an error that err joins does not name a file, a
// line, and a column.
func checkPositions(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			checkPositions(t, e)
		}
		return
	}
	var ye *yamlx.Error
	if !errors.As(err, &ye) || ye.Pos.File == "" || ye.Pos.Line < 1 || ye.Pos.Col < 1 {
		t.Errorf("the error %q names no file, line, and column", err)
	}
}

// spec: Templates and expressions
func FuzzCompile(f *testing.F) {
	for _, text := range []string{
		`facts.os.id == "debian" and facts.os.version == "13"`,
		`join(map(match("all"), string(.vars.key)), ",")`,
		`filter(match("all"), .name != host.name)`,
		`"/srv/" + host.name`,
		`$env.facts.os.id == "x"`,
		`get(vars, "a" + item)`,
		`{{ .vars.nginx_port }}`,
		`{{ range $k, $v := .vars.users }}{{ $k }}={{ $v }}{{ end }}`,
		`{{ index .host.vars "x" | quote }}`,
		`{{ define "x" }}{{ template "x" . }}{{ end }}`,
		`{{ .item.name }`,
	} {
		for _, tpl := range []bool{false, true} {
			f.Add(text, tpl, false)
			f.Add(text, tpl, true)
		}
	}
	f.Fuzz(func(t *testing.T, text string, tpl, loop bool) {
		var sc scope
		if loop {
			sc = scope{reads: &[]varRead{}, args: true}
		} else {
			sc = scope{reads: &[]varRead{}, noItem: "a default cannot use item", sealed: true, noMatch: "a default cannot use match()"}
		}
		tag := "!expr"
		if tpl {
			tag = "!tpl"
			_, err := parseTemplate("templates/f.tmpl", []byte(text), sc)
			checkPositions(t, err)
		}
		_, err := compile(&yamlx.Node{Kind: yamlx.Scalar, Value: text, Tag: tag, Pos: yamlx.Pos{File: "f.yaml", Line: 1, Col: 1}}, sc)
		checkPositions(t, err)
	})
}
