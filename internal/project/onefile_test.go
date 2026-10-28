package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/secret"
)

const oneFile = `name: acme
inventories:
  test:
    hosts:
      web1: {}
pipelines:
  site:
    stages:
      - name: base
        hosts: all
        steps:
          - recipe: app
recipes:
  app:
    steps:
      - unit:
          name: app.service
          content: "[Service]\n"
      - repo:
          name: vendor
          url: https://apt.example.com/debian
          suite: trixie
          components: [main]
          key_content: KEY
`

// spec: Project layout; Inventory; Recipes; Pipelines; Modules/repo; Modules/service and unit
func TestOneFileLoad(t *testing.T) {
	key := strings.ReplaceAll(strings.TrimSpace(string(readTestKey(t))), "\n", "\n            ")
	withKey := strings.Replace(oneFile, "KEY", "|\n            "+key, 1)
	t.Run("a key in winch.yaml", func(t *testing.T) {
		dir := writeProject(t, map[string]string{"winch.yaml": withKey, "inventories/test.yaml": "", "pipelines/site.yaml": ""})
		p, err := Load(t.Context(), dir, "test", "site", nil, Keys{})
		if err != nil {
			t.Fatal(err)
		}
		if p.Inventory.Hosts[0].Name != "web1" {
			t.Errorf("hosts: %v", p.Inventory.Hosts)
		}
		steps := p.Pipeline.Stages[0].Steps[0].Recipe.Steps
		if u := steps[0].Args.(*module.Unit); string(u.Data) != "[Service]\n" {
			t.Errorf("unit data: %q", u.Data)
		}
		if r := steps[1].Args.(*module.Repo); len(r.KeyData) == 0 {
			t.Error("repo: no key data")
		}
	})
	t.Run("--inventory takes a name", func(t *testing.T) {
		dir := writeProject(t, map[string]string{"inventories/prod.yaml": "hosts:\n  web2: {}\n"})
		p, err := Load(t.Context(), dir, "prod", "site", nil, Keys{})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Inventory.Hosts) != 1 || p.Inventory.File != "inventories/prod.yaml" {
			t.Errorf("hosts: %v", p.Inventory.Hosts)
		}
	})
	asFile := func(arg string) string {
		return strings.Replace(oneFile, "      - unit:\n          name: app.service\n          content: \"[Service]\\n\"", "      - file:\n          path: /x\n          "+arg, 1)
	}
	files := func(cfg string) map[string]string {
		return map[string]string{"winch.yaml": cfg, "inventories/test.yaml": "", "pipelines/site.yaml": ""}
	}
	tests := []struct {
		name      string
		files     map[string]string
		inventory string
		want      string
	}{
		{name: "an inventory in both places", files: map[string]string{"winch.yaml": withKey}, want: `winch.yaml:3:3: inventory "test" is also inventories/test.yaml`},
		{name: "a pipeline in both places", files: map[string]string{"winch.yaml": withKey}, want: `winch.yaml:7:3: pipeline "site" is also pipelines/site.yaml`},
		{name: "a recipe in both places", files: map[string]string{"winch.yaml": withKey, "inventories/test.yaml": "", "pipelines/site.yaml": "", "recipes/app/recipe.yaml": "steps: []\n"},
			want: `winch.yaml:14:3: recipe "app" is also recipes/app/`},
		{name: "a recipe directory without recipe.yaml", files: map[string]string{"winch.yaml": withKey, "inventories/test.yaml": "", "pipelines/site.yaml": "", "recipes/app/templates/x": "x"},
			want: `winch.yaml:14:3: recipe "app" is also recipes/app/; keep one of the two`},
		{name: "a bad recipe name", files: files(withKey + "  App:\n    steps: []\n"), want: `winch.yaml:35:3: recipe "App": a recipe name has only lowercase letters, digits, and _`},
		{name: "template in a recipe in winch.yaml", files: files(asFile("template: x.tmpl")), want: "winch.yaml:18:21: template: a recipe in winch.yaml cannot use template; use content with !tpl"},
		{name: "source of file in a recipe in winch.yaml", files: files(asFile("source: x")), want: "winch.yaml:18:19: source: a recipe in winch.yaml cannot use source; use content"},
		{name: "source of unit in a recipe in winch.yaml", files: files(strings.Replace(oneFile, `content: "[Service]\n"`, "source: app.service", 1)),
			want: "winch.yaml:18:19: source: a recipe in winch.yaml cannot use source; use content"},
		{name: "key in a recipe in winch.yaml", files: files(strings.Replace(oneFile, "key_content: KEY", "key: vendor.asc", 1)),
			want: "winch.yaml:24:16: key: a recipe in winch.yaml cannot use key; use key_content"},
		{name: "key_content that is not a key", files: files(oneFile), want: "winch.yaml:24:24: key_content is not an ASCII-armored OpenPGP public key"},
		{name: "unit with content and source", files: map[string]string{"pipelines/site.yaml": stage("      - recipe: app\n"),
			"recipes/app/recipe.yaml":       "steps:\n  - unit: {name: app.service, content: x, source: app.service}\n",
			"recipes/app/files/app.service": "x"},
			want: "a unit has only one of content and source"},
		{name: "unit with content and an empty source", files: map[string]string{"pipelines/site.yaml": stage("      - recipe: app\n"),
			"recipes/app/recipe.yaml": "steps:\n  - unit: {name: app.service, content: x, source: \"\"}\n"},
			want: "a unit has only one of content and source"},
		{name: "unit without content", files: map[string]string{"pipelines/site.yaml": stage("      - unit: {name: app.service}\n")},
			want: "a unit needs content or source"},
		{name: "repo with key and key_content", files: map[string]string{"pipelines/site.yaml": stage("      - recipe: app\n"),
			"recipes/app/recipe.yaml": "steps:\n  - repo: {name: v, url: https://a.example.com, suite: s/, key: k.asc, key_content: x}\n",
			"recipes/app/files/k.asc": "x"},
			want: "a repo has at most one of key and key_content"},
		{name: "repo with an empty key and key_content", files: map[string]string{"pipelines/site.yaml": stage("      - recipe: app\n"),
			"recipes/app/recipe.yaml": "steps:\n  - repo: {name: v, url: https://a.example.com, suite: s/, key: \"\", key_content: x}\n"},
			want: "a repo has at most one of key and key_content"},
		{name: "an inventory path", inventory: "inventories/test.yaml", want: `unknown inventory "inventories/test.yaml"; name an inventory without its directory and .yaml, such as "test"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(t.Context(), writeProject(t, tt.files), tt.inventory, "site", nil, Keys{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func readTestKey(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../module/testdata/key.asc")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// spec: Variables/Secrets (winch secret generate); Project layout
func TestWriteSecretInWinchYAML(t *testing.T) {
	k := newKey(t)
	cfg := "name: acme\ninventory: prod\nrecipients:\n  - " + k.id.Recipient().String() + "\n" +
		"inventories:\n  prod:\n    hosts:\n      web1:\n"
	dir := writeProject(t, map[string]string{"winch.yaml": cfg, "inventories/test.yaml": "", "pipelines/site.yaml": readsPipeline("pw", "token")})
	file, err := WriteSecret(dir, "", "", "pw", "hunter2")
	if err != nil || file != "inventories.prod of winch.yaml" {
		t.Fatalf("WriteSecret = %q, %v", file, err)
	}
	if _, err := WriteSecret(dir, "", "web1", "token", "s3cret"); err != nil {
		t.Fatalf("WriteSecret --host: %v", err)
	}
	if _, err := WriteSecret(dir, "", "web9", "token", "s3cret"); err == nil || err.Error() != `host "web9" is not in inventories.prod of winch.yaml` {
		t.Errorf("WriteSecret for an unknown host: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "winch.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	texts := secretTexts(string(data))
	if len(texts) != 2 || !strings.Contains(string(data), "    groups:\n      all:\n        vars:\n          pw: !secret ") ||
		!strings.Contains(string(data), "      web1:\n        vars:\n          token: !secret ") {
		t.Errorf("winch.yaml:\n%s", data)
	}
	p, err := Load(t.Context(), dir, "", "site", nil, Keys{Identity: secret.Identity{Path: k.path}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Inventory.Hosts[0].Vars["token"].(*Sealed).Plain; got != "s3cret" {
		t.Errorf("token = %q", got)
	}
}
