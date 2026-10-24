package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/davidklassen/winch/internal/golden"
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
			args, _ := json.Marshal(st.Args)
			fmt.Fprintf(&b, "  %s %s at %s\n", st.Module, args, st.Pos)
		}
	}
	return b.String()
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
		{name: "pipeline-name-with-dots", pipeline: "web.v2", files: map[string]string{"pipelines/web.v2.yaml": "stages: []\n"}},
		{name: "no-winch-yaml", files: map[string]string{"winch.yaml": ""}},
		{name: "no-name", files: map[string]string{"winch.yaml": "inventory: inventories/test.yaml\n"}},
		{name: "winch-unknown-key", files: map[string]string{"winch.yaml": "name: acme\ninventroy: x\n"}},
		{name: "host-unknown-key", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    adress: 1.2.3.4\n"}},
		{name: "all-with-hosts", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1: {}\ngroups:\n  all:\n    hosts: [web1]\n"}},
		{name: "other-group", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1: {}\ngroups:\n  web:\n    user: x\n"}},
		{name: "host-named-all", files: map[string]string{"inventories/test.yaml": "hosts:\n  all: {}\n"}},
		{name: "empty-inventory", files: map[string]string{"inventories/test.yaml": "hosts: {}\n"}},
		{name: "unknown-pipeline", pipeline: "sit"},
		{name: "bad-pipeline-name", pipeline: "../winch"},
		{name: "duplicate-stage", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps: []\n  - name: a\n    hosts: all\n    steps: []\n"}},
		{name: "stage-missing-hosts", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    steps: []\n"}},
		{name: "unknown-stage-host", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: web3\n    steps: []\n"}},
		{name: "unknown-module", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - fiel:\n          path: /x\n"}},
		{name: "two-modules", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file: {path: /x, content: a}\n        pkg: {name: x}\n"}},
		{name: "empty-step", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - {}\n"}},
		{name: "step-not-map", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file\n"}},
		{name: "file-no-content", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: /x\n"}},
		{name: "file-content-and-absent", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: /x\n          content: a\n          absent: true\n"}},
		{name: "file-relative-path", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: all\n    steps:\n      - file:\n          path: x\n          content: a\n"}},
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
			p, err := Load(dir, tt.inventory, pipeline)
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
		{name: "no-inventories", files: map[string]string{
			"winch.yaml":            "name: acme\n",
			"inventories/test.yaml": "",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, tt.files)
			got := "ok\n"
			if err := Validate(dir, tt.inventory); err != nil {
				got = err.Error() + "\n"
			}
			golden.Assert(t, filepath.Join("testdata", "validate", tt.name+".golden"), []byte(got))
		})
	}
}
