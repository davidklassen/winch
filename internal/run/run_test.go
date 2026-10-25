package run_test

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

func load(t *testing.T, web3 string) *project.Project {
	t.Helper()
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n  web3:\n    address: " + web3 + "\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "hello\nworld\n"
  - name: cleanup
    hosts: web2
    steps:
      - file:
          path: /etc/issue
          absent: true
`,
	})
	p, err := project.Load(dir, "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// spec: Running a pipeline/Plan; CLI/Output
func TestPlanOutput(t *testing.T) {
	tests := []struct {
		name  string
		web3  string
		setup func(h *fakehost.Hosts)
	}{
		{name: "create", web3: "web3"},
		{name: "change", web3: "web3", setup: func(h *fakehost.Hosts) {
			h.SetFile("web1", "/etc/motd", "hello\nthere\n")
			h.SetFile("web2", "/etc/motd", "hello\nthere\n")
			h.SetFile("web3", "/etc/motd", "hello\nworld\n")
			h.SetFile("web2", "/etc/issue", "Debian\n")
		}},
		{name: "no-changes", web3: "web3", setup: func(h *fakehost.Hosts) {
			for _, host := range []string{"web1", "web2", "web3"} {
				h.SetFile(host, "/etc/motd", "hello\nworld\n")
			}
		}},
		{name: "check-fails", web3: "web3", setup: func(h *fakehost.Hosts) {
			h.FailCheck("web2")
		}},
		{name: "unreachable", web3: "unreachable"},
		{name: "fails-in-later-stage", web3: "web3", setup: func(h *fakehost.Hosts) {
			h.SetFile("web2", "/etc/issue", "Debian\n")
			h.FailCheck("web2 /etc/issue")
		}},
		{name: "control-characters", web3: "web3", setup: func(h *fakehost.Hosts) {
			h.SetFile("web1", "/etc/motd", "hello\n\x1b]0;owned\x07\x1b[2Aworld\n")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			plan := run.MakePlan(context.Background(), load(t, tt.web3), h.Connector())
			var out, errOut bytes.Buffer
			plan.Write(&out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "plan", tt.name+".golden"),
				[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
			if h.Applies != 0 {
				t.Errorf("plan applied %d steps", h.Applies)
			}
		})
	}
}

// spec: Running a pipeline/Apply; Running a pipeline/Failures
func TestApply(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *fakehost.Hosts)
	}{
		{name: "all"},
		// web2 has a second stage, which must not run after the failure.
		{name: "one-host-fails", setup: func(h *fakehost.Hosts) { h.FailApply("web2") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			h.SetFile("web3", "/etc/motd", "hello\nworld\n")
			h.SetFile("web2", "/etc/issue", "Debian\n")
			if tt.setup != nil {
				tt.setup(h)
			}
			p := load(t, "web3")
			plan := run.MakePlan(context.Background(), p, h.Connector())
			var out, errOut bytes.Buffer
			ok := run.Apply(context.Background(), plan, h.Connector(), &out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "apply", tt.name+".golden"),
				[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
			failed := tt.setup != nil
			if ok == failed {
				t.Errorf("Apply = %v, want %v", ok, !failed)
			}
			if c, _ := h.File("web1", "/etc/motd"); c != "hello\nworld\n" {
				t.Errorf("web1 /etc/motd = %q", c)
			}
			if _, ok := h.File("web2", "/etc/issue"); ok != failed {
				t.Errorf("web2 /etc/issue exists = %v, want %v", ok, failed)
			}
			if h.Open != 0 {
				t.Errorf("%d connections are still open", h.Open)
			}
			again := run.MakePlan(context.Background(), p, h.Connector())
			if again.HasChanges() != (tt.setup != nil) {
				t.Errorf("second plan has changes = %v", again.HasChanges())
			}
		})
	}
}

// spec: Running a pipeline/Failures
func TestHasChangesIgnoresFailedHosts(t *testing.T) {
	h := fakehost.New()
	h.SetFile("web2", "/etc/issue", "Debian\n")
	for _, host := range []string{"web1", "web2", "web3"} {
		h.FailCheck(host + " /etc/issue")
	}
	h.FailCheck("web1")
	h.FailCheck("web3")
	plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector())
	if plan.HasChanges() {
		t.Error("a plan whose changes are all on failed hosts has changes")
	}
}

// spec: Modules/pkg; Running a pipeline/Plan
func TestIndexRefreshOncePerRun(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - pkg:
          name: curl
      - pkg:
          name: [nginx, htop]
  - name: tools
    hosts: all
    steps:
      - pkg:
          name: jq
`,
	})
	p, err := project.Load(dir, "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector())
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "plan", "index-refresh.golden"),
		[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
	if !run.Apply(context.Background(), plan, h.Connector(), &out, &errOut) {
		t.Fatalf("apply failed: %s", errOut.String())
	}
	for _, host := range []string{"web1", "web2"} {
		if n := h.Refreshes[host]; n != 1 {
			t.Errorf("%s: %d index refreshes, want 1", host, n)
		}
	}
}

// spec: Modules/file, dir, link; Running a pipeline/Plan
func TestPlanParents(t *testing.T) {
	tests := []struct {
		name     string
		pipeline string
	}{
		{name: "parents-dir-then-file", pipeline: `stages:
  - name: base
    hosts: all
    steps:
      - dir:
          path: /srv/www
          group: www-data
          mode: "0750"
  - name: site
    hosts: all
    steps:
      - file:
          path: /srv/www/index.html
          content: "hello\n"
`},
		{name: "parents-two-files", pipeline: `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /srv/www/index.html
          content: "hello\n"
      - file:
          path: /srv/www/about.html
          content: "about\n"
`},
		{name: "parents-siblings", pipeline: `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /srv/www/index.html
          content: "hello\n"
      - dir:
          path: /srv/static/img
`},
		{name: "parents-absent-then-file", pipeline: `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /srv/www/old.html
          absent: true
      - file:
          path: /srv/www/index.html
          content: "hello\n"
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := loadFiles(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
				"pipelines/site.yaml":   tt.pipeline,
			})
			h := fakehost.New()
			for _, host := range []string{"web1", "web2"} {
				h.RemoveDir(host, "/srv")
				h.RemoveDir(host, "/srv/www")
				h.RemoveDir(host, "/srv/static")
				h.RemoveDir(host, "/srv/static/img")
			}
			plan := run.MakePlan(context.Background(), p, h.Connector())
			var out, errOut bytes.Buffer
			plan.Write(&out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "plan", tt.name+".golden"),
				[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
		})
	}
}

// spec: Running a pipeline/Apply
func TestApplyChecksStagesWithoutChange(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: install
    hosts: all
    steps:
      - pkg:
          name: nginx
  - name: configure
    hosts: all
    steps:
      - file:
          path: /etc/nginx/sites-enabled/default
          absent: true
`,
	})
	p, err := project.Load(dir, "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetPkgFile("nginx", "/etc/nginx/sites-enabled/default", "server {}\n")
	plan := run.MakePlan(context.Background(), p, h.Connector())
	if st := plan.Stages[1].Hosts[0].Steps[0].Result.Status; st != module.OK {
		t.Fatalf("plan of stage configure = %v, want ok", st)
	}
	var out, errOut bytes.Buffer
	if !run.Apply(context.Background(), plan, h.Connector(), &out, &errOut) {
		t.Fatalf("apply failed: %s", errOut.String())
	}
	if _, ok := h.File("web1", "/etc/nginx/sites-enabled/default"); ok {
		t.Errorf("apply did not run stage configure; apply output:\n%s", out.String())
	}
	again := run.MakePlan(context.Background(), p, h.Connector())
	if again.HasChanges() || len(again.Failed) != 0 {
		t.Errorf("second plan: changes %v, failed %v", again.HasChanges(), again.Failed)
	}
}

var recipes = map[string]string{
	"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
	"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - name: Web server
        recipe: nginx
      - file:
          path: /etc/issue
          content: "stage step\n"
      - recipe: php
  - name: tools
    hosts: web2
    steps:
      - recipe: tools
`,
	"recipes/nginx/recipe.yaml": `require:
  - !expr 'facts.os.id == "debian"'
steps:
  - name: Site
    file:
      path: /etc/nginx/site
      template: site.tmpl
  - file:
      path: /etc/nginx/logo.png
      source: logo.png
`,
	"recipes/nginx/templates/site.tmpl": "server_name {{ .host.name }};\n",
	"recipes/nginx/files/logo.png":      "\x89PNG\r\n\x1a\n\x00\x00\xff",
	"recipes/php/recipe.yaml":           "steps:\n  - file:\n      path: /etc/php.ini\n      content: \"x\\n\"\n",
	"recipes/tools/recipe.yaml": `require:
  - !expr 'facts.os.version == "13"'
steps:
  - file:
      path: /etc/tools
      template: tools.tmpl
`,
	"recipes/tools/templates/tools.tmpl": "{{ if eq .host.name \"web2\" }}{{ index .host.groups 3 }}{{ end }}\n",
}

func loadFiles(t *testing.T, files map[string]string) *project.Project {
	t.Helper()
	p, err := project.Load(vmtest.WriteProject(t, files), "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// spec: CLI/Output; Steps; Recipes; Running a pipeline/Plan; Templates and expressions/When they run; Modules/file, dir, link
func TestPlanRecipes(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		setup  func(h *fakehost.Hosts)
		failed []string
	}{
		// web2 fails in stage tools on the template.
		{name: "recipes", failed: []string{"web2"}},
		{name: "recipes-require-fails", failed: []string{"web1"},
			files: map[string]string{"recipes/tools/templates/tools.tmpl": "{{ .host.short }}\n"},
			setup: func(h *fakehost.Hosts) {
				h.SetFacts("web1", facts.Facts{OS: facts.OS{ID: "ubuntu", Version: "24.04", Codename: "noble"}})
			}},
		// tools runs only on web2, so web1 does not need version 13.
		{name: "recipes-require-other-stage", failed: nil,
			files: map[string]string{"recipes/tools/templates/tools.tmpl": "{{ .host.short }}\n"},
			setup: func(h *fakehost.Hosts) {
				h.SetFacts("web1", facts.Facts{OS: facts.OS{ID: "debian", Version: "12", Codename: "bookworm"}})
			}},
		// web2 fails the requirement of tools, a recipe of its second stage,
		// before its first stage.
		{name: "recipes-require-later-stage", failed: []string{"web2"},
			setup: func(h *fakehost.Hosts) {
				h.SetFacts("web2", facts.Facts{OS: facts.OS{ID: "debian", Version: "12", Codename: "bookworm"}})
			}},
		{name: "recipes-require-run-error", failed: []string{"web1"},
			files: map[string]string{
				"recipes/tools/templates/tools.tmpl": "{{ .host.short }}\n",
				"recipes/nginx/recipe.yaml":          "require:\n  - !expr 'int(facts.os.version) >= 13'\nsteps: []\n",
			},
			setup: func(h *fakehost.Hosts) {
				h.SetFacts("web1", facts.Facts{OS: facts.OS{ID: "debian", Codename: "forky"}})
			}},
		{name: "recipes-name-control-characters", failed: nil,
			files: map[string]string{"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - name: "x\e]0;owned\a"
        recipe: nginx
`}},
		{name: "recipes-check-fails", failed: []string{"web1"},
			files: map[string]string{"recipes/tools/templates/tools.tmpl": "{{ .host.short }}\n"},
			setup: func(h *fakehost.Hosts) { h.FailCheck("web1 /etc/nginx/site") }},
		{name: "recipes-change", failed: []string{"web2"}, setup: func(h *fakehost.Hosts) {
			for _, host := range []string{"web1", "web2"} {
				h.SetFile(host, "/etc/nginx/site", "server_name "+host+";\n")
				h.SetFile(host, "/etc/nginx/logo.png", "\x89PNG\r\n\x1a\n\x00\x00\xff")
				h.SetFile(host, "/etc/php.ini", "x\n")
			}
			h.SetFile("web1", "/etc/nginx/site", "server_name old;\n")
			h.SetFile("web1", "/etc/nginx/logo.png", "old text\n")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			files := map[string]string{}
			for _, m := range []map[string]string{recipes, tt.files} {
				for k, v := range m {
					files[k] = v
				}
			}
			plan := run.MakePlan(context.Background(), loadFiles(t, files), h.Connector())
			var out, errOut bytes.Buffer
			plan.Write(&out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "plan", tt.name+".golden"),
				[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
			var failed []string
			for _, host := range []string{"web1", "web2"} {
				if plan.Failed[host] != nil {
					failed = append(failed, host)
				}
				if n := h.FactsReads[host]; n != 1 {
					t.Errorf("%s: facts read %d times, want 1", host, n)
				}
			}
			if !slices.Equal(failed, tt.failed) {
				t.Errorf("failed hosts %v, want %v", failed, tt.failed)
			}
		})
	}
}

// spec: CLI/Output; Steps
func TestApplyRecipes(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *fakehost.Hosts)
	}{
		{name: "recipes"},
		{name: "recipes-fails", setup: func(h *fakehost.Hosts) { h.FailApply("web1 /etc/php.ini") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			p := loadFiles(t, recipes)
			plan := run.MakePlan(context.Background(), p, h.Connector())
			var out, errOut bytes.Buffer
			run.Apply(context.Background(), plan, h.Connector(), &out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "apply", tt.name+".golden"),
				[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
			if c, _ := h.File("web1", "/etc/nginx/logo.png"); c != "\x89PNG\r\n\x1a\n\x00\x00\xff" {
				t.Errorf("logo.png = %q", c)
			}
			if n := h.FactsReads["web1"]; n != 1 {
				t.Errorf("facts read %d times in plan and apply, want 1", n)
			}
		})
	}
}

var varsFiles = map[string]string{
	"winch.yaml": `name: acme
inventory: inventories/test.yaml
vars:
  mail_server: false
  port: 80
`,
	"inventories/test.yaml": `hosts:
  web1: {}
  web2: {}
  web3: {}
groups:
  mail:
    hosts: [web2, web3]
    vars:
      mail_server: true
  broken:
    hosts: [web3]
    vars:
      port: eighty
`,
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - recipe: site
`,
	"recipes/site/recipe.yaml": `vars:
  site_names: !expr 'vars.mail_server ? ["mail", "www"] : ["www"]'
steps:
  - file:
      path: !tpl /etc/site/{{ .item }}
      content: !tpl "{{ .item }} on {{ .host.name }}\n"
    loop: !expr vars.site_names
  - file:
      path: /etc/site/mail.conf
      template: mail.tmpl
    when: !expr vars.mail_server
  - file:
      path: /etc/site/port
      content: !expr 'string(vars.port + 1) + "\n"'
`,
	"recipes/site/templates/mail.tmpl": "relay {{ .host.short }}\n",
}

// spec: Templates and expressions/When they run; Steps; Running a pipeline/Plan; CLI/Output
func TestPlanVars(t *testing.T) {
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), loadFiles(t, varsFiles), h.Connector())
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "plan", "vars.golden"),
		[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
	if plan.Failed["web3"] == nil || len(plan.Failed) != 1 {
		t.Errorf("failed hosts %v, want web3 only", plan.Failed)
	}
	if !run.Apply(context.Background(), plan, h.Connector(), &out, &errOut) {
		t.Logf("apply: %s", errOut.String())
	}
	for _, f := range []struct{ host, path, want string }{
		{"web1", "/etc/site/www", "www on web1\n"},
		{"web2", "/etc/site/mail", "mail on web2\n"},
		{"web2", "/etc/site/mail.conf", "relay web2\n"},
		{"web2", "/etc/site/port", "81\n"},
	} {
		if c, _ := h.File(f.host, f.path); c != f.want {
			t.Errorf("%s %s = %q, want %q", f.host, f.path, c, f.want)
		}
	}
	for _, path := range []string{"/etc/site/mail", "/etc/site/mail.conf"} {
		if _, ok := h.File("web1", path); ok {
			t.Errorf("web1 has %s", path)
		}
	}
}

// spec: CLI/Output
func TestPlanStageNameControlCharacters(t *testing.T) {
	h := fakehost.New()
	p := loadFiles(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: "x\e]0;owned\a"
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "x\n"
`,
	})
	plan := run.MakePlan(context.Background(), p, h.Connector())
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "plan", "stage-name-control-characters.golden"),
		[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
}

// spec: CLI/Output
func TestApplyStageNameControlCharacters(t *testing.T) {
	h := fakehost.New()
	h.FailApply("web2")
	p := loadFiles(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
		"pipelines/site.yaml": `stages:
  - name: "x\e]0;owned\a"
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "x\n"
`,
	})
	plan := run.MakePlan(context.Background(), p, h.Connector())
	var out, errOut bytes.Buffer
	run.Apply(context.Background(), plan, h.Connector(), &out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "apply", "stage-name-control-characters.golden"),
		[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
}
