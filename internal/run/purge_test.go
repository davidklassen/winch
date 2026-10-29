package run_test

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

var purgeFiles = map[string]string{
	"winch.yaml":            "name: acme\ninventory: test\n",
	"inventories/test.yaml": "hosts:\n  web1: {}\n",
	"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - dir:
          path: /etc/x
          purge: true
      - recipe: app
  - name: extra
    hosts: all
    steps:
      - file:
          path: /etc/x/skipped
          content: s
`,
	"pipelines/other.yaml": `stages:
  - name: other
    hosts: all
    steps:
      - file:
          path: /etc/x/other
          content: o
      - file:
          path: /etc/y/z
          content: z
      - file:
          path: /etc/x2
          content: x
`,
	"recipes/app/recipe.yaml": `steps:
  - file:
      path: /etc/app
      content: a
    notify: clean
handlers:
  clean:
    - dir:
        path: /etc/y
        purge: true
`,
}

// spec: Modules/file, dir, link (dir purge: a step for this host in any
// pipeline of the project; a stage that --stages leaves out counts)
func TestPurgeKeep(t *testing.T) {
	p := loadFiles(t, purgeFiles)
	if err := p.Select(project.Selection{Stages: "base"}); err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	if o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))); !o.OK() {
		t.Fatalf("apply failed: %s", errOut.String())
	}
	want := map[string][]string{
		"web1 /etc/x": {"/etc/x/other", "/etc/x/skipped"},
		"web1 /etc/y": {"/etc/y/z"},
	}
	if !reflect.DeepEqual(h.DirKeep, want) {
		t.Errorf("kept paths = %q, want %q", h.DirKeep, want)
	}
}

// spec: Modules/file, dir, link (dir purge keeps a download unpack directory
// with everything in it)
func TestPurgeKeepUnpack(t *testing.T) {
	p := loadFiles(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - dir:
          path: /opt/app
          purge: true
      - dir:
          path: /opt/app/bin
          purge: true
      - dir:
          path: /opt/app2
          purge: true
      - download:
          url: https://example.com/app.tgz
          sha256: "0000000000000000000000000000000000000000000000000000000000000000"
          unpack: /opt/app
`,
	})
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	if o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))); !o.OK() {
		t.Fatalf("apply failed: %s", errOut.String())
	}
	want := map[string][]string{"web1 /opt/app2": nil}
	if !reflect.DeepEqual(h.DirKeep, want) {
		t.Errorf("purged directories with their kept paths = %q, want %q", h.DirKeep, want)
	}
}

// spec: CLI/JSON output
func TestAppliedChanges(t *testing.T) {
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - dir:\n          path: /etc/nginx/conf.d\n          purge: true\n",
	}), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetResult("web1", "/etc/nginx/conf.d", module.Result{Status: module.Change, Action: module.Modify,
		Changes: []string{"remove file /etc/nginx/conf.d/old.conf"}})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	// Between plan and apply, another file shows up on the host.
	h.OnApply = func(string, string) {
		h.SetResult("web1", "/etc/nginx/conf.d", module.Result{Status: module.Change, Action: module.Modify,
			Changes: []string{"remove file /etc/nginx/conf.d/x\x1b[31m.conf"}})
	}
	applied := applyJSON(t, plan, h)
	if want := `"changes":["remove file /etc/nginx/conf.d/x?[31m.conf"]`; !strings.Contains(applied, want) {
		t.Errorf("applied events:\n%s\nwant %s", applied, want)
	}
}
