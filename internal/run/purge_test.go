package run_test

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
)

var purgeFiles = map[string]string{
	"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
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
