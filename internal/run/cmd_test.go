package run_test

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
)

var cmdFiles = map[string]string{
	"winch.yaml":            "name: acme\ninventory: test\n",
	"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n  web3: {}\n",
	"pipelines/site.yaml": `stages:
  - name: checks
    hosts: all
    health:
      command: curl -sf http://localhost/
    steps:
      - assert:
          command: systemctl is-active nginx
          message: nginx does not run
  - name: base
    hosts: web1
    steps:
      - cmd:
          command: apt-get clean
  - name: build
    hosts: web2
    steps:
      - cmd:
          command: make install
          creates: /usr/local/bin/app
          dir: /srv/app
`,
}

// spec: Running a pipeline/Plan; Modules/cmd; Modules/assert; CLI/Output
func TestPlanCmd(t *testing.T) {
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), loadFiles(t, cmdFiles), h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "plan", "cmd.golden"), output(&out, &errOut))
	if change, unchanged, unknown, failed := plan.Counts(); change != 1 || unchanged != 1 || unknown != 1 || failed != 0 {
		t.Errorf("counts = %d %d %d %d, want 1 to change, 1 unchanged, 1 unknown", change, unchanged, unknown, failed)
	}
}

// spec: Modules/cmd; Modules/assert; Running a pipeline/Apply; Modules/reboot
func TestApplyCmd(t *testing.T) {
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), loadFiles(t, cmdFiles), h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if !o.OK() {
		t.Fatalf("apply failed: %s", errOut.String())
	}
	// web3 has only the assert: no change, so apply skips it.
	want := map[string][]string{
		"web1": {"assert systemctl is-active nginx", "cmd apt-get clean"},
		"web2": {"assert systemctl is-active nginx", "cmd make install"},
	}
	for _, host := range []string{"web1", "web2", "web3"} {
		if !slices.Equal(h.Log[host], want[host]) {
			t.Errorf("%s ran %q, want %q", host, h.Log[host], want[host])
		}
	}
	if !o.Changed["web1"] || !o.Changed["web2"] || o.Changed["web3"] {
		t.Errorf("changed = %v, want web1 and web2", o.Changed)
	}
	for _, line := range []string{"web1: base: ~ cmd apt-get clean\n", "web2: build: + cmd make install\n"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("no %q in the apply output:\n%s", line, out.String())
		}
	}
	if strings.Contains(out.String(), "assert") {
		t.Errorf("a passing assert shows in the apply output:\n%s", out.String())
	}
}

// spec: Steps (a step that runs a command counts as changed); Handlers
func TestCmdNotifies(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: app\n",
		"recipes/app/recipe.yaml": `steps:
  - cmd:
      command: app migrate
    then: echo done
    notify: restart
handlers:
  restart:
    - service:
        name: app
        restarted: true
`,
	}
	h := fakehost.New()
	p := loadFiles(t, files)
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	for _, line := range []string{"      ? cmd app migrate\n          then: echo done\n", "      ! handler app.restart\n", "1 host: 1 to change, 0 unchanged, 0 unknown\n"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("no %q in the plan:\n%s", line, out.String())
		}
	}
	if !plan.HasChanges() {
		t.Error("the plan has no changes")
	}
	if ok, got := applyAll(t, p, h); !ok {
		t.Fatalf("apply failed:\n%s", got)
	}
	if want := []string{"cmd app migrate", "command echo done", "app restart"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if p := h.PendingOf("web1"); len(p) != 0 {
		t.Errorf("pending handlers after the run: %v", p)
	}
}

// spec: CLI/Output (the summary); Steps (a pending then)
func TestPendingThenOfCmdCounts(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - cmd:\n          command: app migrate\n        then: echo done\n",
	}
	h := fakehost.New()
	h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "base", Step: 1, Module: "cmd", Main: "app migrate"})
	plan := run.MakePlan(context.Background(), loadFiles(t, files), h.Connector(), run.Options{})
	if change, _, unknown, _ := plan.Counts(); change != 1 || unknown != 0 {
		t.Errorf("counts: %d to change, %d unknown; want a pending then to count as a change", change, unknown)
	}
}

// spec: Running a pipeline/Apply; Modules/cmd
func TestApplyOnlyUnknown(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - cmd:\n          command: uptime\n",
	}
	h := fakehost.New()
	if ok, got := applyAll(t, loadFiles(t, files), h); !ok || !slices.Equal(h.Log["web1"], []string{"cmd uptime"}) {
		t.Errorf("apply ran %q:\n%s", h.Log["web1"], got)
	}
}

// spec: Modules/assert; Running a pipeline/Failures
func TestAssertFails(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "hello\n"
      - assert:
          command: probe 25
          message: outbound port 25 is blocked
      - file:
          path: /etc/issue
          content: "issue\n"
`,
	}
	h := fakehost.New()
	h.FailCommand("web1", "probe 25")
	ok, got := applyAll(t, loadFiles(t, files), h)
	if ok {
		t.Fatal("apply passed")
	}
	if want := "web1: base: failed: assert probe 25: outbound port 25 is blocked\n"; !strings.Contains(string(got), want) {
		t.Errorf("no %q in the output:\n%s", want, got)
	}
	if _, ok := h.File("web1", "/etc/issue"); ok {
		t.Error("the step after the failing assert ran on web1")
	}
	if _, ok := h.File("web2", "/etc/issue"); !ok {
		t.Error("web2 did not finish")
	}
}

// spec: Modules/reboot (a host whose plan has only * steps); CLI ("--exit-code")
func TestAssertOnly(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - assert:\n          command: probe\n          message: x\n",
	}
	h := fakehost.New()
	p := loadFiles(t, files)
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	if plan.HasChanges() {
		t.Error("a plan with only an assert has changes")
	}
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if !strings.HasPrefix(out.String(), "1 host: 0 to change, 1 unchanged, 0 unknown\n") {
		t.Errorf("plan:\n%s", out.String())
	}
	if ok, got := applyAll(t, p, h); !ok || len(h.Log["web1"]) != 0 {
		t.Errorf("apply ran %q:\n%s", h.Log["web1"], got)
	}
}
