package run_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
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
	sum := sha256.Sum256([]byte("app migrate"))
	h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "base", Step: 1, Module: "cmd", Main: hex.EncodeToString(sum[:])})
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

// spec: CLI/Output (a command of several lines); CLI/JSON output; Modules/file, dir, link (validate)
func TestPlanShowsCommands(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - name: Clean
        cmd:
          command: |
            true
            rm -rf /srv/x
      - assert:
          command: |
            test -d /srv
            test -d /etc
          message: no /srv
      - file:
          path: /etc/nginx/nginx.conf
          content: "events {}\n"
          validate: nginx -t
      - file:
          path: /etc/motd
          content: "hello\n"
          validate: |
            grep -q hello /etc/motd
            test -s /etc/motd
      - file:
          path: /etc/issue
          content: "Debian\n"
          validate: "false"
      - file:
          path: /etc/app.conf
          content: "a\n"
          validate: app check
      - certbot:
          name: example.com
          domains: [example.com]
          email: admin@example.com
          pre_hook: |
            systemctl stop nginx
            sleep 1
          deploy_hook: |
            systemctl reload nginx
            systemctl reload dovecot
`,
	}
	h := fakehost.New()
	h.SetFile("web1", "/etc/issue", "Debian\n")
	// Only the mode changes, so apply runs no validate.
	h.SetResult("web1", "/etc/app.conf", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mode 0600 → 0644"}})
	h.SetResult("web1", "example.com", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{
		"deploy_hook\nsystemctl reload nginx\nsystemctl reload dovecot",
		"pre_hook true ... →\nsystemctl stop nginx\nsleep 1",
	}})
	p := &progress{calls: map[string][]string{}}
	plan := run.MakePlan(context.Background(), loadFiles(t, files), h.Connector(), run.Options{Progress: p})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	out.WriteString("json:\n")
	plan.WriteJSON(run.NewEvents(plain(&out), func() time.Time { return time.Time{} }))
	golden.Assert(t, filepath.Join("testdata", "plan", "commands.golden"), output(&out, &errOut))

	out.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := "web1: base: ~ Clean: cmd true ...\n"; !strings.Contains(out.String(), want) {
		t.Errorf("apply has no line %q:\n%s", want, out.String())
	}
	if !slices.Contains(p.calls["web1"], "base: Clean: cmd true ...") || slices.ContainsFunc(p.calls["web1"], func(c string) bool { return strings.Contains(c, "\n") }) {
		t.Errorf("progress %q, want one line per text", p.calls["web1"])
	}
	out.Reset()
	h = fakehost.New()
	h.SetFile("web1", "/etc/issue", "Debian\n")
	plan = run.MakePlan(context.Background(), loadFiles(t, files), h.Connector(), run.Options{})
	if !run.Apply(context.Background(), plan, h.Connector(), run.NewEvents(plain(&out), func() time.Time { return time.Time{} })).OK() {
		t.Fatal(errOut.String())
	}
	if want := `"step":"file /etc/motd","module":"file","status":"change","action":"create","changes":["owner root, group root, mode 0644"],"validate":"grep -q hello /etc/motd\ntest -s /etc/motd\n"}`; !strings.Contains(out.String(), want) {
		t.Errorf("the applied events have no %q:\n%s", want, out.String())
	}
	if want := `"step":"file /etc/issue","module":"file","status":"ok"}`; !strings.Contains(out.String(), want) {
		t.Errorf("the applied events have no %q:\n%s", want, out.String())
	}
}

// spec: Steps (the record of a then holds a hash of the command of a cmd)
func TestThenRecordOfCmd(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - cmd:\n          command: \"true\\nnotify --token abc\"\n        then: echo done\n",
	}
	h := fakehost.New()
	h.FailCommand("web1", "echo done")
	if ok, got := applyAll(t, loadFiles(t, files), h); ok {
		t.Fatalf("apply passed:\n%s", got)
	}
	sum := sha256.Sum256([]byte("true\nnotify --token abc"))
	want := protocol.Then{Pipeline: "site", Stage: "base", Step: 1, Module: "cmd", Main: hex.EncodeToString(sum[:])}
	if got := h.ThenOf("web1"); len(got) != 1 || got[0] != want {
		t.Errorf("then records = %+v, want %+v", got, want)
	}
}

// spec: Modules/cmd (unless); CLI/Output (a command of several lines)
func TestPlanShowsUnless(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - cmd:
          command: make install
          unless: test -x /usr/local/bin/app
      - cmd:
          command: app migrate
          unless: |
            app status
            app check
      - cmd:
          command: apt-get clean
          unless: "true"
`,
	}
	h := fakehost.New()
	h.FailCommand("web1", "test -x /usr/local/bin/app")
	h.FailCommand("web1", "app status\napp check\n")
	plan := run.MakePlan(context.Background(), loadFiles(t, files), h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	want := "    ~ cmd make install\n        unless: test -x /usr/local/bin/app\n" +
		"    ~ cmd app migrate\n        unless:\n          app status\n          app check\n\n" +
		"1 host: 1 to change, 0 unchanged, 0 unknown\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("the plan has no %q:\n%s%s", want, out.String(), errOut.String())
	}
}
