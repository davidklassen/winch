package run_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

// sum is the record key of a then command.
func sum(command string) string {
	b := sha256.Sum256([]byte(command))
	return hex.EncodeToString(b[:])
}

var handlerFiles = map[string]string{
	"winch.yaml": "name: acme\ninventory: inventories/test.yaml\n",
	"inventories/test.yaml": `hosts:
  web1: {}
  web2:
    vars:
      app_on: false
`,
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - recipe: nginx
      - recipe: site
  - name: apps
    hosts: all
    steps:
      - recipe: app
        when: !expr vars.app_on
`,
	"recipes/nginx/recipe.yaml": `steps:
  - file:
      path: /etc/nginx/a.conf
      content: "a\n"
    notify: reload
  - file:
      path: /etc/nginx/b.conf
      content: "b\n"
    notify: reload
  - file:
      path: /etc/nginx/c.conf
      content: "c\n"
    notify: [reload, restart]
handlers:
  restart:
    - service:
        name: nginx
        restarted: true
  reload:
    - service:
        name: nginx
        reloaded: true
`,
	"recipes/site/recipe.yaml": `vars:
  site_pages: [index, about]
steps:
  - file:
      path: !tpl /var/www/{{ .item }}.html
      content: "hi\n"
    loop: !expr vars.site_pages
    then: reindex
    notify: [nginx.reload, app.restart]
`,
	"recipes/app/recipe.yaml": `vars:
  app_on: true
steps:
  - file:
      path: /etc/app.conf
      content: "app\n"
    notify: restart
handlers:
  restart:
    - service:
        name: app
        restarted: true
`,
}

var handlerPaths = map[string]string{
	"/etc/nginx/a.conf":   "a\n",
	"/etc/nginx/b.conf":   "b\n",
	"/etc/nginx/c.conf":   "c\n",
	"/var/www/index.html": "hi\n",
	"/var/www/about.html": "hi\n",
	"/etc/app.conf":       "app\n",
}

// present writes every file of the handler project on hosts, so its steps
// check as ok.
func present(h *fakehost.Hosts, hosts ...string) {
	for _, host := range hosts {
		for p, c := range handlerPaths {
			h.SetFile(host, p, c)
		}
	}
}

func handlerProject(t *testing.T, set ...string) *project.Project {
	t.Helper()
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, handlerFiles), "", "site", set, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func output(out, errOut *bytes.Buffer) []byte {
	return []byte("stdout:\n" + out.String() + "stderr:\n" + errOut.String())
}

// applyOutput is output of apply with the lines of each host together. The
// hosts of a stage run at the same time, so only the order of the lines of
// one host is fixed.
func applyOutput(out, errOut *bytes.Buffer) []byte {
	return []byte("stdout:\n" + byHost(out.String()) + "stderr:\n" + byHost(errOut.String()))
}

// byHost sorts the lines before the first blank line by their host, and
// keeps the order of the lines of each host.
func byHost(s string) string {
	body, rest, blank := strings.Cut(s, "\n\n")
	if !blank {
		body, rest = strings.TrimSuffix(s, "\n"), ""
	}
	if body == "" {
		return s
	}
	lines := strings.Split(body, "\n")
	slices.SortStableFunc(lines, func(a, b string) int {
		ha, _, _ := strings.Cut(a, ": ")
		hb, _, _ := strings.Cut(b, ": ")
		return strings.Compare(ha, hb)
	})
	if !blank {
		return strings.Join(lines, "\n") + "\n"
	}
	return strings.Join(lines, "\n") + "\n\n" + rest
}

// spec: Handlers; Running a pipeline/Plan; CLI/Output
func TestPlanHandlers(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *fakehost.Hosts)
	}{
		{name: "fresh"},
		{name: "pending", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetPending("web1", "nginx.reload")
		}},
		{name: "pending-recipe-does-not-run", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetPending("web2", "app.restart")
		}},
		{name: "unchanged", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
		}},
		{name: "end-of-stage-only", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetFile("web1", "/var/www/about.html", "old\n")
		}},
		{name: "then-first-element", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetFile("web1", "/var/www/index.html", "old\n")
		}},
		{name: "then-ok-after-change", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetFile("web1", "/etc/nginx/c.conf", "old\n")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			plan := run.MakePlan(context.Background(), handlerProject(t), h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			plan.Write(&out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "handlers", "plan-"+tt.name+".golden"), output(&out, &errOut))
		})
	}
}

func applyAll(t *testing.T, p *project.Project, h *fakehost.Hosts) (bool, []byte) {
	t.Helper()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	ok := run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK()
	return ok, applyOutput(&out, &errOut)
}

// spec: Handlers; Steps; Running a pipeline/Apply; CLI/Output
func TestApplyHandlers(t *testing.T) {
	h := fakehost.New()
	p := handlerProject(t)
	ok, got := applyAll(t, p, h)
	if !ok {
		t.Fatalf("apply failed:\n%s", got)
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-fresh.golden"), got)
	// Three changed files run each handler of nginx once after nginx. The
	// site's change reloads nginx again at the end of the stage.
	want := map[string][]string{
		"web1": {"nginx restart", "nginx reload", "command reindex", "nginx reload", "app restart"},
		"web2": {"nginx restart", "nginx reload", "command reindex", "nginx reload"},
	}
	for host, w := range want {
		if !slices.Equal(h.Log[host], w) {
			t.Errorf("%s ran %q, want %q", host, h.Log[host], w)
		}
		if p := h.PendingOf(host); len(p) != 0 {
			t.Errorf("%s has pending handlers %v after the run", host, p)
		}
		if th := h.ThenOf(host); len(th) != 0 {
			t.Errorf("%s has then records %v after the run", host, th)
		}
	}
	if plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); plan.HasChanges() {
		t.Error("a second plan has changes")
	}
}

// spec: Handlers; Running a pipeline/Apply
func TestHandlerFollowsApply(t *testing.T) {
	t.Run("change in the plan, ok in apply", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/etc/nginx/a.conf", "old\n")
		p := handlerProject(t)
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		h.SetFile("web1", "/etc/nginx/a.conf", "a\n")
		var out, errOut bytes.Buffer
		if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
			t.Fatal(errOut.String())
		}
		if len(h.Log["web1"]) != 0 {
			t.Errorf("web1 ran %q, want nothing", h.Log["web1"])
		}
	})
	t.Run("ok in the plan, change in apply", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/etc/nginx/a.conf", "old\n")
		p := handlerProject(t)
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		h.SetFile("web1", "/etc/nginx/a.conf", "a\n")
		h.SetFile("web1", "/etc/nginx/c.conf", "old\n")
		var out, errOut bytes.Buffer
		if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
			t.Fatal(errOut.String())
		}
		if want := []string{"nginx restart", "nginx reload"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
	})
}

// spec: Handlers; Running a pipeline/Failures
func TestFailedHandlerStaysPending(t *testing.T) {
	h := fakehost.New()
	present(h, "web2")
	h.FailApply("web1 nginx")
	p := handlerProject(t)
	ok, got := applyAll(t, p, h)
	if ok {
		t.Fatal("apply succeeded with a failing handler")
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-handler-fails.golden"), got)
	if got, want := h.PendingOf("web1"), []string{"nginx.reload", "nginx.restart"}; !slices.Equal(got, want) {
		t.Fatalf("pending = %v, want %v", got, want)
	}

	h.Fix("web1 nginx")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-after-failed-handler.golden"), output(&out, &errOut))
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"nginx restart", "nginx reload", "command reindex", "nginx reload", "app restart"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if p := h.PendingOf("web1"); len(p) != 0 {
		t.Errorf("pending after the second run = %v", p)
	}
}

// spec: Handlers
func TestNotificationDropped(t *testing.T) {
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetFile("web2", "/var/www/index.html", "old\n")
	// The reload at the end of the stage fails, so the records stay.
	h.FailApply("web2 nginx")
	if ok, got := applyAll(t, handlerProject(t), h); ok {
		t.Fatalf("apply succeeded:\n%s", got)
	}
	if got, want := h.PendingOf("web2"), []string{"nginx.reload"}; !slices.Equal(got, want) {
		t.Errorf("pending on web2 = %v, want %v: app does not run there", got, want)
	}
}

// spec: Steps
func TestThen(t *testing.T) {
	t.Run("one element changes", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/var/www/about.html", "old\n")
		if ok, got := applyAll(t, handlerProject(t), h); !ok {
			t.Fatal(string(got))
		}
		if want := []string{"command reindex", "nginx reload", "app restart"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
	})
	t.Run("no element changes", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/etc/nginx/a.conf", "old\n")
		if ok, got := applyAll(t, handlerProject(t), h); !ok {
			t.Fatal(string(got))
		}
		if want := []string{"nginx reload"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
	})
	t.Run("then fails", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/var/www/index.html", "old\n")
		h.FailCommand("web1", "reindex")
		ok, got := applyAll(t, handlerProject(t), h)
		if ok {
			t.Fatal("apply succeeded with a failing then")
		}
		golden.Assert(t, filepath.Join("testdata", "handlers", "apply-then-fails.golden"), got)
		if want := []string{"command reindex"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
		if got, want := h.PendingOf("web1"), []string{"nginx.reload", "app.restart"}; !slices.Equal(got, want) {
			t.Errorf("pending = %v, want %v", got, want)
		}
	})
	t.Run("then fails, the next run runs it", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web2")
		h.SetFile("web1", "/etc/nginx/a.conf", "a\n")
		h.SetFile("web1", "/etc/nginx/b.conf", "b\n")
		h.SetFile("web1", "/etc/nginx/c.conf", "c\n")
		h.SetFile("web1", "/etc/app.conf", "app\n")
		h.FailCommand("web1", "reindex")
		p := handlerProject(t)
		if ok, got := applyAll(t, p, h); ok {
			t.Fatalf("apply succeeded with a failing then:\n%s", got)
		}
		// Both elements change, and one record stays.
		if got, want := h.ThenOf("web1"), []protocol.Then{{Recipe: "site", SHA256: sum("reindex")}}; !slices.Equal(got, want) {
			t.Fatalf("then records = %v, want %v", got, want)
		}
		h.Fix("web1 reindex")
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		var out, errOut bytes.Buffer
		plan.Write(&out, &errOut)
		golden.Assert(t, filepath.Join("testdata", "handlers", "plan-after-failed-then.golden"), output(&out, &errOut))
		if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
			t.Fatal(errOut.String())
		}
		if want := []string{"command reindex", "nginx reload", "command reindex", "app restart"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
		if got := h.ThenOf("web1"); len(got) != 0 {
			t.Errorf("then records after the second run = %v", got)
		}
		if plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); plan.HasChanges() {
			t.Error("a third plan has changes")
		}
	})
	t.Run("a later element fails", func(t *testing.T) {
		h := fakehost.New()
		h.FailApply("web1 /var/www/about.html")
		present(h, "web2")
		if ok, _ := applyAll(t, handlerProject(t), h); ok {
			t.Fatal("apply succeeded")
		}
		if slices.Contains(h.Log["web1"], "command reindex") {
			t.Error("then ran after a failed element")
		}
		if got, want := h.ThenOf("web1"), []protocol.Then{{Recipe: "site", SHA256: sum("reindex")}}; !slices.Equal(got, want) {
			t.Errorf("then records = %v, want %v", got, want)
		}
		got := h.PendingOf("web1")
		if !slices.Contains(got, "nginx.reload") || !slices.Contains(got, "app.restart") {
			t.Errorf("pending = %v, want the notifications of the first element", got)
		}
	})
	t.Run("empty loop", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/etc/nginx/a.conf", "old\n")
		h.FailCommand("web1", "reindex")
		if ok, got := applyAll(t, handlerProject(t, "vars.site_pages=[]"), h); !ok {
			t.Fatal(string(got))
		}
		if want := []string{"nginx reload"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
		if p := h.PendingOf("web1"); len(p) != 0 {
			t.Errorf("pending = %v, want none", p)
		}
	})
}

// spec: Handlers; Running a pipeline/Plan; Running a pipeline/Failures
func TestApplyPendingOnly(t *testing.T) {
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetPending("web1", "nginx.reload")
	h.SetFile("web2", "/etc/nginx/a.conf", "old\n")
	// app does not run on web2, so its record waits there.
	h.SetPending("web2", "app.restart")
	if ok, got := applyAll(t, handlerProject(t), h); !ok {
		t.Fatal(string(got))
	}
	if want := []string{"nginx reload"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if p := h.PendingOf("web1"); len(p) != 0 {
		t.Errorf("pending on web1 = %v, want none", p)
	}
	if got, want := h.PendingOf("web2"), []string{"app.restart"}; !slices.Equal(got, want) {
		t.Errorf("pending on web2 = %v, want %v", got, want)
	}
}

// spec: Handlers; CLI/Output
func TestStageStepNotifiesEarlierRecipe(t *testing.T) {
	files := maps.Clone(handlerFiles)
	files["pipelines/site.yaml"] += `      - file:
          path: /etc/motd
          content: "hi\n"
        notify: nginx.reload
`
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	present(h, "web1", "web2")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-stage-step.golden"), output(&out, &errOut))
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"nginx reload"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
}

// spec: Steps; Running a pipeline/Plan; CLI/Output
func TestPendingThen(t *testing.T) {
	files := maps.Clone(handlerFiles)
	files["pipelines/site.yaml"] += `      - file:
          path: /etc/motd
          content: "hi\n"
        then: newaliases
`
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetFile("web1", "/etc/motd", "hi\n")
	h.SetFile("web2", "/etc/motd", "hi\n")
	h.SetThen("web1", protocol.Then{Recipe: "site", SHA256: sum("reindex")}, protocol.Then{Stage: "apps", SHA256: sum("newaliases")})
	// No step matches these: another recipe, the stage of a recipe, another
	// command, a recipe named like the stage.
	other := []protocol.Then{
		{Recipe: "nginx", SHA256: sum("reindex")},
		{Stage: "web", SHA256: sum("reindex")},
		{Recipe: "site", SHA256: sum("other")},
		{Recipe: "apps", SHA256: sum("newaliases")},
	}
	h.SetThen("web2", other...)
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-pending-then.golden"), output(&out, &errOut))

	out.Reset()
	errOut.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-pending-then.golden"), output(&out, &errOut))
	if want := []string{"command reindex", "command newaliases"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if len(h.Log["web2"]) != 0 {
		t.Errorf("web2 ran %q, want nothing", h.Log["web2"])
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records on web1 = %v, want none", got)
	}
	if got := h.ThenOf("web2"); !slices.Equal(got, other) {
		t.Errorf("then records on web2 = %v, want %v", got, other)
	}
	if plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); plan.HasChanges() {
		t.Error("a second plan has changes")
	}
}

// spec: Steps; CLI/Output
func TestPendingThenOfAChangedStep(t *testing.T) {
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetFile("web1", "/var/www/about.html", "old\n")
	h.SetThen("web1", protocol.Then{Recipe: "site", SHA256: sum("reindex")})
	p := handlerProject(t)
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-pending-then-change.golden"), output(&out, &errOut))
	out.Reset()
	errOut.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-pending-then-change.golden"), output(&out, &errOut))
	if want := []string{"command reindex", "nginx reload", "app restart"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records = %v, want none", got)
	}
}

// spec: Steps; Handlers
func TestPendingThenOfAHandlerStep(t *testing.T) {
	files := maps.Clone(handlerFiles)
	files["recipes/app/recipe.yaml"] += "      then: app-check\n"
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetPending("web1", "app.restart")
	h.SetThen("web1", protocol.Then{Recipe: "app", SHA256: sum("app-check")})
	if ok, got := applyAll(t, p, h); !ok {
		t.Fatal(string(got))
	}
	if want := []string{"app restart", "command app-check"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records = %v, want none", got)
	}
	if got := h.PendingOf("web1"); len(got) != 0 {
		t.Errorf("pending handlers = %v, want none", got)
	}
}

// spec: CLI/Output; CLI/JSON output
func TestCommandLines(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    parallelism: 1
    health:
      command: |
        systemctl is-active nginx

        curl -sf http://localhost/
    steps:
      - file:
          path: /etc/aliases
          content: "a\n"
        then: |
          newaliases
          postmap /etc/postfix/virtual
`,
	}
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	then := "newaliases\npostmap /etc/postfix/virtual\n"
	h := fakehost.New()
	h.SetFile("web1", "/etc/aliases", "a\n")
	h.SetThen("web1", protocol.Then{Stage: "base", SHA256: sum(then)})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-command-lines.golden"), output(&out, &errOut))

	out.Reset()
	plan.WriteJSON(run.NewEvents(&out, func() time.Time { return time.Time{} }))
	if n := strings.Count(out.String(), `"then":"newaliases\npostmap /etc/postfix/virtual\n"`); n != 2 {
		t.Errorf("JSON has the then with its newlines %d times, want 2:\n%s", n, out.String())
	}
	if n := strings.Count(out.String(), `"health":"systemctl is-active nginx\n\ncurl -sf http://localhost/\n"`); n != 2 {
		t.Errorf("JSON has the health command with its newlines %d times, want 2:\n%s", n, out.String())
	}

	out.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-command-lines.golden"), output(&out, &errOut))

	h = fakehost.New()
	h.FailCommand("web1", "systemctl is-active nginx\n\ncurl -sf http://localhost/\n")
	plan = run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut))
	want := "base: failed: health:\n    systemctl is-active nginx\n\n    curl -sf http://localhost/\ndid not pass within 1m0s: exit status 1"
	if err := o.Failed["web1"]; err == nil || err.Error() != want {
		t.Errorf("web1: error %q, want %q", err, want)
	}
}

// spec: Steps; Handlers
func TestFailedStepKeepsEarlierRecordsOnly(t *testing.T) {
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetPending("web1", "app.restart")
	h.SetFile("web1", "/var/www/index.html", "old\n")
	h.FailApply("web1 /var/www/index.html")
	if ok, got := applyAll(t, handlerProject(t), h); ok {
		t.Fatalf("apply succeeded with a failing step\n%s", got)
	}
	if got, want := h.PendingOf("web1"), []string{"app.restart"}; !slices.Equal(got, want) {
		t.Errorf("pending = %v, want %v", got, want)
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records = %v, want none", got)
	}
}
