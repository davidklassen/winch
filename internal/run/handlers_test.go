package run_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

var handlerFiles = map[string]string{
	"winch.yaml": "name: acme\ninventory: test\n",
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

// plain writes to b without color, through a filter without secrets.
func plain(b *bytes.Buffer) *color.Writer {
	return color.NewWriter(b, secret.NewFilter().Parts, false)
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
			plan.Write(plain(&out), plain(&errOut))
			golden.Assert(t, filepath.Join("testdata", "handlers", "plan-"+tt.name+".golden"), output(&out, &errOut))
		})
	}
}

func applyAll(t *testing.T, p *project.Project, h *fakehost.Hosts) (bool, []byte) {
	t.Helper()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	ok := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK()
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
		"web1": {"nginx restart", "nginx reload", "command reindex", "nginx reload", "app restart", "access"},
		"web2": {"nginx restart", "nginx reload", "command reindex", "nginx reload", "access"},
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
		if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
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
		if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
			t.Fatal(errOut.String())
		}
		if want := []string{"nginx restart", "nginx reload", "access"}; !slices.Equal(h.Log["web1"], want) {
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
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-after-failed-handler.golden"), output(&out, &errOut))
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"nginx restart", "nginx reload", "command reindex", "nginx reload", "app restart", "access"}; !slices.Equal(h.Log["web1"], want) {
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
		if want := []string{"command reindex", "nginx reload", "app restart", "access"}; !slices.Equal(h.Log["web1"], want) {
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
		if want := []string{"nginx reload", "access"}; !slices.Equal(h.Log["web1"], want) {
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
		if got, want := h.ThenOf("web1"), []protocol.Then{{Recipe: "site", Module: "file", Mains: []string{"/var/www/index.html", "/var/www/about.html"}}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("then records = %v, want %v", got, want)
		}
		h.Fix("web1 reindex")
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		var out, errOut bytes.Buffer
		plan.Write(plain(&out), plain(&errOut))
		golden.Assert(t, filepath.Join("testdata", "handlers", "plan-after-failed-then.golden"), output(&out, &errOut))
		if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
			t.Fatal(errOut.String())
		}
		if want := []string{"command reindex", "nginx reload", "command reindex", "app restart", "access"}; !slices.Equal(h.Log["web1"], want) {
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
		if got, want := h.ThenOf("web1"), []protocol.Then{{Recipe: "site", Module: "file", Mains: []string{"/var/www/index.html", "/var/www/about.html"}}}; !reflect.DeepEqual(got, want) {
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
		if want := []string{"nginx reload", "access"}; !slices.Equal(h.Log["web1"], want) {
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
	if want := []string{"nginx reload", "access"}; !slices.Equal(h.Log["web1"], want) {
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
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-stage-step.golden"), output(&out, &errOut))
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"nginx reload", "access"}; !slices.Equal(h.Log["web1"], want) {
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
	h.SetThen("web1", protocol.Then{Recipe: "site", Module: "file", Mains: []string{"/var/www/about.html"}}, protocol.Then{Pipeline: "site", Stage: "apps", Module: "file", Mains: []string{"/etc/motd"}})
	// No step matches these records: a step without then, another stage, a
	// handler that the recipe does not have, another module, and another main
	// argument.
	gone := []protocol.Then{
		{Recipe: "nginx", Module: "file", Mains: []string{"/etc/nginx/a.conf"}},
		{Pipeline: "site", Stage: "web", Module: "file", Mains: []string{"/etc/motd"}},
		{Recipe: "site", Handler: "restart", Module: "file", Mains: []string{"/etc/motd"}},
		{Recipe: "site", Module: "dir", Mains: []string{"/var/www/about.html"}},
		{Pipeline: "site", Stage: "apps", Module: "file", Mains: []string{"/etc/issue"}},
	}
	// The plan does not check these scopes on web2: a recipe that the project
	// does not have, a recipe whose when is false, and another pipeline.
	kept := []protocol.Then{
		{Recipe: "apps", Module: "file", Mains: []string{"/etc/motd"}},
		{Recipe: "app", Module: "file", Mains: []string{"/etc/app.conf"}},
		{Pipeline: "deploy", Stage: "apps", Module: "file", Mains: []string{"/etc/motd"}},
	}
	h.SetThen("web2", slices.Concat(gone, kept)...)
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-pending-then.golden"), output(&out, &errOut))

	out.Reset()
	errOut.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-pending-then.golden"), output(&out, &errOut))
	if want := []string{"command reindex", "command newaliases", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if len(h.Log["web2"]) != 0 {
		t.Errorf("web2 ran %q, want nothing", h.Log["web2"])
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records on web1 = %v, want none", got)
	}
	// Apply removes the gone records on web2, which has no change.
	if got := h.ThenOf("web2"); !reflect.DeepEqual(got, kept) {
		t.Errorf("then records on web2 = %v, want %v", got, kept)
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
	h.SetThen("web1", protocol.Then{Recipe: "site", Module: "file", Mains: []string{"/var/www/about.html"}})
	p := handlerProject(t)
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-pending-then-change.golden"), output(&out, &errOut))
	out.Reset()
	errOut.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-pending-then-change.golden"), output(&out, &errOut))
	if want := []string{"command reindex", "nginx reload", "app restart", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records = %v, want none", got)
	}
}

// spec: Steps; Handlers
func TestPendingThenOfAHandlerStep(t *testing.T) {
	files := maps.Clone(handlerFiles)
	files["recipes/app/recipe.yaml"] += "      loop: [1, 2]\n      then: |\n        app-check\n        app-log\n"
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetPending("web1", "app.restart")
	h.SetThen("web1", protocol.Then{Recipe: "app", Handler: "restart", Module: "service", Mains: []string{"app"}})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	out.WriteString("json:\n")
	plan.WriteJSON(run.NewEvents(plain(&out), func() time.Time { return time.Time{} }))
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-pending-then-handler.golden"), output(&out, &errOut))

	out.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-pending-then-handler.golden"), output(&out, &errOut))
	if want := []string{"app restart", "app restart", "command app-check\napp-log\n", "access"}; !slices.Equal(h.Log["web1"], want) {
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
		"winch.yaml":            "name: acme\ninventory: test\n",
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
	h := fakehost.New()
	h.SetFile("web1", "/etc/aliases", "a\n")
	h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "base", Module: "file", Mains: []string{"/etc/aliases"}})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-command-lines.golden"), output(&out, &errOut))

	out.Reset()
	plan.WriteJSON(run.NewEvents(plain(&out), func() time.Time { return time.Time{} }))
	if n := strings.Count(out.String(), `"then":"newaliases\npostmap /etc/postfix/virtual\n"`); n != 2 {
		t.Errorf("JSON has the then with its newlines %d times, want 2:\n%s", n, out.String())
	}
	if n := strings.Count(out.String(), `"health":"systemctl is-active nginx\n\ncurl -sf http://localhost/\n"`); n != 2 {
		t.Errorf("JSON has the health command with its newlines %d times, want 2:\n%s", n, out.String())
	}

	out.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-command-lines.golden"), output(&out, &errOut))

	h = fakehost.New()
	h.FailCommand("web1", "systemctl is-active nginx\n\ncurl -sf http://localhost/\n")
	plan = run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	want := "base: failed: health:\n    systemctl is-active nginx\n\n    curl -sf http://localhost/\ndid not pass within 60s: exit status 1"
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

// spec: Steps
func TestFixedThenRuns(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: mail
    hosts: all
    steps:
      - file:
          path: /etc/postfix/virtual
          content: "a\n"
        then: postmapp /etc/postfix/virtual
`,
	}
	h := fakehost.New()
	h.FailCommand("web1", "postmapp /etc/postfix/virtual")
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, got := applyAll(t, p, h); ok {
		t.Fatalf("apply succeeded with a failing then:\n%s", got)
	}

	files["pipelines/site.yaml"] = strings.Replace(files["pipelines/site.yaml"], "postmapp", "postmap", 1)
	if p, err = project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{}); err != nil {
		t.Fatal(err)
	}
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if want := "! then: postmap /etc/postfix/virtual\n"; !strings.Contains(out.String(), want) {
		t.Errorf("plan does not show %q:\n%s", want, out.String())
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"command postmapp /etc/postfix/virtual", "command postmap /etc/postfix/virtual", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records = %v, want none", got)
	}
}

func TestInsertedStepKeepsPendingThen(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: mail
    hosts: all
    steps:
      - file:
          path: /etc/postfix/virtual
          content: "a\n"
        then: postmap /etc/postfix/virtual
`,
	}
	h := fakehost.New()
	h.FailCommand("web1", "postmap /etc/postfix/virtual")
	h.SetFile("web1", "/etc/db.conf", "db\n")
	p := loadFiles(t, files)
	if ok, got := applyAll(t, p, h); ok {
		t.Fatalf("apply succeeded with a failing then:\n%s", got)
	}

	files["pipelines/site.yaml"] = strings.Replace(files["pipelines/site.yaml"], "    steps:\n", `    steps:
      - file:
          path: /etc/db.conf
          content: "db\n"
        then: systemctl restart db
`, 1)
	p = loadFiles(t, files)
	h.Fix("web1 postmap /etc/postfix/virtual")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if !strings.Contains(out.String(), "! then: postmap /etc/postfix/virtual") {
		t.Errorf("plan does not show the pending then:\n%s", out.String())
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"command postmap /etc/postfix/virtual", "command postmap /etc/postfix/virtual", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records = %v, want none", got)
	}
}

// spec: Modules/download; Handlers; Steps
func TestDownloadOKNotifiesNothing(t *testing.T) {
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: tools\n    hosts: all\n    steps:\n      - recipe: tool\n",
		"recipes/tool/recipe.yaml": `steps:
  - download:
      url: https://example.com/tool
      sha256: ` + strings.Repeat("a", 64) + `
      path: /opt/tool
    then: tool --setup
    notify: restart
handlers:
  restart:
    - service:
        name: tool
        restarted: true
`,
	}
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetResult("web1", "/opt/tool", module.Result{Status: module.OK})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if s := out.String(); strings.Contains(s, "handler") || strings.Contains(s, "then:") {
		t.Errorf("plan:\n%s\nwant no handler or then", s)
	}
	ok, got := applyAll(t, p, h)
	if !ok {
		t.Fatalf("apply failed:\n%s", got)
	}
	if len(h.Log["web1"]) != 0 || len(h.PendingOf("web1")) != 0 || len(h.ThenOf("web1")) != 0 {
		t.Errorf("apply ran %q, pending %q, then records %v; want nothing", h.Log["web1"], h.PendingOf("web1"), h.ThenOf("web1"))
	}
}

var stageHandlerFiles = map[string]string{
	"winch.yaml":            "name: acme\ninventory: test\n",
	"inventories/test.yaml": "hosts:\n  web1: {}\n",
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    health:
      command: healthy
    steps:
      - file:
          path: /etc/app/a.conf
          content: "a\n"
        notify: [reload, restart]
      - file:
          path: /etc/app/b.conf
          content: "b\n"
        notify: reload
      - file:
          path: /etc/app/c.conf
          content: "c\n"
    handlers:
      restart:
        - service:
            name: app
            restarted: true
      reload:
        - service:
            name: app
            reloaded: true
          confirm_access: true
          then: app-check
  - name: other
    hosts: all
    steps:
      - file:
          path: /etc/other.conf
          content: "o\n"
        notify: reload
    handlers:
      reload:
        - cmd:
            command: other-reload
`,
}

// spec: Pipelines; Handlers; Running a pipeline/Health gates; Running a
// pipeline/Lockout protection
func TestStageHandlers(t *testing.T) {
	p := loadFiles(t, stageHandlerFiles)
	h := fakehost.New()
	// A record of a stage of another pipeline stays.
	h.SetPending("web1", "deploy\tweb\treload")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	for _, want := range []string{"  web\n", "    ! handler web.restart\n    ! handler web.reload\n    * health: healthy\n", "  other\n", "    ! handler other.reload\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("plan does not show %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "handlers", "apply-stage-handlers.golden"), output(&out, &errOut))
	// Two changed steps notify reload: it runs once, in declared order.
	if want := []string{"app restart", "app reload", "access", "confirm", "command app-check", "cmd other-reload", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	// The last apply of the service app is the reload.
	reload := -1
	for i, e := range h.Trace {
		if e == "apply web1 app" {
			reload = i
		}
	}
	health := slices.IndexFunc(h.Trace, func(s string) bool { return strings.HasPrefix(s, "health web1 healthy ") })
	if reload < 0 || health < reload {
		t.Errorf("trace %q: the health gate runs before the handler", h.Trace)
	}
	if got, want := h.PendingOf("web1"), []string{"deploy\tweb\treload"}; !slices.Equal(got, want) {
		t.Errorf("pending = %q, want %q", got, want)
	}
	guards := map[string]protocol.Guard{
		"web1 /etc/app/a.conf": {Pipeline: "site", Stage: "web", Save: true, Handlers: []string{"site\tweb\treload"}},
		"web1 app":             {Pipeline: "site", Stage: "web", Save: true, Confirm: true},
		"web1 /etc/other.conf": {Pipeline: "site", Stage: "other"},
		"web1 other-reload":    {Pipeline: "site", Stage: "other"},
	}
	for k, g := range guards {
		if !reflect.DeepEqual(h.Guards[k], g) {
			t.Errorf("guard of %s = %+v, want %+v", k, h.Guards[k], g)
		}
	}
	if plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); plan.HasChanges() {
		t.Error("a second plan has changes")
	}
}

// spec: Handlers; Running a pipeline/Failures
func TestStageHandlerStaysPending(t *testing.T) {
	p := loadFiles(t, stageHandlerFiles)
	h := fakehost.New()
	for _, f := range []string{"a", "b", "c"} {
		h.SetFile("web1", "/etc/app/"+f+".conf", f+"\n")
	}
	h.FailCommand("web1", "other-reload")
	if ok, got := applyAll(t, p, h); ok {
		t.Fatalf("apply succeeded with a failing handler:\n%s", got)
	}
	if got, want := h.PendingOf("web1"), []string{"site\tother\treload"}; !slices.Equal(got, want) {
		t.Fatalf("pending = %q, want %q", got, want)
	}

	h.Fix("web1 other-reload")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if want := "web1\n  other\n    ! handler other.reload\n\n"; !strings.HasPrefix(out.String(), want) {
		t.Errorf("plan:\n%s\nwant it to start with\n%s", out.String(), want)
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"cmd other-reload", "cmd other-reload", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.PendingOf("web1"); len(got) != 0 {
		t.Errorf("pending after the second run = %q", got)
	}
}

var stageHandlerVarFiles = map[string]string{
	"winch.yaml":            "name: acme\ninventory: test\nvars:\n  svc: !expr 'upper(host.name)'\n",
	"inventories/test.yaml": "hosts:\n  web1: {}\n",
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - file:
          path: /etc/a
          content: "a\n"
        notify: reload
    handlers:
      reload:
        - cmd:
            command: !expr '"reload " + vars.svc'
          then: reindex
  - name: db
    hosts: all
    steps:
      - file:
          path: /etc/b
          content: "b\n"
`,
}

// spec: Pipelines; Handlers; Steps (the place of a then)
func TestStageHandlerStep(t *testing.T) {
	p := loadFiles(t, stageHandlerVarFiles)
	h := fakehost.New()
	h.FailCommand("web1", "reindex")
	if ok, got := applyAll(t, p, h); ok {
		t.Fatalf("apply succeeded with a failing then:\n%s", got)
	}
	if want := []string{"cmd reload WEB1", "command reindex"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	th := h.ThenOf("web1")
	if len(th) != 1 || th[0].Pipeline != "site" || th[0].Stage != "web" || th[0].Handler != "reload" || th[0].Module != "cmd" || th[0].Recipe != "" {
		t.Errorf("then records = %+v, want one of the cmd of handler reload of stage web of pipeline site", th)
	}
}

// spec: Handlers (a pending handler of a stage that --stages leaves out
// stays recorded and does not show in the plan)
func TestStageHandlerOfASkippedStage(t *testing.T) {
	p := loadFiles(t, stageHandlerVarFiles)
	if err := p.Select(project.Selection{Stages: "db"}); err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetPending("web1", "site\tweb\treload")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if strings.Contains(out.String(), "handler") {
		t.Errorf("plan shows the handler of a skipped stage:\n%s", out.String())
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"site\tweb\treload"}; !slices.Equal(h.PendingOf("web1"), want) {
		t.Errorf("pending = %q, want %q", h.PendingOf("web1"), want)
	}
	if want := []string{"access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
}

// spec: Steps
func TestPendingThenWithoutItsStep(t *testing.T) {
	files := maps.Clone(handlerFiles)
	files["recipes/site/recipe.yaml"] = `steps:
  - file:
      path: !tpl /var/www/{{ .item }}.html
      content: "hi\n"
    loop: [index]
    then: reindex
`
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
	// The loop lost its last element, and the aliases step is gone.
	h.SetThen("web1",
		protocol.Then{Pipeline: "site", Stage: "apps", Module: "file", Mains: []string{"/etc/motd"}},
		protocol.Then{Recipe: "site", Module: "file", Mains: []string{"/var/www/index.html", "/var/www/about.html"}},
		protocol.Then{Pipeline: "site", Stage: "apps", Module: "file", Mains: []string{"/etc/aliases"}},
	)
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if want := "web1: note: a pending then of file /etc/aliases matches no step and will not run\n"; errOut.String() != want {
		t.Errorf("plan notes %q, want %q", errOut.String(), want)
	}
	if !strings.Contains(out.String(), "! then: newaliases") || !strings.Contains(out.String(), "! then: reindex") {
		t.Errorf("the plan does not run the moved then records:\n%s", out.String())
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"command reindex", "command newaliases", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ThenOf("web1"); len(got) != 0 {
		t.Errorf("then records after apply = %v, want none", got)
	}
}

// spec: Steps
func TestGoneThenScopes(t *testing.T) {
	files := maps.Clone(handlerFiles)
	files["inventories/test.yaml"] = "hosts:\n  web1: {}\n  web2: {}\ngroups:\n  db:\n    hosts: [web2]\n"
	files["recipes/app/recipe.yaml"] += "      then: app-check\n"
	files["pipelines/site.yaml"] += `  - name: db
    hosts: db
    steps:
      - file:
          path: /etc/db.conf
          content: "db\n"
        then: db-reload
`
	records := []protocol.Then{
		{Pipeline: "site", Stage: "old", Module: "file", Mains: []string{"/etc/old"}},
		{Pipeline: "site", Stage: "db", Module: "file", Mains: []string{"/etc/gone"}},
		{Pipeline: "site", Stage: "apps", Module: "file", Mains: []string{"/etc/apps"}},
		{Recipe: "app", Handler: "restart", Module: "service", Mains: []string{"app"}},
		{Recipe: "nginx", Module: "file", Mains: []string{"/etc/nginx/gone.conf"}},
	}
	for _, tc := range []struct {
		name   string
		stages string
		want   string
	}{
		// A stage that the pipeline no longer has gives the note; a stage
		// without the host, and a handler that does not run, do not.
		{name: "all stages", want: "web1: note: a pending then of file /etc/old matches no step and will not run\n" +
			"web1: note: a pending then of file /etc/apps matches no step and will not run\n" +
			"web1: note: a pending then of file /etc/nginx/gone.conf matches no step and will not run\n"},
		// A skipped stage gives no note, and its recipe app does not run.
		{name: "a skipped stage", stages: "web", want: "web1: note: a pending then of file /etc/old matches no step and will not run\n" +
			"web1: note: a pending then of file /etc/nginx/gone.conf matches no step and will not run\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := loadFiles(t, files)
			if tc.stages != "" {
				if err := p.Select(project.Selection{Stages: tc.stages}); err != nil {
					t.Fatal(err)
				}
			}
			h := fakehost.New()
			present(h, "web1", "web2")
			h.SetFile("web1", "/etc/nginx/a.conf", "changed\n")
			h.SetThen("web1", records...)
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			var errOut bytes.Buffer
			plan.WriteNotes(plain(&errOut))
			if errOut.String() != tc.want {
				t.Errorf("notes:\n%s\nwant:\n%s", errOut.String(), tc.want)
			}
		})
	}
}

// spec: Steps; Modules/assert; Running a pipeline/Health gates; Running a pipeline/Apply
func TestGoneRecordWithoutChange(t *testing.T) {
	files := map[string]string{
		"winch.yaml":              "name: acme\ninventory: test\n",
		"inventories/test.yaml":   "hosts:\n  web1: {}\n  web2: {}\n",
		"pipelines/site.yaml":     "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: \"hi\\n\"\n      - recipe: app\n",
		"recipes/app/recipe.yaml": "steps:\n  - file:\n      path: /etc/app.conf\n      content: \"app\\n\"\n",
	}
	then := protocol.Then{Pipeline: "site", Stage: "base", Module: "file", Mains: []string{"/etc/aliases"}}
	pend := func(c protocol.Check) func(*fakehost.Hosts) { return func(h *fakehost.Hosts) { h.Pend("web1", c) } }
	for _, tc := range []struct {
		name   string
		record func(*fakehost.Hosts)
		note   string
	}{
		{"then", func(h *fakehost.Hosts) { h.SetThen("web1", then) }, "a pending then of file /etc/aliases matches no step"},
		{"gate", pend(protocol.Check{Pipeline: "site", Stage: "base"}), "a pending health gate of stage base matches no gate"},
		{"assert", pend(protocol.Check{Pipeline: "site", Stage: "base", Step: 3}), "a pending assert of stage base step 3 matches no assert"},
		{"recipe assert", pend(protocol.Check{Recipe: "app", Step: 2}), "a pending assert of recipe app step 2 matches no assert"},
		{"handler assert", pend(protocol.Check{Recipe: "app", Handler: "check", Step: 1}), "a pending assert of handler app.check step 1 matches no assert"},
		{"stage handler assert", pend(protocol.Check{Pipeline: "site", Stage: "base", Handler: "check", Step: 1}), "a pending assert of handler base.check step 1 matches no assert"},
		{"unprintable stage", pend(protocol.Check{Pipeline: "site", Stage: "x\x1b[2J"}), "a pending health gate of stage x?[2J matches no gate"},
	} {
		for _, other := range []bool{false, true} {
			name := tc.name + " alone"
			if other {
				name = tc.name + " next to a change"
			}
			t.Run(name, func(t *testing.T) {
				p := loadFiles(t, files)
				h := fakehost.New()
				h.SetFile("web1", "/etc/motd", "hi\n")
				h.SetFile("web1", "/etc/app.conf", "app\n")
				h.SetFile("web2", "/etc/app.conf", "app\n")
				if !other {
					h.SetFile("web2", "/etc/motd", "hi\n")
				}
				tc.record(h)
				plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
				var out, errOut bytes.Buffer
				plan.Write(plain(&out), plain(&errOut))
				if want := "web1: note: " + tc.note + " and will not run\n"; errOut.String() != want {
					t.Errorf("plan notes %q, want %q", errOut.String(), want)
				}
				want := "2 hosts: 0 to change, 2 unchanged, 0 unknown\n"
				if other {
					want = "2 hosts: 1 to change, 1 unchanged, 0 unknown\n"
				}
				if !strings.Contains(out.String(), want) {
					t.Errorf("the plan has no %q:\n%s", want, out.String())
				}
				// A change after the plan shows whether apply runs the steps of web1.
				h.SetFile("web1", "/etc/motd", "drift\n")
				o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
				if !o.OK() || o.Changed["web1"] {
					t.Fatalf("apply failed or changed web1: %v\n%s", o.Failed, errOut.String())
				}
				if c, _ := h.File("web1", "/etc/motd"); c != "drift\n" {
					t.Errorf("apply ran the steps of web1: /etc/motd = %q", c)
				}
				h.SetFile("web1", "/etc/motd", "hi\n")
				if len(h.ThenOf("web1")) != 0 || len(h.ChecksOf("web1")) != 0 {
					t.Errorf("records stay: %v %v", h.ThenOf("web1"), h.ChecksOf("web1"))
				}
				if len(h.Log["web1"]) != 0 {
					t.Errorf("web1 ran %q, want nothing", h.Log["web1"])
				}
				next := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
				errOut.Reset()
				next.WriteNotes(plain(&errOut))
				if errOut.Len() != 0 || next.HasChanges() {
					t.Errorf("the next plan has notes %q or changes", errOut.String())
				}
			})
		}
	}
}

// spec: Steps; Running a pipeline/Failures
func TestGoneRecordOfFailedHostStays(t *testing.T) {
	p := loadFiles(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: \"hi\\n\"\n",
	})
	h := fakehost.New()
	h.SetFile("web1", "/etc/motd", "hi\n")
	h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "base", Module: "file", Mains: []string{"/etc/aliases"}})
	h.FailCheck("web1 /etc/motd")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	if plan.Failed["web1"] == nil {
		t.Fatal("the check of web1 did not fail")
	}
	connects := h.Connects["web1"]
	var out, errOut bytes.Buffer
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if h.Connects["web1"] != connects || len(h.ThenOf("web1")) != 1 {
		t.Errorf("apply connected to web1 %d times, records %v", h.Connects["web1"]-connects, h.ThenOf("web1"))
	}
	if c, _ := h.File("web2", "/etc/motd"); c != "hi\n" || !o.Changed["web2"] || o.Failed["web2"] != nil {
		t.Errorf("web2: /etc/motd %q, changed %v, error %v", c, o.Changed["web2"], o.Failed["web2"])
	}
}

// spec: Running a pipeline/Apply (Ctrl-C)
func TestGoneRecordRemovalFails(t *testing.T) {
	p := loadFiles(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: \"hi\\n\"\n",
	})
	h := fakehost.New()
	h.SetFile("web1", "/etc/motd", "hi\n")
	h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "base", Module: "file", Mains: []string{"/etc/aliases"}})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	traced := len(h.Trace)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	o := run.Apply(ctx, plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if !errors.Is(o.Failed["web1"], run.ErrInterrupted) {
		t.Errorf("after an interrupt web1 failed with %v, want interrupted", o.Failed["web1"])
	}
	if len(h.ThenOf("web1")) != 1 || len(h.Trace) != traced {
		t.Errorf("apply started web1 after an interrupt: records %v, trace %q", h.ThenOf("web1"), h.Trace[traced:])
	}
	h.FailClose("web1")
	errOut.Reset()
	o = run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if o.Failed["web1"] == nil || !strings.Contains(errOut.String(), "the session ended without an error message (ssh: exit status 255)") {
		t.Errorf("apply did not fail web1: %v, stderr %q", o.Failed, errOut.String())
	}
}

// spec: Steps
func TestPendingThenOfTwoLineSteps(t *testing.T) {
	p := loadFiles(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: ssh
    hosts: all
    steps:
      - line:
          path: /etc/ssh/sshd_config
          line: PermitRootLogin no
          match: ^PermitRootLogin
        then: sshd -t
      - line:
          path: /etc/ssh/sshd_config
          line: Port 22
          match: ^Port
        then: sshd -t
`,
	})
	h := fakehost.New()
	h.SetFile("web1", "/etc/ssh/sshd_config", "PermitRootLogin no\nPort 22\n")
	h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "ssh", Module: "line", Mains: []string{"/etc/ssh/sshd_config"}})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	// Apply runs the pending then once, so the plan shows it once.
	if n := strings.Count(out.String(), "! then: sshd -t"); n != 1 {
		t.Errorf("the plan shows the pending then %d times, want once:\n%s", n, out.String())
	}
}
