package run_test

import (
	"bytes"
	"context"
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

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
	p, err := project.Load(vmtest.WriteProject(t, handlerFiles), "", "site", set)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func output(out, errOut *bytes.Buffer) []byte {
	return []byte("stdout:\n" + out.String() + "stderr:\n" + errOut.String())
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			plan := run.MakePlan(context.Background(), handlerProject(t), h.Connector())
			var out, errOut bytes.Buffer
			plan.Write(&out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "handlers", "plan-"+tt.name+".golden"), output(&out, &errOut))
		})
	}
}

func applyAll(t *testing.T, p *project.Project, h *fakehost.Hosts) (bool, []byte) {
	t.Helper()
	plan := run.MakePlan(context.Background(), p, h.Connector())
	var out, errOut bytes.Buffer
	ok := run.Apply(context.Background(), plan, h.Connector(), &out, &errOut)
	return ok, output(&out, &errOut)
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
	}
	if plan := run.MakePlan(context.Background(), p, h.Connector()); plan.HasChanges() {
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
		plan := run.MakePlan(context.Background(), p, h.Connector())
		h.SetFile("web1", "/etc/nginx/a.conf", "a\n")
		var out, errOut bytes.Buffer
		if !run.Apply(context.Background(), plan, h.Connector(), &out, &errOut) {
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
		plan := run.MakePlan(context.Background(), p, h.Connector())
		h.SetFile("web1", "/etc/nginx/a.conf", "a\n")
		h.SetFile("web1", "/etc/nginx/c.conf", "old\n")
		var out, errOut bytes.Buffer
		if !run.Apply(context.Background(), plan, h.Connector(), &out, &errOut) {
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
	plan := run.MakePlan(context.Background(), p, h.Connector())
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-after-failed-handler.golden"), output(&out, &errOut))
	if !run.Apply(context.Background(), plan, h.Connector(), &out, &errOut) {
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
	p, err := project.Load(vmtest.WriteProject(t, files), "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	present(h, "web1", "web2")
	plan := run.MakePlan(context.Background(), p, h.Connector())
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "handlers", "plan-stage-step.golden"), output(&out, &errOut))
	if !run.Apply(context.Background(), plan, h.Connector(), &out, &errOut) {
		t.Fatal(errOut.String())
	}
	if want := []string{"nginx reload"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
}
