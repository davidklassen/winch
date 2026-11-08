package run_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

var reactFiles = map[string]string{
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
  - file:
      path: /etc/nginx/b.conf
      content: "b\n"
  - file:
      path: /etc/nginx/c.conf
      content: "c\n"
  - service:
      name: nginx
      restarted: true
    on_change: [/etc/nginx/c.conf]
  - service:
      name: nginx
      reloaded: true
    on_change: [/etc/nginx]
`,
	"recipes/site/recipe.yaml": `vars:
  site_pages: [index, about]
steps:
  - file:
      path: !tpl /var/www/{{ item }}.html
      content: "hi\n"
    loop: !expr vars.site_pages
    then: reindex
`,
	"recipes/app/recipe.yaml": `vars:
  app_on: true
steps:
  - file:
      path: /etc/app.conf
      content: "app\n"
  - service:
      name: app
      restarted: true
    on_change: [/etc/app.conf, /var/www]
`,
}

var reactPaths = map[string]string{
	"/etc/nginx/a.conf":   "a\n",
	"/etc/nginx/b.conf":   "b\n",
	"/etc/nginx/c.conf":   "c\n",
	"/var/www/index.html": "hi\n",
	"/var/www/about.html": "hi\n",
	"/etc/app.conf":       "app\n",
}

// present writes every file of the reactions project on hosts, so its steps
// check as ok.
func present(h *fakehost.Hosts, hosts ...string) {
	for _, host := range hosts {
		for p, c := range reactPaths {
			h.SetFile(host, p, c)
		}
	}
}

func reactProject(t *testing.T, set ...string) *project.Project {
	t.Helper()
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, reactFiles), "", "site", set, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func applyAll(t *testing.T, p *project.Project, h *fakehost.Hosts) (bool, []byte) {
	t.Helper()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	ok := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK()
	return ok, applyOutput(&out, &errOut)
}

// mains are the main arguments of a record for the main arguments args.
func mains(args ...string) []string {
	var hs []string
	for _, a := range args {
		h := sha256.Sum256([]byte(a))
		hs = append(hs, hex.EncodeToString(h[:]))
	}
	return hs
}

// The records of the steps of the reactions project.
var (
	nginxRestart = protocol.React{Recipe: "nginx", Module: "service", Mains: mains("nginx")}
	siteThen     = protocol.React{Recipe: "site", Module: "file", Mains: mains("/var/www/index.html", "/var/www/about.html"), Then: true}
	appRestart   = protocol.React{Recipe: "app", Module: "service", Mains: mains("app")}
)

// spec: Reactions; Running a pipeline/Plan; CLI/Output
func TestPlanReactions(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *fakehost.Hosts)
	}{
		{name: "fresh"},
		{name: "unchanged", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
		}},
		{name: "one-file", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetFile("web1", "/etc/nginx/a.conf", "old\n")
		}},
		{name: "pending", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetReact("web1", nginxRestart)
		}},
		{name: "pending-recipe-does-not-run", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetReact("web2", appRestart)
		}},
		{name: "then-first-element", setup: func(h *fakehost.Hosts) {
			present(h, "web1", "web2")
			h.SetFile("web1", "/var/www/index.html", "old\n")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			plan := run.MakePlan(context.Background(), reactProject(t), h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			plan.Write(plain(&out), plain(&errOut))
			golden.Assert(t, filepath.Join("testdata", "reactions", "plan-"+tt.name+".golden"), output(&out, &errOut))
		})
	}
}

// spec: Reactions; Running a pipeline/Apply; CLI/Output
func TestApplyReactions(t *testing.T) {
	h := fakehost.New()
	p := reactProject(t)
	ok, got := applyAll(t, p, h)
	if !ok {
		t.Fatalf("apply failed:\n%s", got)
	}
	golden.Assert(t, filepath.Join("testdata", "reactions", "apply-fresh.golden"), got)
	// The three files of nginx restart and reload nginx once. The pages of
	// the site restart app in the next stage.
	want := map[string][]string{
		"web1": {"nginx restart", "nginx reload", "command reindex", "app restart", "access"},
		"web2": {"nginx restart", "nginx reload", "command reindex", "access"},
	}
	for host, w := range want {
		if !slices.Equal(h.Log[host], w) {
			t.Errorf("%s ran %q, want %q", host, h.Log[host], w)
		}
		if r := h.ReactOf(host); len(r) != 0 {
			t.Errorf("%s has records %v after the run", host, r)
		}
	}
	if plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); plan.HasChanges() {
		t.Error("a second plan has changes")
	}
}

// spec: Reactions; Running a pipeline/Apply (the second check decides)
func TestReactionFollowsApply(t *testing.T) {
	t.Run("change in the plan, ok in apply", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/etc/nginx/a.conf", "old\n")
		plan := run.MakePlan(context.Background(), reactProject(t), h.Connector(), run.Options{})
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
		plan := run.MakePlan(context.Background(), reactProject(t), h.Connector(), run.Options{})
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

// spec: Reactions (a pending record after a failed run); Running a
// pipeline/Failures
func TestFailedReactionStaysPending(t *testing.T) {
	h := fakehost.New()
	present(h, "web2")
	h.FailApply("web1 nginx")
	p := reactProject(t)
	ok, got := applyAll(t, p, h)
	if ok {
		t.Fatal("apply succeeded with a failing restart")
	}
	golden.Assert(t, filepath.Join("testdata", "reactions", "apply-restart-fails.golden"), got)
	reload := protocol.React{Recipe: "nginx", Module: "service", Mains: mains("nginx")}
	if got, want := h.ReactOf("web1"), []protocol.React{reload}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}

	h.Fix("web1 nginx")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "reactions", "plan-after-failed-restart.golden"), output(&out, &errOut))
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	// The restart and the reload of nginx share one record: the first step
	// that matches it runs.
	if want := []string{"access", "nginx restart", "command reindex", "app restart", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if r := h.ReactOf("web1"); len(r) != 0 {
		t.Errorf("records after the second run = %v", r)
	}
}

// spec: Reactions (then)
func TestThen(t *testing.T) {
	t.Run("one element changes", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/var/www/about.html", "old\n")
		if ok, got := applyAll(t, reactProject(t), h); !ok {
			t.Fatal(string(got))
		}
		if want := []string{"command reindex", "app restart", "access"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
	})
	t.Run("no element changes", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/etc/nginx/a.conf", "old\n")
		if ok, got := applyAll(t, reactProject(t), h); !ok {
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
		ok, got := applyAll(t, reactProject(t), h)
		if ok {
			t.Fatal("apply succeeded with a failing then")
		}
		golden.Assert(t, filepath.Join("testdata", "reactions", "apply-then-fails.golden"), got)
		if want := []string{"command reindex", "access"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
		if got, want := h.ReactOf("web1"), []protocol.React{siteThen, appRestart}; !reflect.DeepEqual(got, want) {
			t.Errorf("records = %v, want %v", got, want)
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
		p := reactProject(t)
		if ok, got := applyAll(t, p, h); ok {
			t.Fatalf("apply succeeded with a failing then:\n%s", got)
		}
		// Both elements change, and one record stays.
		if got, want := h.ReactOf("web1"), []protocol.React{siteThen, appRestart}; !reflect.DeepEqual(got, want) {
			t.Fatalf("records = %v, want %v", got, want)
		}
		h.Fix("web1 reindex")
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		var out, errOut bytes.Buffer
		plan.Write(plain(&out), plain(&errOut))
		golden.Assert(t, filepath.Join("testdata", "reactions", "plan-after-failed-then.golden"), output(&out, &errOut))
		if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
			t.Fatal(errOut.String())
		}
		if want := []string{"command reindex", "access", "command reindex", "app restart", "access"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
		if got := h.ReactOf("web1"); len(got) != 0 {
			t.Errorf("records after the second run = %v", got)
		}
		if plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); plan.HasChanges() {
			t.Error("a third plan has changes")
		}
	})
	t.Run("a later element fails", func(t *testing.T) {
		h := fakehost.New()
		h.FailApply("web1 /var/www/about.html")
		present(h, "web2")
		if ok, _ := applyAll(t, reactProject(t), h); ok {
			t.Fatal("apply succeeded")
		}
		if slices.Contains(h.Log["web1"], "command reindex") {
			t.Error("then ran after a failed element")
		}
		if got := h.ReactOf("web1"); !slices.ContainsFunc(got, func(r protocol.React) bool { return reflect.DeepEqual(r, siteThen) }) {
			t.Errorf("records = %v, want the record of the then", got)
		}
	})
	t.Run("empty loop", func(t *testing.T) {
		h := fakehost.New()
		present(h, "web1", "web2")
		h.SetFile("web1", "/etc/nginx/a.conf", "old\n")
		h.FailCommand("web1", "reindex")
		if ok, got := applyAll(t, reactProject(t, "vars.site_pages=[]"), h); !ok {
			t.Fatal(string(got))
		}
		if want := []string{"nginx reload", "access"}; !slices.Equal(h.Log["web1"], want) {
			t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
		}
		if r := h.ReactOf("web1"); len(r) != 0 {
			t.Errorf("records = %v, want none", r)
		}
	})
}

// spec: Reactions (then on a step with loop: its error names the step)
func TestThenErrorOfALoopStep(t *testing.T) {
	for _, tt := range []struct{ name, step, want string }{
		{"no name", "", "web1: base: failed: file (loop): then: sievec /etc/sieve: exit status 1"},
		{"a name", "      - name: Sieve scripts\n  ", "web1: base: failed: Sieve scripts: file: then: sievec /etc/sieve: exit status 1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			step := "      - file:\n          path: !tpl /etc/sieve/{{ item }}\n          content: x\n        loop: [a, b]\n        then: sievec /etc/sieve\n"
			if tt.step != "" {
				step = "      - name: Sieve scripts\n        file:\n          path: !tpl /etc/sieve/{{ item }}\n          content: x\n        loop: [a, b]\n        then: sievec /etc/sieve\n"
			}
			p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n" + step})
			h := fakehost.New()
			h.SetFile("web1", "/etc/sieve/b", "x")
			h.FailCommand("web1", "sievec /etc/sieve")
			ok, got := applyAll(t, p, h)
			if ok || !strings.Contains(string(got), tt.want+"\n") {
				t.Errorf("apply:\n%s\nwant the error %q", got, tt.want)
			}
		})
	}
}

// spec: Modules/service and unit (restarted and reloaded check as ok when the
// run started the unit after the change); Reactions
func TestRestartAfterStart(t *testing.T) {
	const conf = "  - file:\n      path: /etc/app.conf\n      content: \"app\\n\"\n"
	const start = "  - service:\n      name: app\n      running: true\n"
	const restart = "  - service:\n      name: app.service\n      restarted: true\n    on_change: [/etc/app.conf]\n"
	const reload = "  - service:\n      name: app\n      reloaded: true\n    on_change: [/etc/app.conf]\n"
	pending := func(h *fakehost.Hosts) {
		h.SetFile("web1", "/etc/app.conf", "app\n")
		h.SetReact("web1", protocol.React{Recipe: "app", Module: "service", Mains: mains("app.service")})
	}
	const oneStage = "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: app\n"
	tests := []struct {
		name     string
		pipeline string
		recipes  map[string]string
		setup    func(*fakehost.Hosts)
		want     []string
	}{
		{"a start after the change", oneStage, map[string]string{"app": "steps:\n" + conf + start + restart}, nil,
			[]string{"app start"}},
		{"a start after the change skips a reload", oneStage, map[string]string{"app": "steps:\n" + conf + start + reload}, nil,
			[]string{"app start"}},
		{"a change after the start", oneStage, map[string]string{"app": "steps:\n" + start + conf + restart}, nil,
			[]string{"app start", "app.service restart"}},
		{"a start in an earlier stage", "stages:\n  - name: a\n    hosts: all\n    steps:\n      - recipe: run\n  - name: b\n    hosts: all\n    steps:\n      - recipe: app\n",
			map[string]string{"run": "steps:\n" + start, "app": "steps:\n" + conf + restart}, nil,
			[]string{"app start", "app.service restart"}},
		{"a pending record without a start", oneStage, map[string]string{"app": "steps:\n" + conf + restart}, pending,
			[]string{"app.service restart"}},
		{"a pending record and a start", oneStage, map[string]string{"app": "steps:\n" + start + conf + restart}, pending,
			[]string{"app start"}},
		{"a change after the start and an earlier change", oneStage, map[string]string{"app": "steps:\n" + conf + start + "  - file:\n      path: /etc/app2.conf\n      content: \"app\\n\"\n" +
			"  - service:\n      name: app.service\n      restarted: true\n    on_change: [/etc/app.conf, /etc/app2.conf]\n"}, nil,
			[]string{"app start", "app.service restart"}},
		{"a start of another unit", oneStage, map[string]string{"app": "steps:\n" + conf + "  - service:\n      name: other\n      running: true\n" + restart}, nil,
			[]string{"other start", "app.service restart"}},
		{"a restart with confirm_access", oneStage, map[string]string{"app": "steps:\n" + conf + start + "  - service:\n      name: app\n      restarted: true\n    on_change: [/etc/app.conf]\n    confirm_access: true\n"}, nil,
			[]string{"app start", "app restart", "confirm"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"pipelines/site.yaml": tc.pipeline}
			for name, r := range tc.recipes {
				files["recipes/"+name+"/recipe.yaml"] = r
			}
			p := loadWeb1(t, files)
			h := fakehost.New()
			if tc.setup != nil {
				tc.setup(h)
			}
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			plan.Write(plain(&out), plain(&errOut))
			// The plan checks the restart as apply does.
			shows := strings.Contains(out.String(), ": restart (") || strings.Contains(out.String(), ": reload (")
			if shows != slices.ContainsFunc(tc.want, func(s string) bool { return strings.HasSuffix(s, " restart") }) {
				t.Errorf("plan:\n%s\nwant the restart line only when apply restarts", out.String())
			}
			if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
				t.Fatalf("apply failed:\n%s", errOut.String())
			}
			if got := slices.DeleteFunc(h.Log["web1"], func(s string) bool { return s == "access" }); !slices.Equal(got, tc.want) {
				t.Errorf("web1 ran %q, want %q", got, tc.want)
			}
			if r := h.ReactOf("web1"); len(r) != 0 {
				t.Errorf("records after the run = %v", r)
			}
		})
	}
}

// spec: Reactions (a change after a step that reacts to it is a plan error)
func TestChangeAfterReaction(t *testing.T) {
	for _, tt := range []struct {
		name, pipeline, want string
	}{
		{"a later recipe", `stages:
  - name: web
    hosts: all
    steps:
      - recipe: nginx
      - recipe: app
`, "web1: app: file /etc/nginx/sites-available/app: app#1 changes /etc/nginx/sites-available/app after nginx#2 reacts to it; add a step with on_change after app#1"},
		{"a later stage", `stages:
  - name: web
    hosts: all
    steps:
      - recipe: nginx
  - name: apps
    hosts: all
    steps:
      - recipe: app
`, "web1: app: file /etc/nginx/sites-available/app: app#1 changes /etc/nginx/sites-available/app after nginx#2 reacts to it; add a step with on_change after app#1"},
		{"a then", `stages:
  - name: web
    hosts: all
    steps:
      - dir:
          path: /etc/nginx/sites-available
        then: nginx -t
      - recipe: app
`, "web1: app: file /etc/nginx/sites-available/app: app#1 changes /etc/nginx/sites-available/app after the then of web#1 reacts to it; add a step with on_change after app#1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := loadWeb1(t, map[string]string{
				"pipelines/site.yaml":       tt.pipeline,
				"recipes/nginx/recipe.yaml": "steps:\n  - pkg:\n      name: nginx\n  - service:\n      name: nginx\n      reloaded: true\n    on_change: [/etc/nginx]\n",
				"recipes/app/recipe.yaml":   "steps:\n  - file:\n      path: /etc/nginx/sites-available/app\n      content: \"x\\n\"\n",
			})
			h := fakehost.New()
			h.SetFile("web1", "/etc/nginx/sites-available", "")
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			if err := plan.Failed["web1"]; err == nil || "web1: "+err.Error() != tt.want {
				t.Errorf("plan error %v, want %s", err, tt.want)
			}
		})
	}
	t.Run("no change after the reaction", func(t *testing.T) {
		p := loadWeb1(t, map[string]string{
			"pipelines/site.yaml":       "stages:\n  - name: web\n    hosts: all\n    steps:\n      - recipe: nginx\n      - recipe: app\n",
			"recipes/nginx/recipe.yaml": "steps:\n  - pkg:\n      name: nginx\n  - service:\n      name: nginx\n      reloaded: true\n    on_change: [/etc/nginx]\n",
			"recipes/app/recipe.yaml":   "steps:\n  - file:\n      path: /etc/nginx/sites-available/app\n      content: \"x\\n\"\n",
		})
		h := fakehost.New()
		h.SetFile("web1", "/etc/nginx/sites-available/app", "x\n")
		if plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); plan.Failed["web1"] != nil {
			t.Errorf("plan error %v, want none: the later step changes nothing", plan.Failed["web1"])
		}
	})
}

// spec: Reactions (the warning for a path that no step changes)
func TestOnChangeWithoutAStep(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    steps:
      - file:
          path: /etc/nginx/nginx.conf
          content: "x\n"
      - service:
          name: nginx
          reloaded: true
        on_change: [/etc/ngnix, /etc/nginx/conf.d]
      - service:
          name: nginx
          restarted: true
        on_change: [/etc/ngnix, /etc/nginx]
`,
	})
	h := fakehost.New()
	h.SetFile("web1", "/etc/nginx/nginx.conf", "x\n")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var errOut bytes.Buffer
	plan.WriteNotes(plain(&errOut))
	if want := "web1: warning: on_change: no step of web1 changes /etc/ngnix, /etc/nginx/conf.d\n"; errOut.String() != want {
		t.Errorf("notes %q, want %q", errOut.String(), want)
	}
}

// spec: Reactions (every earlier step of the host counts, in any stage;
// --stages); CLI (--stages)
func TestReactionInALaterStage(t *testing.T) {
	p := reactProject(t)
	if err := p.Select(project.Selection{Stages: "web"}); err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetFile("web1", "/var/www/about.html", "old\n")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.WriteNotes(plain(&errOut))
	if want := "web1: note: a pending service app of recipe app waits until its recipe runs on this host\n"; errOut.String() != want {
		t.Errorf("notes %q, want %q", errOut.String(), want)
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if got, want := h.ReactOf("web1"), []protocol.React{appRestart}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records after --stages web = %v, want %v", got, want)
	}

	p = reactProject(t)
	if err := p.Select(project.Selection{Stages: "apps"}); err != nil {
		t.Fatal(err)
	}
	plan = run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	out.Reset()
	plan.Write(plain(&out), plain(&errOut))
	if want := "! service app: restart (pending from an earlier run)\n"; !strings.Contains(out.String(), want) {
		t.Errorf("plan of --stages apps:\n%s\nwant %q", out.String(), want)
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"command reindex", "access", "app restart", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if r := h.ReactOf("web1"); len(r) != 0 {
		t.Errorf("records after --stages apps = %v", r)
	}
}

// spec: Reactions; Running a pipeline/Apply (gone records); State on the
// host (records of the old kinds stop matching)
func TestGoneRecords(t *testing.T) {
	files := maps.Clone(reactFiles)
	files["pipelines/mail.yaml"] = "stages:\n  - name: mx\n    hosts: all\n    steps:\n      - recipe: mail\n"
	files["recipes/mail/recipe.yaml"] = "steps:\n  - file:\n      path: /etc/mail.conf\n      content: mail\n"
	// The plan does not check these on web1: a recipe of another pipeline,
	// and a stage of another pipeline.
	kept := []protocol.React{
		{Recipe: "mail", Module: "cmd", Mains: mains("postfix reload")},
		{Pipeline: "mail", Stage: "mx", Module: "cmd", Mains: mains("x")},
	}
	// No step matches these: another module, a then of a step without then,
	// a recipe and a stage that the project no longer has, and a stage of
	// this pipeline.
	gone := []protocol.React{
		{Recipe: "nginx", Module: "cmd", Mains: mains("nginx")},
		{Recipe: "nginx", Module: "file", Mains: mains("/etc/nginx/a.conf"), Then: true},
		{Recipe: "old", Module: "service", Mains: mains("old")},
		{Pipeline: "site", Stage: "old", Module: "service", Mains: mains("old")},
		{Pipeline: "site", Stage: "web", Module: "service", Mains: mains("nginx")},
	}
	p := loadWeb1(t, files)
	h := fakehost.New()
	present(h, "web1")
	h.SetReact("web1", slices.Concat(kept, gone)...)
	h.SetOld("web1", "/var/lib/winch/handlers/acme", "/var/lib/winch/then/acme")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "reactions", "plan-gone.golden"), output(&out, &errOut))
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if got := h.ReactOf("web1"); !reflect.DeepEqual(got, kept) {
		t.Errorf("records after apply = %v, want %v", got, kept)
	}
	if got := h.OldOf("web1"); len(got) != 0 {
		t.Errorf("old record files after apply = %v, want none", got)
	}
	if len(h.Log["web1"]) != 0 {
		t.Errorf("web1 ran %q, want nothing", h.Log["web1"])
	}
	if next := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); next.HasWork() {
		t.Error("the next plan has work")
	}
}

// spec: Reactions (then); Running a pipeline/Plan; CLI/Output
func TestPendingThen(t *testing.T) {
	files := maps.Clone(reactFiles)
	files["pipelines/site.yaml"] += `      - file:
          path: /etc/motd
          content: "hi\n"
        then: newaliases
`
	p := loadWeb1(t, files)
	h := fakehost.New()
	present(h, "web1")
	h.SetFile("web1", "/etc/motd", "hi\n")
	h.SetReact("web1", siteThen, protocol.React{Pipeline: "site", Stage: "apps", Module: "file", Mains: mains("/etc/motd"), Then: true})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	out.WriteString("json:\n")
	plan.WriteJSON(run.NewEvents(plain(&out), func() time.Time { return time.Time{} }))
	golden.Assert(t, filepath.Join("testdata", "reactions", "plan-pending-then.golden"), output(&out, &errOut))

	out.Reset()
	errOut.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "reactions", "apply-pending-then.golden"), applyOutput(&out, &errOut))
	if want := []string{"command reindex", "command newaliases", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ReactOf("web1"); len(got) != 0 {
		t.Errorf("records on web1 = %v, want none", got)
	}
}

// spec: Reactions (then: a fixed command runs)
func TestFixedThenRuns(t *testing.T) {
	files := map[string]string{
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
	p := loadWeb1(t, files)
	if ok, got := applyAll(t, p, h); ok {
		t.Fatalf("apply succeeded with a failing then:\n%s", got)
	}

	files["pipelines/site.yaml"] = strings.Replace(files["pipelines/site.yaml"], "postmapp", "postmap", 1)
	p = loadWeb1(t, files)
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if want := "! then: postmap /etc/postfix/virtual\n"; !strings.Contains(out.String(), want) {
		t.Errorf("plan does not show %q:\n%s", want, out.String())
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"command postmapp /etc/postfix/virtual", "access", "command postmap /etc/postfix/virtual", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ReactOf("web1"); len(got) != 0 {
		t.Errorf("records = %v, want none", got)
	}
}

// spec: Reactions (a pending step runs wherever it now stands)
func TestInsertedStepKeepsPendingThen(t *testing.T) {
	files := map[string]string{
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
	p := loadWeb1(t, files)
	if ok, got := applyAll(t, p, h); ok {
		t.Fatalf("apply succeeded with a failing then:\n%s", got)
	}

	files["pipelines/site.yaml"] = strings.Replace(files["pipelines/site.yaml"], "    steps:\n", `    steps:
      - file:
          path: /etc/db.conf
          content: "db\n"
        then: systemctl restart db
`, 1)
	p = loadWeb1(t, files)
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
	if want := []string{"command postmap /etc/postfix/virtual", "access", "command postmap /etc/postfix/virtual", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
	if got := h.ReactOf("web1"); len(got) != 0 {
		t.Errorf("records = %v, want none", got)
	}
}

// spec: Reactions (a step counts only when it changes something)
func TestOKStepAddsNoRecord(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: tools\n    hosts: all\n    steps:\n      - recipe: tool\n",
		"recipes/tool/recipe.yaml": `steps:
  - download:
      url: https://example.com/tool
      sha256: ` + strings.Repeat("a", 64) + `
      path: /opt/tool
    then: tool --setup
  - service:
      name: tool
      restarted: true
    on_change: [/opt/tool]
`,
	})
	h := fakehost.New()
	h.SetResult("web1", "/opt/tool", module.Result{Status: module.OK})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if s := out.String(); strings.Contains(s, "service") || strings.Contains(s, "then:") {
		t.Errorf("plan:\n%s\nwant no restart or then", s)
	}
	ok, got := applyAll(t, p, h)
	if !ok {
		t.Fatalf("apply failed:\n%s", got)
	}
	if len(h.Log["web1"]) != 0 || len(h.ReactOf("web1")) != 0 {
		t.Errorf("apply ran %q, records %v; want nothing", h.Log["web1"], h.ReactOf("web1"))
	}
}

// spec: Reactions (pending records); Running a pipeline/Failures
func TestPendingRecordOfAFailedHost(t *testing.T) {
	p := loadWeb1(t, reactFiles)
	h := fakehost.New()
	present(h, "web1", "web2")
	h.SetReact("web1", appRestart, protocol.React{Recipe: "old", Module: "cmd"})
	h.FailCheck("web1")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	if plan.Failed["web1"] == nil {
		t.Fatal("web1 did not fail")
	}
	var errOut bytes.Buffer
	plan.WriteNotes(plain(&errOut))
	if errOut.Len() != 0 {
		t.Errorf("notes %q, want none for a failed host", errOut.String())
	}
}

// spec: Reactions (then: apply runs a pending record once)
func TestPendingThenOfTwoSteps(t *testing.T) {
	p := loadWeb1(t, map[string]string{
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
	h.SetReact("web1", protocol.React{Pipeline: "site", Stage: "ssh", Module: "line", Mains: mains("/etc/ssh/sshd_config"), Then: true})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if n := strings.Count(out.String(), "! then: sshd -t"); n != 1 {
		t.Errorf("the plan shows the pending then %d times, want once:\n%s", n, out.String())
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"command sshd -t", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
}

// spec: Running a pipeline/Lockout protection (the store of a guarded step
// holds the paths of the changes it reacts to; the line when it did not run)
func TestGuardedStepThatDidNotRun(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: ssh\n",
		"recipes/ssh/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/sshd_config.d/local.conf
      content: "PasswordAuthentication no\n"
  - file:
      path: /etc/motd
      content: "hi\n"
  - file:
      path: /etc/issue
      content: "hi\n"
  - service:
      name: ssh
      reloaded: true
    on_change: [/etc/ssh]
    confirm_access: true
`,
	})
	h := fakehost.New()
	h.FailApply("web1 /etc/issue")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	if run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal("apply succeeded")
	}
	// /etc/motd changed too, but the reload does not react to it.
	if want := "web1: put back /etc/ssh/sshd_config.d/local.conf: service ssh did not run\n"; !strings.Contains(out.String(), want) {
		t.Errorf("apply output:\n%s\nwant %q", out.String(), want)
	}
	h = fakehost.New()
	h.FailApply("web1 /etc/issue")
	out.Reset()
	run.Apply(context.Background(), run.MakePlan(context.Background(), p, h.Connector(), run.Options{}), h.Connector(), run.NewEvents(plain(&out), func() time.Time { return time.Time{} }))
	if want := `{"type":"diagnostic","time":"0001-01-01T00:00:00Z","severity":"note","host":"web1","message":"put back /etc/ssh/sshd_config.d/local.conf: service ssh did not run"}`; !strings.Contains(out.String(), want) {
		t.Errorf("JSON events:\n%s\nwant %s", out.String(), want)
	}
	reload := protocol.React{Recipe: "ssh", Module: "service", Mains: mains("ssh")}
	g := h.Guards["web1 /etc/ssh/sshd_config.d/local.conf"]
	if !reflect.DeepEqual(g.Guarded, []protocol.React{reload}) {
		t.Errorf("the guard of the drop-in = %+v, want the store of the reload", g)
	}
	if g := h.Guards["web1 /etc/motd"]; len(g.Guarded) != 0 {
		t.Errorf("the guard of /etc/motd = %+v, want no store: the reload does not react to it", g)
	}
	h.Fix("web1 /etc/issue")

	// After the reload ran, no line.
	h = fakehost.New()
	out.Reset()
	if !run.Apply(context.Background(), run.MakePlan(context.Background(), p, h.Connector(), run.Options{}), h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if strings.Contains(out.String(), "put back") {
		t.Errorf("apply output:\n%s\nwant no put back line", out.String())
	}
	if g := h.Guards["web1 ssh"]; g.Store != reload.Store() || !g.Confirm {
		t.Errorf("the guard of the reload = %+v, want its store and confirm", g)
	}
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

// spec: Modules/service and unit (restarted checks as ok only when the run
// started the unit after the change); Running a pipeline/Apply (the second
// check decides)
func TestRestartWhenApplyStartsNothing(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: app\n",
		"recipes/app/recipe.yaml": "steps:\n  - file:\n      path: /etc/app.conf\n      content: \"app\\n\"\n  - service:\n      name: app\n      running: true\n" +
			"  - service:\n      name: app.service\n      restarted: true\n    on_change: [/etc/app.conf]\n",
	})
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	// A package script started the unit before apply checks the start.
	h.SetResult("web1", "app", module.Result{Status: module.OK})
	var out, errOut bytes.Buffer
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal(errOut.String())
	}
	if want := []string{"app.service restart", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("web1 ran %q, want %q", h.Log["web1"], want)
	}
}

// spec: Running a pipeline/Lockout protection (the line names the paths
// that the store of the guarded step keeps)
func TestGuardedStepThatDidNotRunKeepsNoPath(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: ssh\n",
		"recipes/ssh/recipe.yaml": `steps:
  - pkg:
      name: openssh-server
  - file:
      path: /etc/motd
      content: "hi\n"
  - service:
      name: ssh
      reloaded: true
    on_change: [/var/lib/dpkg/status]
    confirm_access: true
`,
	})
	h := fakehost.New()
	h.FailApply("web1 /etc/motd")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	if run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal("apply succeeded")
	}
	if strings.Contains(out.String(), "put back") {
		t.Errorf("apply output:\n%s\nwant no put back line: the store keeps no path of a pkg step", out.String())
	}
}

// spec: Reactions (the plan shows a pending step with !); CLI/Output (marks)
func TestPendingStepThatChecksOK(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: app\n",
		"recipes/app/recipe.yaml": "steps:\n  - file:\n      path: /etc/app.conf\n      content: \"app\\n\"\n  - service:\n      name: app\n      running: true\n" +
			"  - service:\n      name: app.service\n      restarted: true\n    on_change: [/etc/app.conf]\n",
	})
	h := fakehost.New()
	h.SetReact("web1", protocol.React{Recipe: "app", Module: "service", Mains: mains("app.service")})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	// The run starts the unit after the change: the restart checks as ok,
	// and apply removes the record.
	if want := "      ! service app.service (/etc/app.conf changes)\n"; !strings.Contains(out.String(), want) {
		t.Errorf("plan:\n%s\nwant %q", out.String(), want)
	}
}

// spec: Variables/Secrets in output (a part of on_change that comes from a
// secret)
func TestOnChangeSecret(t *testing.T) {
	p, _ := secretsProject(t, map[string]string{"pw": "hunter2"}, stage+"      - service:\n          name: app\n          restarted: true\n        on_change: [!tpl \"/srv/{{ vars.pw }}\"]\n", "", nil, nil)
	plan := run.MakePlan(context.Background(), p, fakehost.New().Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if want := "web1: warning: on_change: no step of web1 changes /srv/(secret)\n"; !strings.Contains(errOut.String(), want) || strings.Contains(out.String()+errOut.String(), "hunter2") {
		t.Errorf("stderr %q, want %q and no secret", errOut.String(), want)
	}
}

// spec: Reactions (the warning counts the steps of the host only)
func TestOnChangeWithAStepOfAnotherHost(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"inventories/test.yaml": "hosts:\n  web1: {}\n  db1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: db
    hosts: db1
    steps:
      - file:
          path: /etc/db.conf
          content: "x\n"
  - name: web
    hosts: web1
    steps:
      - service:
          name: app
          restarted: true
        on_change: [/etc/db.conf]
`,
	})
	plan := run.MakePlan(context.Background(), p, fakehost.New().Connector(), run.Options{})
	var errOut bytes.Buffer
	plan.WriteNotes(plain(&errOut))
	if want := "web1: warning: on_change: no step of web1 changes /etc/db.conf\n"; errOut.String() != want {
		t.Errorf("notes %q, want %q", errOut.String(), want)
	}
}
