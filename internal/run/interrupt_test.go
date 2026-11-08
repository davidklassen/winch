package run_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
)

func interruptProject(t *testing.T) *project.Project {
	t.Helper()
	return loadWeb1(t, map[string]string{
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
		// With parallelism 1, web2 starts only after web1.
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    parallelism: 1\n    steps:\n      - recipe: app\n",
		"recipes/app/recipe.yaml": `steps:
  - file:
      path: /etc/a
      content: "a\n"
    then: echo a
  - file:
      path: /etc/b
      content: "b\n"
  - service:
      name: app
      reloaded: true
    on_change: [/etc/a]
`,
	})
}

// spec: Running a pipeline/Apply (Ctrl-C)
func TestApplyInterrupted(t *testing.T) {
	p := interruptProject(t)
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.OnApply = func(host, main string) {
		if host == "web1" && main == "/etc/a" {
			cancel()
		}
	}
	var out, errOut bytes.Buffer
	o := run.Apply(ctx, plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	for _, host := range []string{"web1", "web2"} {
		if !errors.Is(o.Failed[host], run.ErrInterrupted) {
			t.Errorf("%s: error %v, want interrupted", host, o.Failed[host])
		}
	}
	if c, _ := h.File("web1", "/etc/a"); c != "a\n" {
		t.Error("the running step did not finish")
	}
	if !slices.Contains(h.Log["web1"], "command echo a") {
		t.Errorf("the then of the running step did not run: %q", h.Log["web1"])
	}
	if _, ok := h.File("web1", "/etc/b"); ok {
		t.Error("a new step started after the interrupt")
	}
	if got := h.Log["web1"]; len(got) == 0 || got[len(got)-1] != "access" {
		t.Errorf("no access check after the run after the interrupt: %q", got)
	}
	if _, ok := h.File("web2", "/etc/a"); ok || h.Connects["web2"] != 1 {
		t.Errorf("a new host started after the interrupt: %d connects of web2, want 1 of the plan", h.Connects["web2"])
	}
	if got, want := h.ReactOf("web1"), []protocol.React{{Recipe: "app", Module: "service", Mains: mains("app")}}; !reflect.DeepEqual(got, want) {
		t.Errorf("records %v, want %v", got, want)
	}
	if h.Open != 0 {
		t.Errorf("%d connections are still open", h.Open)
	}
	want := "web1: app: + file /etc/a\nweb1: access check after the run passed\n\n2 hosts: 0 changed, 0 unchanged, 2 failed\n"
	if out.String() != want || errOut.String() != "web1: interrupted\nweb2: interrupted\n" {
		t.Errorf("stdout %q, stderr %q", out.String(), errOut.String())
	}
}

// spec: Running a pipeline/Lockout protection (the access check after the
// run after the first Ctrl-C, on its own line after the error)
func TestApplyInterruptedLostAccess(t *testing.T) {
	p := interruptProject(t)
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.OnApply = func(host, main string) {
		if host == "web1" && main == "/etc/a" {
			cancel()
			h.FailAccess("web1")
		}
	}
	var out, errOut bytes.Buffer
	o := run.Apply(ctx, plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if !errors.Is(o.Failed["web1"], run.ErrInterrupted) || !errors.Is(o.Failed["web2"], run.ErrInterrupted) {
		t.Errorf("errors %v, want both hosts interrupted", o.Failed)
	}
	if want := "web1: interrupted\n  the access check after the run failed: ssh: connect to host web1 port 22: Connection timed out\nweb2: interrupted\n"; errOut.String() != want {
		t.Errorf("stderr %q, want %q", errOut.String(), want)
	}
}

// spec: Running a pipeline/Lockout protection (a second Ctrl-C skips the
// access check after the run)
func TestApplyInterruptedTwice(t *testing.T) {
	p := interruptProject(t)
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.OnApply = func(host, main string) {
		if host == "web1" && main == "/etc/b" {
			cancel()
			h.EndSessions("web1")
		}
	}
	var out, errOut bytes.Buffer
	o := run.Apply(ctx, plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if o.Failed["web1"] == nil {
		t.Fatal("web1 did not fail")
	}
	// The fake host logs the try that the end of the sessions cancels.
	if n := slices.Index(h.Log["web1"], "access"); n < 0 || slices.Contains(h.Log["web1"][n+1:], "access") || strings.Contains(errOut.String()+out.String(), "access check") {
		t.Errorf("the access check after the run ran after a second interrupt: log %q, stdout %q, stderr %q", h.Log["web1"], out.String(), errOut.String())
	}
}

// spec: Running a pipeline/Apply (Ctrl-C)
func TestPlanInterrupted(t *testing.T) {
	h := fakehost.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan := run.MakePlan(ctx, interruptProject(t), h.Connector(), run.Options{})
	for _, host := range []string{"web1", "web2"} {
		if !errors.Is(plan.Failed[host], run.ErrInterrupted) {
			t.Errorf("%s: error %v, want interrupted", host, plan.Failed[host])
		}
		if h.FactsReads[host] != 0 {
			t.Errorf("%s: the plan contacted the host after the interrupt", host)
		}
	}
}

// spec: Running a pipeline/Apply (Ctrl-C)
func TestPlanInterruptedBetweenChecks(t *testing.T) {
	h := fakehost.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var checks []string
	h.OnCheck = func(host, main string) {
		mu.Lock()
		defer mu.Unlock()
		checks = append(checks, host+" "+main)
		cancel()
	}
	plan := run.MakePlan(ctx, interruptProject(t), h.Connector(), run.Options{})
	// The plan checks both hosts at the same time; each stops after its
	// running check.
	if len(checks) == 0 || slices.ContainsFunc(checks, func(c string) bool { return !strings.HasSuffix(c, " /etc/a") }) {
		t.Errorf("checks %q, want only the first step of each host", checks)
	}
	for _, host := range []string{"web1", "web2"} {
		if !errors.Is(plan.Failed[host], run.ErrInterrupted) {
			t.Errorf("%s: error %v, want interrupted", host, plan.Failed[host])
		}
	}
}

// spec: CLI (winch exec)
func TestExecInterruptedDuringConnect(t *testing.T) {
	p := interruptProject(t)
	h := fakehost.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.OnConnect = func(string) { cancel() }
	results := run.Exec(ctx, p.Name, p.Pipeline.Stages[0].Targets, protocol.Exec{Command: "uptime"}, h.Connector(), run.Options{Serial: true})
	for _, r := range results {
		if r.Ran || !errors.Is(r.Err, run.ErrInterrupted) {
			t.Errorf("%s: ran %v, error %v, want interrupted", r.Host, r.Ran, r.Err)
		}
	}
	if len(h.Log["web1"]) != 0 || h.Open != 0 {
		t.Errorf("web1 ran %q, %d sessions stay open", h.Log["web1"], h.Open)
	}
}

// spec: CLI (winch exec)
func TestExecFailsAfterInterrupt(t *testing.T) {
	p := interruptProject(t)
	h := fakehost.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.OnExec = func(host string) {
		if host == "web1" {
			cancel()
		}
	}
	h.FailExec("web1")
	results := run.Exec(ctx, p.Name, p.Pipeline.Stages[0].Targets, protocol.Exec{Command: "uptime"}, h.Connector(), run.Options{Serial: true})
	if r := results[0]; r.Ran || !errors.Is(r.Err, run.ErrInterrupted) {
		t.Errorf("%s: ran %v, error %v, want interrupted", r.Host, r.Ran, r.Err)
	}
}
