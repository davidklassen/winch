package run_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

// manyProject has three hosts, and a pipeline with the stages in stages.
func manyProject(t *testing.T, stages string) *project.Project {
	t.Helper()
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n  web3: {}\n",
		"pipelines/site.yaml":   "stages:\n" + stages,
		"recipes/app/recipe.yaml": `steps:
  - file:
      path: /etc/app.conf
      content: "app\n"
    notify: reload
handlers:
  reload:
    - service:
        name: app
        reloaded: true
`,
	}), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const motdStage = `  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "hi\n"
`

// barrier returns a hook that waits until n hosts called it, and a function
// that reports whether every call saw all n hosts arrive.
func barrier(n int) (func(host, main string), func() bool) {
	var mu sync.Mutex
	arrived := map[string]bool{}
	all := make(chan struct{})
	ok := true
	return func(host, main string) {
			mu.Lock()
			if !arrived[host] {
				arrived[host] = true
				if len(arrived) == n {
					close(all)
				}
			}
			mu.Unlock()
			select {
			case <-all:
			case <-time.After(2 * time.Second):
				mu.Lock()
				ok = false
				mu.Unlock()
			}
		}, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return ok
		}
}

// spec: Running a pipeline/Order
func TestHostsInParallel(t *testing.T) {
	for _, serial := range []bool{false, true} {
		t.Run(map[bool]string{false: "batch", true: "serial"}[serial], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := manyProject(t, motdStage)
				h := fakehost.New()
				hook, ok := barrier(3)
				h.OnCheck = hook
				plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{Serial: serial})
				if !ok() {
					t.Error("plan: the hosts did not check at the same time")
				}
				hook, ok = barrier(3)
				h.OnApply = hook
				var out, errOut bytes.Buffer
				if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
					t.Fatalf("apply failed: %s", errOut.String())
				}
				if !ok() {
					t.Error("apply: the hosts did not apply at the same time")
				}
			})
		})
	}
}

// spec: Running a pipeline/Order
func TestStagesInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := manyProject(t, motdStage+`  - name: next
    hosts: all
    steps:
      - file:
          path: /etc/issue
          content: "x\n"
`)
		h := fakehost.New()
		slow := func(host, main string) {
			if host == "web1" && main == "/etc/motd" {
				time.Sleep(100 * time.Millisecond)
			}
		}
		h.OnCheck, h.OnApply = slow, slow
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		var out, errOut bytes.Buffer
		run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut))
		last := slices.Index(h.Trace, "apply web1 /etc/motd")
		first := slices.IndexFunc(h.Trace, func(s string) bool { return strings.HasSuffix(s, " /etc/issue") })
		if last < 0 || first < last {
			t.Errorf("a host started the next stage before web1 finished the first: %q", h.Trace)
		}
	})
}

// spec: Running a pipeline/Order
func TestParallelism(t *testing.T) {
	for _, n := range []int{1, 2} {
		t.Run(map[int]string{1: "one", 2: "two"}[n], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := manyProject(t, strings.Replace(motdStage, "    hosts: all\n", "    hosts: all\n    parallelism: "+map[int]string{1: "1", 2: "2"}[n]+"\n", 1))
				h := fakehost.New()
				plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
				h.MaxOpen, h.Trace = 0, nil
				h.OnApply = func(host, main string) { time.Sleep(50 * time.Millisecond) }
				var out, errOut bytes.Buffer
				if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
					t.Fatalf("apply failed: %s", errOut.String())
				}
				if h.MaxOpen != n {
					t.Errorf("%d hosts ran at the same time, want %d", h.MaxOpen, n)
				}
				var connects []string
				for _, s := range h.Trace {
					if strings.HasPrefix(s, "connect ") {
						connects = append(connects, s)
					}
				}
				// The first n hosts start together and connect in any order.
				slices.Sort(connects[:n])
				if want := []string{"connect web1", "connect web2", "connect web3"}; !slices.Equal(connects, want) {
					t.Errorf("connects %q, want %q", connects, want)
				}
			})
		})
	}
}

// spec: Running a pipeline/Failures; Running a pipeline/Order
func TestParallelismFailure(t *testing.T) {
	next := `  - name: next
    hosts: all
    steps:
      - file:
          path: /etc/issue
          content: "x\n"
`
	tests := []struct {
		name        string
		parallelism string
		want        map[string]string
		// issue are the hosts that reach the next stage.
		issue []string
	}{
		{name: "with parallelism", parallelism: "    parallelism: 1\n",
			want:  map[string]string{"web2": "base: failed: file /etc/motd: write /etc/motd: read-only file system", "web3": "not started: web2 failed in stage base"},
			issue: []string{"web1"}},
		{name: "without parallelism",
			want:  map[string]string{"web2": "base: failed: file /etc/motd: write /etc/motd: read-only file system"},
			issue: []string{"web1", "web3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := manyProject(t, strings.Replace(motdStage, "    hosts: all\n", "    hosts: all\n"+tt.parallelism, 1)+next)
			h := fakehost.New()
			h.FailApply("web2 /etc/motd")
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			o := run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut))
			got := map[string]string{}
			for host, err := range o.Failed {
				got[host] = err.Error()
			}
			for host, want := range tt.want {
				if got[host] != want {
					t.Errorf("%s: error %q, want %q", host, got[host], want)
				}
			}
			if len(got) != len(tt.want) {
				t.Errorf("failed hosts %q, want %q", got, tt.want)
			}
			for _, host := range []string{"web1", "web2", "web3"} {
				_, ok := h.File(host, "/etc/issue")
				if want := slices.Contains(tt.issue, host); ok != want {
					t.Errorf("%s reached the next stage: %v, want %v", host, ok, want)
				}
			}
		})
	}
}

const healthStage = `  - name: base
    hosts: all
    parallelism: 1
    health:
      command: curl -sf http://localhost/
      stable: 2
      timeout: 30
    steps:
      - file:
          path: /etc/motd
          content: "hi\n"
`

// spec: Running a pipeline/Health gates; Running a pipeline/Order; Running a pipeline/Failures
func TestHealthGate(t *testing.T) {
	t.Run("runs after a stage with a change", func(t *testing.T) {
		p := manyProject(t, healthStage)
		h := fakehost.New()
		h.SetFile("web2", "/etc/motd", "hi\n")
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		if slices.ContainsFunc(h.Trace, func(s string) bool { return strings.HasPrefix(s, "health ") }) {
			t.Errorf("plan ran the health gate: %q", h.Trace)
		}
		h.Trace = nil
		var out, errOut bytes.Buffer
		if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
			t.Fatalf("apply failed: %s", errOut.String())
		}
		want := []string{
			"connect web1", "apply web1 /etc/motd", "health web1 curl -sf http://localhost/ 2s 30s", "close web1",
			"connect web3", "apply web3 /etc/motd", "health web3 curl -sf http://localhost/ 2s 30s", "close web3",
		}
		if !slices.Equal(h.Trace, want) {
			t.Errorf("trace\n%q\nwant\n%q", h.Trace, want)
		}
		if !strings.Contains(out.String(), "web1: base: * health: curl -sf http://localhost/\n") {
			t.Errorf("apply output does not show the gate:\n%s", out.String())
		}
	})
	t.Run("a failing gate stops the next host", func(t *testing.T) {
		p := manyProject(t, healthStage)
		h := fakehost.New()
		h.FailCommand("web1", "curl -sf http://localhost/")
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		var out, errOut bytes.Buffer
		o := run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut))
		if err := o.Failed["web1"]; err == nil || err.Error() != "base: failed: health: curl -sf http://localhost/: did not pass within 30s: exit status 1" {
			t.Errorf("web1: error %v", err)
		}
		for _, host := range []string{"web2", "web3"} {
			if _, ok := h.File(host, "/etc/motd"); ok {
				t.Errorf("%s started after the failed gate", host)
			}
			if err := o.Failed[host]; err == nil || err.Error() != "not started: web1 failed in stage base" {
				t.Errorf("%s: error %v", host, err)
			}
		}
	})
}

// spec: Running a pipeline/Health gates; CLI/Output
func TestPlanHealth(t *testing.T) {
	p := manyProject(t, healthStage)
	h := fakehost.New()
	h.SetFile("web2", "/etc/motd", "hi\n")
	h.SetFile("web3", "/etc/motd", "hi\n")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	golden.Assert(t, filepath.Join("testdata", "plan", "health.golden"), output(&out, &errOut))
}

// spec: Remote execution/Sessions
func TestSerialStart(t *testing.T) {
	for _, serial := range []bool{true, false} {
		t.Run(map[bool]string{false: "batch", true: "serial"}[serial], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := manyProject(t, motdStage)
				h := fakehost.New()
				var mu sync.Mutex
				inside, overlap := 0, false
				var order []string
				h.OnConnect = func(host string) {
					mu.Lock()
					inside++
					overlap = overlap || inside > 1
					order = append(order, host)
					mu.Unlock()
					time.Sleep(30 * time.Millisecond)
					mu.Lock()
					inside--
					mu.Unlock()
				}
				plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{Serial: serial})
				var out, errOut bytes.Buffer
				run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut))
				if overlap == serial {
					t.Errorf("connects overlap: %v", overlap)
				}
				if serial && !slices.Equal(order, []string{"web1", "web2", "web3", "web1", "web2", "web3"}) {
					t.Errorf("connect order %q", order)
				}
			})
		})
	}
}

// spec: Remote execution/Sessions ("plan and apply each make one handshake
// per host")
func TestOneSessionPerHost(t *testing.T) {
	for _, serial := range []bool{true, false} {
		t.Run(map[bool]string{false: "batch", true: "serial"}[serial], func(t *testing.T) {
			p := manyProject(t, motdStage+`  - name: web2
    hosts: web2
    steps:
      - file:
          path: /etc/issue
          content: "x\n"
  - name: rest
    hosts: web1,web3
    steps:
      - file:
          path: /etc/hostname
          content: "x\n"
`)
			h := fakehost.New()
			check := func(phase string) {
				t.Helper()
				for _, host := range []string{"web1", "web2", "web3"} {
					if h.Connects[host] != 1 {
						t.Errorf("%s: %s: %d connects, want 1", phase, host, h.Connects[host])
					}
				}
				if h.Open != 0 {
					t.Errorf("%s: %d connections are still open", phase, h.Open)
				}
				if i, j := slices.Index(h.Trace, "close web2"), slices.Index(h.Trace, "close web1"); i < 0 || i > j {
					t.Errorf("%s: web2 is not closed before web1 at the end of its work: %q", phase, h.Trace)
				}
				clear(h.Connects)
				h.Trace = nil
			}
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{Serial: serial})
			check("plan")
			var out, errOut bytes.Buffer
			if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
				t.Fatalf("apply failed: %s", errOut.String())
			}
			check("apply")
		})
	}
}

// spec: Remote execution/Sessions ("It closes when its host has no more
// work")
func TestSessionClosesWhenHostStops(t *testing.T) {
	const next = `  - name: next
    hosts: all
    parallelism: 1
    steps:
      - file:
          path: /etc/issue
          content: "x\n"
`
	t.Run("plan interrupted", func(t *testing.T) {
		p := manyProject(t, motdStage+next)
		h := fakehost.New()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// web3 finishes its only step of base, and is interrupted before next.
		h.OnCheck = func(host, main string) {
			if host == "web3" {
				cancel()
			}
		}
		plan := run.MakePlan(ctx, p, h.Connector(), run.Options{})
		if !errors.Is(plan.Failed["web3"], run.ErrInterrupted) || h.Connects["web3"] != 1 {
			t.Fatalf("web3: error %v, %d connects, want interrupted after 1", plan.Failed["web3"], h.Connects["web3"])
		}
		if h.Open != 0 {
			t.Errorf("%d connections are still open", h.Open)
		}
	})
	t.Run("last stage not selected", func(t *testing.T) {
		p := manyProject(t, motdStage+next)
		if err := p.Select(project.Selection{Stages: "base"}); err != nil {
			t.Fatal(err)
		}
		h := fakehost.New()
		run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		if h.Open != 0 {
			t.Errorf("%d connections are still open", h.Open)
		}
	})
	t.Run("apply hosts not started", func(t *testing.T) {
		p := manyProject(t, motdStage+next)
		h := fakehost.New()
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		h.FailApply("web1 /etc/issue")
		var out, errOut bytes.Buffer
		o := run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut))
		if o.Failed["web2"] == nil {
			t.Fatalf("web2 did not fail: %s", errOut.String())
		}
		if h.Open != 0 {
			t.Errorf("%d connections are still open", h.Open)
		}
	})
}

// spec: Handlers; CLI (--stages)
func TestStagesLeaveHandlerPending(t *testing.T) {
	p := manyProject(t, `  - name: app
    hosts: all
    steps:
      - recipe: app
  - name: conf
    hosts: all
    steps:
      - file:
          path: /etc/app.d/x.conf
          content: "x\n"
        notify: app.reload
`)
	if err := p.Select(project.Selection{Stages: "conf"}); err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(&out, &errOut)
	if strings.Contains(out.String(), "handler") || strings.Contains(out.String(), "/etc/app.conf") {
		t.Errorf("the plan shows the skipped stage:\n%s", out.String())
	}
	out.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
		t.Fatalf("apply failed: %s", errOut.String())
	}
	for _, host := range []string{"web1", "web2", "web3"} {
		if got := h.PendingOf(host); !slices.Equal(got, []string{"app.reload"}) {
			t.Errorf("%s: pending %q, want app.reload", host, got)
		}
		if len(h.Log[host]) != 0 {
			t.Errorf("%s: the handler ran: %q", host, h.Log[host])
		}
		if _, ok := h.File(host, "/etc/app.conf"); ok {
			t.Errorf("%s: the skipped stage ran", host)
		}
	}
}

// spec: Running a pipeline/Plan; CLI (--stages)
func TestSkippedStageRequirement(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":                 "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml":      "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":        "stages:\n  - name: a\n    hosts: all\n    steps:\n      - recipe: ubuntu\n" + motdStage,
		"recipes/ubuntu/recipe.yaml": "require:\n  - !expr 'facts.os.id == \"ubuntu\"'\nsteps: []\n",
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Select(project.Selection{Stages: "base"}); err != nil {
		t.Fatal(err)
	}
	plan := run.MakePlan(context.Background(), p, fakehost.New().Connector(), run.Options{})
	if err := plan.Failed["web1"]; err == nil || !strings.Contains(err.Error(), "recipe ubuntu requires") {
		t.Errorf("web1: error %v, want the requirement", err)
	}
}

// spec: Running a pipeline/Apply (Ctrl-C); Running a pipeline/Health gates
func TestNoHealthGateAfterInterrupt(t *testing.T) {
	p := manyProject(t, strings.Replace(healthStage, "    parallelism: 1\n", "", 1))
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.OnApply = func(host, main string) { cancel() }
	var out, errOut bytes.Buffer
	o := run.Apply(ctx, plan, h.Connector(), run.Text(&out, &errOut))
	if slices.ContainsFunc(h.Trace, func(s string) bool { return strings.HasPrefix(s, "health ") }) {
		t.Errorf("a gate ran after the interrupt: %q", h.Trace)
	}
	for _, host := range []string{"web1", "web2", "web3"} {
		if !errors.Is(o.Failed[host], run.ErrInterrupted) {
			t.Errorf("%s: error %v, want interrupted", host, o.Failed[host])
		}
	}
}

// spec: Running a pipeline/Failures ("Running hosts finish the stage")
func TestParallelismRunningHostsFinish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := manyProject(t, strings.Replace(motdStage, "    hosts: all\n", "    hosts: all\n    parallelism: 2\n", 1))
		h := fakehost.New()
		h.FailApply("web1 /etc/motd")
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		h.OnApply = func(host, main string) {
			if host == "web2" {
				time.Sleep(200 * time.Millisecond)
			}
		}
		var out, errOut bytes.Buffer
		o := run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut))
		if _, ok := h.File("web2", "/etc/motd"); !ok || o.Failed["web2"] != nil {
			t.Errorf("web2 did not finish the stage: %v", o.Failed["web2"])
		}
		if err := o.Failed["web3"]; err == nil || err.Error() != "not started: web1 failed in stage base" {
			t.Errorf("web3: error %v", err)
		}
	})
}

// spec: Running a pipeline/Failures ("Without parallelism, other hosts continue")
func TestSerialFailureContinues(t *testing.T) {
	p := manyProject(t, motdStage)
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{Serial: true})
	h.SetUnreachable("web2")
	var out, errOut bytes.Buffer
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut))
	if _, ok := h.File("web3", "/etc/motd"); !ok || o.Failed["web3"] != nil {
		t.Errorf("web3 did not run after web2 failed: %v", o.Failed["web3"])
	}
}

// spec: Running a pipeline/Health gates
func TestHealthGateOnlyAfterAChange(t *testing.T) {
	p := manyProject(t, healthStage+`  - name: next
    hosts: all
    steps:
      - file:
          path: /etc/issue
          content: "x\n"
`)
	h := fakehost.New()
	h.SetFile("web2", "/etc/motd", "hi\n")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(&out, &errOut)).OK() {
		t.Fatalf("apply failed: %s", errOut.String())
	}
	if _, ok := h.File("web2", "/etc/issue"); !ok {
		t.Error("web2 did not apply")
	}
	if slices.ContainsFunc(h.Trace, func(s string) bool { return strings.HasPrefix(s, "health web2 ") }) {
		t.Errorf("web2 ran the gate of a stage without a change: %q", h.Trace)
	}
}

// spec: Running a pipeline/Order
func TestPlanStagesInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := manyProject(t, motdStage+`  - name: next
    hosts: all
    steps:
      - file:
          path: /etc/issue
          content: "x\n"
`)
		h := fakehost.New()
		var mu sync.Mutex
		var checks []string
		h.OnCheck = func(host, main string) {
			if host == "web1" && main == "/etc/motd" {
				time.Sleep(100 * time.Millisecond)
			}
			mu.Lock()
			checks = append(checks, main)
			mu.Unlock()
		}
		run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		if i := slices.Index(checks, "/etc/issue"); i < 0 || slices.Contains(checks[i:], "/etc/motd") {
			t.Errorf("a host checked the next stage before every host finished the first: %q", checks)
		}
	})
}
