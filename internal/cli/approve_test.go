package cli

import (
	"context"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

var hashLineRe = regexp.MustCompile(`\nplan ([0-9a-f]{16})\n`)

// planHash returns the plan hash in the output of plan or apply.
func planHash(t *testing.T, out string) string {
	t.Helper()
	m := hashLineRe.FindStringSubmatch("\n" + out)
	if m == nil {
		t.Fatalf("no plan hash in %q", out)
	}
	return m[1]
}

// spec: Running a pipeline/Apply; CLI/Exit codes
func TestCheck(t *testing.T) {
	dir := writeProject(t, motd)
	t.Run("the same plan applies", func(t *testing.T) {
		h := fakehost.New()
		r := winch(t, dir, h, false, "", "plan", "site")
		hash := planHash(t, r.out)
		r = winch(t, dir, h, false, "", "apply", "site", "--check", hash)
		if r.code != exitOK || h.Applies != 2 {
			t.Errorf("exit %d, applies %d, stderr %q", r.code, h.Applies, r.err)
		}
		if planHash(t, r.out) != hash {
			t.Errorf("apply shows another hash than %s:\n%s", hash, r.out)
		}
	})
	t.Run("a stale hash changes nothing", func(t *testing.T) {
		h := fakehost.New()
		hash := planHash(t, winch(t, dir, h, false, "", "plan", "site").out)
		h.SetFile("web1", "/etc/motd", "drift\n")
		r := winch(t, dir, h, false, "", "apply", "site", "--check", hash)
		if r.code != exitHash || h.Applies != 0 {
			t.Errorf("exit %d, applies %d", r.code, h.Applies)
		}
		want := "winch apply: the plan hash is " + planHash(t, r.out) + ", not " + hash + "; nothing changed\n"
		if r.err != want {
			t.Errorf("stderr = %q, want %q", r.err, want)
		}
	})
	t.Run("a plan for another login user changes nothing", func(t *testing.T) {
		hash := planHash(t, winch(t, dir, fakehost.New(), false, "", "plan", "site").out)
		h := fakehost.New()
		r := winch(t, dir, h, false, "", "apply", "site", "--user", "deploy", "--check", hash)
		if r.code != exitHash || h.Applies != 0 {
			t.Errorf("exit %d, applies %d", r.code, h.Applies)
		}
	})
	t.Run("a plan for another ssh destination changes nothing", func(t *testing.T) {
		hash := planHash(t, winch(t, dir, fakehost.New(), false, "", "plan", "site").out)
		h := fakehost.New()
		h.SetDestination("web1", protocol.Destination{User: "admin", HostName: "192.0.2.10", Port: "22"})
		r := winch(t, dir, h, false, "", "apply", "site", "--check", hash)
		if r.code != exitHash || h.Applies != 0 {
			t.Errorf("exit %d, applies %d", r.code, h.Applies)
		}
	})
	t.Run("the same plan with a terminal does not ask", func(t *testing.T) {
		h := fakehost.New()
		hash := planHash(t, winch(t, dir, h, false, "", "plan", "site").out)
		r := winch(t, dir, h, true, "", "apply", "site", "--check", hash)
		if r.code != exitOK || h.Applies != 2 || strings.Contains(r.err, "Apply these changes?") {
			t.Errorf("exit %d, applies %d, stderr %q", r.code, h.Applies, r.err)
		}
	})
	t.Run("a stale hash with a terminal does not ask", func(t *testing.T) {
		h := fakehost.New()
		r := winch(t, dir, h, true, "y\n", "apply", "site", "--check", "0badc0de0badc0de")
		if r.code != exitHash || h.Applies != 0 || strings.Contains(r.err, "Apply these changes?") {
			t.Errorf("exit %d, applies %d, stderr %q", r.code, h.Applies, r.err)
		}
	})
	t.Run("a failed host wins over a stale hash", func(t *testing.T) {
		h := fakehost.New()
		h.FailCheck("web1")
		r := winch(t, dir, h, false, "", "apply", "site", "--check", "0badc0de0badc0de")
		if r.code != exitFailed || h.Applies != 0 {
			t.Errorf("exit %d, applies %d", r.code, h.Applies)
		}
	})
	for _, bad := range []string{"xyz", "A3F9C2E1D07B4C58", "a3f9c2e1", "a3f9c2e1d07b4c5", "a3f9c2e1d07b4c580", ""} {
		t.Run("bad hash "+bad, func(t *testing.T) {
			h := fakehost.New()
			r := winch(t, dir, h, false, "", "apply", "site", "--yes", "--check", bad)
			if r.code != exitInvalid || !strings.Contains(r.err, "a plan hash has 16 hex characters") {
				t.Errorf("exit %d, stderr %q", r.code, r.err)
			}
			if h.Applies != 0 || len(h.FactsReads) != 0 {
				t.Errorf("winch contacted a host: applies %d, facts reads %v", h.Applies, h.FactsReads)
			}
		})
	}
	t.Run("plan does not take --check", func(t *testing.T) {
		r := winch(t, dir, fakehost.New(), false, "", "plan", "site", "--check", "a3f9c2e1d07b4c58")
		if r.code != exitInvalid {
			t.Errorf("exit %d", r.code)
		}
	})
}

const appPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - recipe: app
`

const appRecipe = `steps:
  - file:
      path: /etc/app.conf
      content: "a\n"
  - service:
      name: app
      reloaded: true
    on_change: [/etc/app.conf]
`

// spec: CLI ("--exit-code"); CLI/Exit codes
func TestExitCode(t *testing.T) {
	dir := writeProject(t, motd)
	h := fakehost.New()
	if r := winch(t, dir, h, false, "", "plan", "site", "--exit-code"); r.code != exitChanges {
		t.Errorf("a plan with changes: exit %d, want %d", r.code, exitChanges)
	}
	if r := winch(t, dir, h, false, "", "plan", "site"); r.code != exitOK {
		t.Errorf("a plan with changes without --exit-code: exit %d", r.code)
	}
	winch(t, dir, h, false, "", "apply", "site", "--yes")
	if r := winch(t, dir, h, false, "", "plan", "site", "--exit-code"); r.code != exitOK {
		t.Errorf("a plan without changes: exit %d, want 0", r.code)
	}
	h.FailCheck("web1")
	h.SetFile("web2", "/etc/motd", "drift\n")
	if r := winch(t, dir, h, false, "", "plan", "site", "--exit-code"); r.code != exitFailed {
		t.Errorf("a plan with a failed host: exit %d, want %d", r.code, exitFailed)
	}
	if r := winch(t, dir, h, false, "", "apply", "site", "--exit-code"); r.code != exitInvalid {
		t.Errorf("apply --exit-code: exit %d, want %d", r.code, exitInvalid)
	}

	pending := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":              "name: acme\ninventory: test\n",
		"inventories/test.yaml":   "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":     appPipeline,
		"recipes/app/recipe.yaml": appRecipe,
	})
	h = fakehost.New()
	h.SetFile("web1", "/etc/app.conf", "a\n")
	h.SetReact("web1", protocol.React{Recipe: "app", Module: "service", Mains: mains("app")})
	if r := winch(t, pending, h, false, "", "plan", "site", "--exit-code"); r.code != exitChanges {
		t.Errorf("a plan with only a pending step: exit %d, want %d", r.code, exitChanges)
	}
	unknown := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - cmd:\n          command: apt-get clean\n",
	})
	if r := winch(t, unknown, fakehost.New(), false, "", "plan", "site", "--exit-code"); r.code != exitChanges {
		t.Errorf("a plan with only an unknown step: exit %d, want %d, stdout %q", r.code, exitChanges, r.out)
	}
	h = fakehost.New()
	h.SetFile("web1", "/etc/motd", "hello\n")
	h.SetFile("web2", "/etc/motd", "hello\n")
	h.SetReact("web1", protocol.React{Pipeline: "site", Stage: "base", Module: "file", Mains: mains("/etc/motd"), Then: true})
	then := writeProject(t, strings.Replace(motd, `content: "hello\n"`, `content: "hello\n"`+"\n        then: echo done", 1))
	if r := winch(t, then, h, false, "", "plan", "site", "--exit-code"); r.code != exitChanges {
		t.Errorf("a plan with only a pending then: exit %d, want %d, stdout %q", r.code, exitChanges, r.out)
	}
}

// spec: Running a pipeline/Lockout protection (the rollback of an earlier run
// is the first change of the host); CLI ("--exit-code")
func TestDueRollbackOnlyThroughCLI(t *testing.T) {
	dir := writeProject(t, motd)
	h := fakehost.New()
	h.SetFile("web1", "/etc/motd", "hello\n")
	h.SetFile("web2", "/etc/motd", "hello\n")
	h.SetDue("web1", "put back /etc/nftables.conf")
	if r := winch(t, dir, h, false, "", "plan", "site", "--exit-code"); r.code != exitChanges {
		t.Errorf("plan --exit-code: exit %d, want %d, stdout %q", r.code, exitChanges, r.out)
	}
	r := winch(t, dir, h, false, "", "apply", "site")
	if r.code != exitConfirm || !strings.Contains(r.out, "To apply, run: ") {
		t.Errorf("apply without a terminal: exit %d, want %d, stdout %q", r.code, exitConfirm, r.out)
	}
	if r := winch(t, dir, h, true, "n\n", "apply", "site"); r.code != exitOK || !strings.Contains(r.err, "Nothing changed.") {
		t.Errorf("apply answered no: exit %d, stderr %q", r.code, r.err)
	}
	if slices.Contains(h.Log["web1"], "due") {
		t.Errorf("apply ran the rollback without a yes: log %q", h.Log["web1"])
	}
	r = winch(t, dir, h, false, "", "apply", "site", "--check", planHash(t, r.out))
	if r.code != exitOK || !strings.Contains(r.out, "web1: ! rollback of an earlier run\n") {
		t.Errorf("apply: exit %d, stdout %q", r.code, r.out)
	}
	if !slices.Contains(h.Log["web1"], "due") || h.Applies != 0 {
		t.Errorf("apply: log %q, applies %d, want the rollback and no step", h.Log["web1"], h.Applies)
	}
}

// spec: Running a pipeline/Apply; Running a pipeline/Lockout protection
func TestHashCoversDueRollback(t *testing.T) {
	dir := writeProject(t, motd)
	h := fakehost.New()
	h.SetFile("web1", "/etc/motd", "hello\n")
	h.SetFile("web2", "/etc/motd", "hello\n")
	hash := planHash(t, winch(t, dir, h, false, "", "plan", "site").out)
	h.SetDue("web1", "put back /etc/nftables.conf")
	r := winch(t, dir, h, false, "", "apply", "site", "--check", hash)
	if r.code != exitHash || slices.Contains(h.Log["web1"], "due") {
		t.Errorf("exit %d, want %d, log %q", r.code, exitHash, h.Log["web1"])
	}
}

// spec: Running a pipeline/Lockout protection (a failed host runs no rollback)
func TestDueRollbackOfAFailedHostThroughCLI(t *testing.T) {
	dir := writeProject(t, motd)
	h := fakehost.New()
	h.SetFile("web2", "/etc/motd", "hello\n")
	h.SetDue("web1", "put back /etc/nftables.conf")
	h.FailCheck("web1")
	r := winch(t, dir, h, false, "", "apply", "site")
	if r.code != exitFailed || strings.Contains(r.out, "To apply, run: ") {
		t.Errorf("apply: exit %d, want %d, stdout %q", r.code, exitFailed, r.out)
	}
}

// spec: Reactions; CLI ("--exit-code")
func TestPendingStepOfALeftOutStage(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": motd + `  - name: access
    hosts: all
    steps:
      - recipe: ssh
`,
		"recipes/ssh/recipe.yaml": "steps:\n  - file:\n      path: /etc/ssh/banner\n      content: \"hi\\n\"\n  - service:\n      name: ssh\n      reloaded: true\n    on_change: [/etc/ssh]\n",
	})
	h := fakehost.New()
	h.SetFile("web1", "/etc/motd", "hello\n")
	reload := protocol.React{Recipe: "ssh", Module: "service", Mains: mains("ssh")}
	h.SetReact("web1", reload)
	r := winch(t, dir, h, false, "", "plan", "site", "--stages", "base", "--exit-code")
	if r.code != exitOK {
		t.Errorf("plan --exit-code: exit %d, want 0", r.code)
	}
	if want := "web1: note: a pending service ssh of recipe ssh waits until its recipe runs on this host\n"; !strings.Contains(r.err, want) {
		t.Errorf("stderr %q has no %q", r.err, want)
	}
	if r := winch(t, dir, h, false, "", "apply", "site", "--stages", "base"); r.code != exitOK {
		t.Errorf("apply without a terminal: exit %d, stderr %q", r.code, r.err)
	}
	if want := []protocol.React{reload}; !reflect.DeepEqual(h.ReactOf("web1"), want) {
		t.Errorf("records = %v, want %v", h.ReactOf("web1"), want)
	}
}

// spec: CLI/Exit codes; Running a pipeline/Failures
func TestUnreachableExit(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2:\n    address: unreachable\n",
		"pipelines/site.yaml":   motd,
	})
	h := fakehost.New()
	r := winch(t, dir, h, false, "", "plan", "site")
	if r.code != exitUnreachable || !strings.Contains(r.out, "2 hosts: 1 to change, 0 unchanged, 0 unknown, 1 failed\n") {
		t.Errorf("plan: exit %d, stdout %q", r.code, r.out)
	}
	if r := winch(t, dir, h, false, "", "plan", "site", "--exit-code"); r.code != exitUnreachable {
		t.Errorf("plan --exit-code: exit %d, want %d", r.code, exitUnreachable)
	}
	if r := winch(t, dir, h, false, "", "apply", "site"); r.code != exitUnreachable {
		t.Errorf("apply without a terminal: exit %d, want %d", r.code, exitUnreachable)
	}
	r = winch(t, dir, h, false, "", "apply", "site", "--yes")
	if c, _ := h.File("web1", "/etc/motd"); r.code != exitUnreachable || c != "hello\n" {
		t.Errorf("apply: exit %d, web1 /etc/motd %q", r.code, c)
	}
	if r := winch(t, dir, h, false, "", "apply", "site", "--check", "0badc0de0badc0de"); r.code != exitUnreachable {
		t.Errorf("apply with a stale hash: exit %d, want %d", r.code, exitUnreachable)
	}
	h.SetFile("web1", "/etc/motd", "drift\n")
	h.FailCheck("web1")
	if r := winch(t, dir, h, false, "", "plan", "site"); r.code != exitFailed {
		t.Errorf("plan with a failed and an unreachable host: exit %d, want %d", r.code, exitFailed)
	}
}

// spec: CLI/Exit codes; Running a pipeline/Failures
func TestUnreachableDuringApply(t *testing.T) {
	h := fakehost.New()
	// web2 goes down after its check: its session dies, and apply cannot
	// connect again.
	h.OnCheck = func(host, _ string) {
		if host == "web2" {
			h.SetUnreachable("web2")
			h.Kill("web2")
		}
	}
	r := winch(t, writeProject(t, motd), h, false, "", "apply", "site", "--yes", "--json")
	if r.code != exitUnreachable || !strings.Contains(r.out, `"phase":"apply","host":"web2","status":"unreachable"`) {
		t.Errorf("exit %d, stdout %q", r.code, r.out)
	}
}

// spec: Running a pipeline/Apply (Ctrl-C)
func TestInterruptAtQuestion(t *testing.T) {
	h := fakehost.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut strings.Builder
	// main prints no interrupt message while winch asks.
	var asking atomic.Bool
	var askingAtInterrupt bool
	code := Main(ctx, []string{"apply", "site"}, Env{
		Dir: writeProject(t, motd), In: interruptReader{func() { askingAtInterrupt = asking.Load(); cancel() }}, Out: &out, Err: &errOut, Terminal: true,
		Connect: h.ConnectorFor, Filter: secret.NewFilter(), Asking: &asking,
	})
	if code != exitOK || h.Applies != 0 || !strings.HasSuffix(errOut.String(), "Apply these changes? [y/N] \nNothing changed.\n") {
		t.Errorf("exit %d, applies %d, stderr %q", code, h.Applies, errOut.String())
	}
	if !askingAtInterrupt || asking.Load() {
		t.Errorf("asking at the interrupt %t, after the question %t; want true, then false", askingAtInterrupt, asking.Load())
	}
	// spec: Remote execution/Sessions
	if h.Open != 0 {
		t.Errorf("%d sessions stay open", h.Open)
	}
}

// interruptReader interrupts the run when winch reads the answer, and never
// returns.
type interruptReader struct{ cancel func() }

func (r interruptReader) Read([]byte) (int, error) {
	r.cancel()
	select {}
}

// spec: Running a pipeline/Apply (Ctrl-C)
func TestInterruptDuringPlan(t *testing.T) {
	h := fakehost.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.OnCheck = func(host, _ string) {
		if host == "web1" {
			cancel()
		}
	}
	var out, errOut strings.Builder
	code := Main(ctx, []string{"apply", "site"}, Env{
		Dir: writeProject(t, motd), In: strings.NewReader("y\n"), Out: &out, Err: &errOut, Terminal: true,
		Connect: h.ConnectorFor, Filter: secret.NewFilter(),
	})
	if code != exitFailed || h.Applies != 0 || strings.Contains(errOut.String(), "Apply these changes?") {
		t.Errorf("exit %d, applies %d, stderr %q", code, h.Applies, errOut.String())
	}
	if h.Open != 0 {
		t.Errorf("%d sessions stay open", h.Open)
	}
}

// spec: CLI/Prompts
func TestQuestionDiscardsEarlyInput(t *testing.T) {
	controller, terminal := vmtest.OpenPTY(t)
	h := fakehost.New()
	h.OnCheck = func(host, _ string) {
		if host != "web1" {
			return
		}
		if _, err := controller.WriteString("y\n"); err != nil {
			t.Error(err)
		}
		// The terminal echoes the line when it holds it as input.
		var echo []byte
		buf := make([]byte, 64)
		for !strings.Contains(string(echo), "y\r\n") {
			n, err := controller.Read(buf)
			if err != nil {
				t.Error(err)
				return
			}
			echo = append(echo, buf[:n]...)
		}
	}
	errOut := &questionWriter{asked: make(chan struct{})}
	var out strings.Builder
	code := make(chan int, 1)
	go func() {
		code <- Main(context.Background(), []string{"apply", "site"}, Env{
			Dir: writeProject(t, motd), In: terminal, Out: &out, Err: errOut, Terminal: true,
			Connect: h.ConnectorFor, Filter: secret.NewFilter(),
		})
	}()
	select {
	case <-errOut.asked:
	case c := <-code:
		t.Fatalf("exit %d before the question, applies %d, stderr %q", c, h.Applies, errOut.String())
	}
	if _, err := controller.WriteString("n\n"); err != nil {
		t.Fatal(err)
	}
	c := <-code
	if c != exitOK || h.Applies != 0 || !strings.HasSuffix(errOut.String(), "Nothing changed.\n") {
		t.Errorf("exit %d, applies %d, stderr %q", c, h.Applies, errOut.String())
	}
}

// questionWriter closes asked when winch asks the apply question.
type questionWriter struct {
	mu    sync.Mutex
	b     strings.Builder
	asked chan struct{}
}

func (w *questionWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b.Write(p)
	if strings.Contains(string(p), "Apply these changes?") {
		close(w.asked)
	}
	return len(p), nil
}

func (w *questionWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}
