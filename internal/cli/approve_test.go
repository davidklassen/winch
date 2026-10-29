package cli

import (
	"context"
	"regexp"
	"strings"
	"sync"
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
		want := "winch: the plan hash is " + planHash(t, r.out) + ", not " + hash + "; nothing changed\n"
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

const handlerPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - recipe: app
`

const appRecipe = `steps:
  - file:
      path: /etc/app.conf
      content: "a\n"
    notify: reload
handlers:
  reload:
    - service:
        name: app
        reloaded: true
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
		"pipelines/site.yaml":     handlerPipeline,
		"recipes/app/recipe.yaml": appRecipe,
	})
	h = fakehost.New()
	h.SetFile("web1", "/etc/app.conf", "a\n")
	h.SetPending("web1", "app.reload")
	if r := winch(t, pending, h, false, "", "plan", "site", "--exit-code"); r.code != exitChanges {
		t.Errorf("a plan with only a pending handler: exit %d, want %d", r.code, exitChanges)
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
	h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "base", Step: 1, Module: "file", Main: "/etc/motd"})
	then := writeProject(t, strings.Replace(motd, `content: "hello\n"`, `content: "hello\n"`+"\n        then: echo done", 1))
	if r := winch(t, then, h, false, "", "plan", "site", "--exit-code"); r.code != exitChanges {
		t.Errorf("a plan with only a pending then: exit %d, want %d, stdout %q", r.code, exitChanges, r.out)
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
	// web2 goes down after its check, before apply connects again.
	h.OnCheck = func(host, _ string) {
		if host == "web2" {
			h.SetUnreachable("web2")
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
	code := Main(ctx, []string{"apply", "site"}, Env{
		Dir: writeProject(t, motd), In: interruptReader{cancel}, Out: &out, Err: &errOut, Terminal: true,
		Connect: h.ConnectorFor, Filter: secret.NewFilter(),
	})
	if code != exitOK || h.Applies != 0 || !strings.HasSuffix(errOut.String(), "Apply these changes? [y/N] \nNothing changed.\n") {
		t.Errorf("exit %d, applies %d, stderr %q", code, h.Applies, errOut.String())
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
}

// spec: CLI/Prompts
func TestQuestionDiscardsEarlyInput(t *testing.T) {
	controller, terminal := openPTY(t)
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
