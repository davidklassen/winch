package integration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/vmtest"
)

var hashRe = regexp.MustCompile(`\nplan ([0-9a-f]{8})\n`)

func hashOf(t *testing.T, out string) string {
	t.Helper()
	m := hashRe.FindStringSubmatch("\n" + out)
	if m == nil {
		t.Fatalf("no plan hash in %q", out)
	}
	return m[1]
}

// spec: Running a pipeline/Plan; Running a pipeline/Apply; CLI/Exit codes
func TestApprove(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "approve")
	dir := project(t, "hosts:\n  approve:\n    address: 127.0.0.1\n")

	t.Run("a stale hash exits 6 and changes nothing", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "site")
		hash := hashOf(t, r.Stdout)
		pipeline := filepath.Join(dir, "pipelines/site.yaml")
		data, err := os.ReadFile(pipeline)
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(data), "Managed by winch.", "Managed by winch, edited.", 1)
		if err := os.WriteFile(pipeline, []byte(edited), 0o644); err != nil {
			t.Fatal(err)
		}
		before := vm.MustRun(t, "cat /etc/motd")
		r = lab.Winch(t, dir, "apply", "site", "--check", hash)
		if r.Code != 6 || !strings.Contains(r.Stderr, "not "+hash+"; nothing changed") {
			t.Errorf("apply with the old hash: exit %d", r.Code)
		}
		if after := vm.MustRun(t, "cat /etc/motd"); after != before {
			t.Errorf("/etc/motd changed to %q", after)
		}
		r = lab.Winch(t, dir, "apply", "site", "--check", hashOf(t, r.Stdout))
		if r.Code != 0 || vm.MustRun(t, "cat /etc/motd") != "Managed by winch, edited.\n" {
			t.Errorf("apply with the new hash: exit %d", r.Code)
		}
	})

	t.Run("a drifted file makes plan --exit-code exit 2", func(t *testing.T) {
		if r := lab.Winch(t, dir, "plan", "site", "--exit-code"); r.Code != 0 {
			t.Errorf("plan without changes: exit %d", r.Code)
		}
		vm.MustRun(t, "echo drift > /etc/motd")
		r := lab.Winch(t, dir, "plan", "site", "--exit-code")
		if r.Code != 2 || !strings.Contains(r.Stdout, "~ file /etc/motd") {
			t.Errorf("plan with a drifted file: exit %d", r.Code)
		}
		if r := lab.Winch(t, dir, "apply", "site", "--check", hashOf(t, r.Stdout)); r.Code != 0 {
			t.Errorf("apply: exit %d", r.Code)
		}
		if r := lab.Winch(t, dir, "plan", "site", "--exit-code"); r.Code != 0 {
			t.Errorf("plan after apply: exit %d", r.Code)
		}
	})

	t.Run("SIGINT during a package install lets the install finish", func(t *testing.T) {
		vm.MustRun(t, "apt-get update -qq && rm -f /root/winch-wait.started /root/winch-wait.go /root/after")
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
			"inventories/test.yaml": "hosts:\n  approve:\n    address: 127.0.0.1\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - pkg:
          name: winch-wait
      - file:
          path: /root/after
          content: "after\n"
`,
		})
		w := startWinch(t, dir, "apply", "site", "--yes")
		vm.MustRun(t, "timeout 120 sh -c 'until [ -e /root/winch-wait.started ]; do sleep 0.2; done'")
		w.interrupt(t)
		time.Sleep(2 * time.Second)
		if w.exited() {
			t.Fatalf("winch ended during the install: %s", w.stderr.String())
		}
		vm.MustRun(t, "touch /root/winch-wait.go")
		code := w.wait(t)
		if code != 1 || !strings.Contains(w.stderr.String(), "approve: interrupted") {
			t.Errorf("exit %d, want 1 and the host interrupted", code)
		}
		if out := vm.MustRun(t, "dpkg-query -W -f='${db:Status-Abbrev}' winch-wait; test -e /root/after && echo after; true"); out != "ii " {
			t.Errorf("after the interrupt: %q, want winch-wait installed and no /root/after", out)
		}
		r := lab.Winch(t, dir, "plan", "site", "--exit-code")
		if r.Code != 2 || strings.Contains(r.Stdout, "winch-wait") || !strings.Contains(r.Stdout, "+ file /root/after") {
			t.Errorf("the next plan: exit %d, want only the file", r.Code)
		}
		if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
			t.Errorf("the next apply: exit %d", r.Code)
		}
	})

	t.Run("a second SIGINT ends winch, and the install finishes on the host", func(t *testing.T) {
		vm.MustRun(t, "dpkg --purge winch-wait >/dev/null; rm -f /root/winch-wait.started /root/winch-wait.go /root/after")
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
			"inventories/test.yaml": "hosts:\n  approve:\n    address: 127.0.0.1\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - pkg:\n          name: winch-wait\n",
		})
		w := startWinch(t, dir, "apply", "site", "--yes")
		vm.MustRun(t, "timeout 120 sh -c 'until [ -e /root/winch-wait.started ]; do sleep 0.2; done'")
		w.interrupt(t)
		time.Sleep(500 * time.Millisecond)
		w.interrupt(t)
		select {
		case <-w.done:
		case <-time.After(30 * time.Second):
			t.Fatal("winch did not end after the second interrupt")
		}
		if code := w.wait(t); code == 0 {
			t.Errorf("exit 0 after two interrupts")
		}
		vm.MustRun(t, "touch /root/winch-wait.go")
		// The helper ends after the install, and then frees the lock.
		vm.MustRun(t, "timeout 60 sh -c 'while pgrep -f ^/var/lib/winch/bin/ >/dev/null; do sleep 0.2; done'")
		if out := vm.MustRun(t, "dpkg -s winch-wait | grep ^Status"); out != "Status: install ok installed\n" {
			t.Errorf("winch-wait: %q", out)
		}
		if r := lab.Winch(t, dir, "plan", "site", "--exit-code"); r.Code != 0 {
			t.Errorf("the next plan: exit %d, want 0", r.Code)
		}
	})

	t.Run("a stopped VM gives exit 4", func(t *testing.T) {
		conf := filepath.Join(lab.Dir, "hosts", vm.Name+".conf")
		data, err := os.ReadFile(conf)
		if err != nil {
			t.Fatal(err)
		}
		vm.Stop()
		// Stop removes the SSH config of the VM; the port in it is now closed.
		if _, err := lab.WriteHost(vm.Name, string(data)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(conf) })
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 4 || !strings.Contains(r.Stderr, "approve: ") {
			t.Errorf("plan: exit %d", r.Code)
		}
	})
}

// winchProcess is winch running in its own process group, as in a terminal.
type winchProcess struct {
	cmd    *exec.Cmd
	stderr bytes.Buffer
	done   chan struct{}
	err    error
}

func startWinch(t *testing.T, dir string, args ...string) *winchProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	t.Cleanup(cancel)
	w := &winchProcess{done: make(chan struct{})}
	w.cmd = exec.CommandContext(ctx, os.Getenv("WINCH_BIN"), args...)
	w.cmd.Dir = dir
	w.cmd.Env = lab.Env()
	w.cmd.Stdout = &bytes.Buffer{}
	w.cmd.Stderr = &w.stderr
	w.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := w.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		w.err = w.cmd.Wait()
		close(w.done)
	}()
	return w
}

// interrupt sends SIGINT to the process group, as a Ctrl-C in a terminal
// does.
func (w *winchProcess) interrupt(t *testing.T) {
	t.Helper()
	if err := syscall.Kill(-w.cmd.Process.Pid, syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
}

func (w *winchProcess) exited() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

// wait returns the exit code.
func (w *winchProcess) wait(t *testing.T) int {
	<-w.done
	t.Logf("winch: %v\nstdout:\n%s\nstderr:\n%s", w.err, w.cmd.Stdout, w.stderr.String())
	if exit, ok := errors.AsType[*exec.ExitError](w.err); ok {
		return exit.ExitCode()
	}
	if w.err != nil {
		t.Errorf("winch: %v", w.err)
	}
	return 0
}

// unchanged reports whether out is the output of a plan of n hosts without
// changes.
func unchanged(out string, n int) bool {
	hosts := "1 host"
	if n > 1 {
		hosts = strconv.Itoa(n) + " hosts"
	}
	return regexp.MustCompile(`^` + hosts + `: 0 to change, ` + strconv.Itoa(n) + ` unchanged, 0 unknown\nplan [0-9a-f]{8}\n$`).MatchString(out)
}
