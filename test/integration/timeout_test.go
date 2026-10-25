package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/session"
)

// spec: Remote execution/Sessions; Running a pipeline/Failures
func TestSilentAddressFails(t *testing.T) {
	t.Parallel()
	// The listener accepts connections and never sends the SSH banner. A
	// dropped SYN needs a firewall rule; ConnectTimeout covers both cases.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		var conns []net.Conn
		for {
			c, err := l.Accept()
			if err != nil {
				for _, c := range conns {
					c.Close() //nolint:errcheck // the test is over
				}
				return
			}
			conns = append(conns, c)
		}
	}()
	conf := filepath.Join(lab.Dir, "hosts", "silent.conf")
	host := fmt.Sprintf("Host silent\n  HostName 127.0.0.1\n  Port %d\n", l.Addr().(*net.TCPAddr).Port)
	if err := os.WriteFile(conf, []byte(host), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(conf) })
	dir := project(t, "hosts:\n  silent: {}\n")

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Getenv("WINCH_BIN"), "plan", "site")
	cmd.Dir = dir
	cmd.Env = lab.Env()
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	t.Logf("winch plan site: %v after %s\n%s", err, elapsed, out)
	if ctx.Err() != nil {
		t.Fatal("winch did not end within a minute")
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); !ok || exit.ExitCode() != 1 {
		t.Errorf("exit = %v, want 1", err)
	}
	if !strings.Contains(string(out), "silent:") || !strings.Contains(string(out), "timed out") {
		t.Errorf("output does not name the host and the timeout")
	}
	if elapsed < 10*time.Second || elapsed > 25*time.Second {
		t.Errorf("winch ended after %s, want about 15s", elapsed)
	}
}

// spec: Remote execution/Sessions; Remote execution/Helper
func TestFrozenHostFails(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "frozen")
	s := vm.Session(t)
	if err := vm.Freeze(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vm.Thaw() }) //nolint:errcheck // Stop kills the VM next

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := s.Check(t.Context(), "file", &module.File{Path: "/etc/hostname"}, &module.State{})
		done <- err
	}()
	select {
	case err := <-done:
		elapsed := time.Since(start)
		t.Logf("check: %v after %s", err, elapsed)
		// ssh ends after four keepalives without an answer. The lab's
		// LogLevel ERROR hides its message.
		if err == nil {
			t.Error("check on a frozen host succeeded")
		}
		if elapsed > 75*time.Second {
			t.Errorf("check ended after %s, want about 60s", elapsed)
		}
	case <-time.After(2 * time.Minute):
		t.Fatal("check on a frozen host did not end within 2 minutes")
	}

	// The helper on the host ends when the host runs again, and frees the
	// lock.
	if err := vm.Thaw(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		s, err := session.Open(t.Context(), session.Config{
			Host:     vm.Name,
			Address:  vm.Name,
			Binaries: helperbin.Binaries(),
			Hello:    protocol.Hello{Run: "test-after-thaw", User: "test", Machine: "test"},
			Progress: &strings.Builder{},
		})
		if err == nil {
			s.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("open after thaw: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}
