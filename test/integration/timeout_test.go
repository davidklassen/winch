package integration

import (
	"bufio"
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

// spec: Remote execution/Sessions
func TestMaxStartupsRetry(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "startups")
	// The helper is on the VM, so a later Open does not spend time on the
	// upload.
	vm.Session(t).Close()
	// Failed polls during the boot can add a penalty that drops new
	// connections too.
	vm.MustRun(t, "printf 'MaxStartups 1\\nPerSourcePenalties no\\n' > /etc/ssh/sshd_config.d/startups.conf && systemctl reload ssh")
	// The lab's LogLevel ERROR hides the message of a closed connection.
	conf := filepath.Join(lab.Dir, "hosts", vm.Name+".conf")
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, append(data, "  LogLevel INFO\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(string(data[strings.Index(string(data), "Port "):]), "Port %d", &port); err != nil {
		t.Fatal(err)
	}

	// An unauthenticated connection holds the only startup slot. sshd
	// refuses connections for a moment after the reload.
	var hold net.Conn
	for deadline := time.Now().Add(10 * time.Second); ; {
		hold, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			if _, err = bufio.NewReader(hold).ReadString('\n'); err == nil {
				break
			}
			hold.Close() //nolint:errcheck // the next try opens a new one
		}
		if time.Now().After(deadline) {
			t.Fatalf("hold a startup slot: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer hold.Close() //nolint:errcheck // the test is over
	out, err := exec.CommandContext(t.Context(), "ssh", vm.Name, "true").CombinedOutput()
	t.Logf("ssh while the slot is held: %v\n%s", err, out)
	if exit, ok := errors.AsType[*exec.ExitError](err); !ok || exit.ExitCode() != 255 || !strings.Contains(string(out), "Connection closed by") {
		t.Fatalf("exit = %v, want 255 and a closed connection", err)
	}

	time.AfterFunc(time.Second, func() { hold.Close() }) //nolint:errcheck // the slot is free either way
	start := time.Now()
	s, err := session.Open(t.Context(), session.Config{
		Host:     vm.Name,
		Address:  vm.Name,
		Binaries: helperbin.Binaries(),
		Hello:    protocol.Hello{Run: "test-max-startups", User: "test", Machine: "test"},
		Progress: &strings.Builder{},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("open after %s: %v", elapsed, err)
	}
	s.Close()
	if elapsed < 2*time.Second {
		t.Errorf("open took %s, want the 2s wait before the retry", elapsed)
	}
	// sshd dropped the probe and the first start of Open.
	// The output starts with the host key warning of LogLevel INFO.
	out = []byte(vm.MustRun(t, "journalctl -u ssh --no-pager -o cat | grep -c 'drop connection.*Maxstartups' || true"))
	if f := strings.Fields(string(out)); len(f) == 0 || f[len(f)-1] != "2" {
		t.Errorf("sshd dropped connections: %q, want 2", out)
	}
}
