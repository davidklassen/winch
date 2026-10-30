package integration

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/session"
	"github.com/davidklassen/winch/internal/vmtest"
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
	t.Cleanup(func() { l.Close() })
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
	// The jump host is the silent address. ssh does not pass ConnectTimeout
	// to the ssh of the jump.
	conf, err := lab.WriteHost("silent", fmt.Sprintf("Host silent\n  HostName 127.0.0.1\n  Port %d\nHost silentjump\n  HostName 127.0.0.1\n  ProxyJump silent\n", l.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(conf) })

	for _, host := range []string{"silent", "silentjump"} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			dir := project(t, "hosts:\n  "+host+": {}\n")
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
			if exit, ok := errors.AsType[*exec.ExitError](err); !ok || exit.ExitCode() != 4 {
				t.Errorf("exit = %v, want 4", err)
			}
			if !strings.Contains(string(out), host+":") || !strings.Contains(string(out), "timed out") {
				t.Errorf("output does not name the host and the timeout")
			}
			if elapsed < 10*time.Second || elapsed > 25*time.Second {
				t.Errorf("winch ended after %s, want about 15s", elapsed)
			}
		})
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
			Progress: color.NewWriter(io.Discard, secret.NewFilter().Parts, false),
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
	// connections too. A reload returns before sshd reads the config, and a
	// connection to the old sshd does not count as a startup of the new one.
	// The sshd of Ubuntu 24.04 has no penalties. The sshd of Ubuntu 26.04
	// exits when a connection comes while all of MaxStartups 1 is in use; a
	// full limit of 2 keeps it running and drops the second startup.
	vm.MustRun(t, "{ echo 'MaxStartups 1:100:2'; if sshd -T | grep -q '^persourcepenalties '; then echo 'PerSourcePenalties no'; fi; } > /etc/ssh/sshd_config.d/startups.conf && systemctl restart ssh")
	data, err := os.ReadFile(filepath.Join(lab.Dir, "hosts", vm.Name+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(string(data[strings.Index(string(data), "Port "):]), "Port %d", &port); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// The test counts the ssh starts of Open at a proxy. sshd's log of drops
	// can also hold a connection of a boot poll that QEMU delivers late.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	// The end of the third connection, the first start of the second Open,
	// frees the startup slot.
	var starts atomic.Int32
	release := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n := starts.Add(1)
			go func() {
				defer c.Close() //nolint:errcheck // the copy is over
				vc, err := net.Dial("tcp", addr)
				if err != nil {
					t.Errorf("proxy: %v", err)
					return
				}
				sent := make(chan struct{})
				go func() {
					io.Copy(vc, c)         //nolint:errcheck // the close ends the other copy
					vc.Close()             //nolint:errcheck // the copy is over
					io.Copy(io.Discard, c) //nolint:errcheck // a failed write to sshd leaves data in c
					close(sent)
				}()
				io.Copy(c, vc) //nolint:errcheck // ssh sees the end and closes c
				if n == 3 {
					close(release)
				}
				// A close of c with unread data from ssh sends a reset, not
				// the close of sshd.
				c.(*net.TCPConn).CloseWrite() //nolint:errcheck // the close of c follows
				<-sent
			}()
		}
	}()
	// The lab's LogLevel ERROR hides the message of a closed connection.
	proxy := vm.Name + "-proxy"
	conf, err := lab.WriteHost(proxy, fmt.Sprintf("Host %s\n  HostName 127.0.0.1\n  Port %d\n  LogLevel INFO\n", proxy, l.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(conf) })

	// An unauthenticated connection holds the only startup slot. sshd can
	// refuse or drop a try for a moment after the restart.
	var hold net.Conn
	for deadline := time.Now().Add(10 * time.Second); ; {
		hold, err = net.Dial("tcp", addr)
		if err == nil {
			var line string
			// sshd answers a dropped connection with a line too.
			if line, err = bufio.NewReader(hold).ReadString('\n'); err == nil && strings.HasPrefix(line, "SSH-") {
				break
			}
			if err == nil {
				err = fmt.Errorf("sshd answered %q", line)
			}
			hold.Close() //nolint:errcheck // the next try opens a new one
		}
		if time.Now().After(deadline) {
			t.Fatalf("hold a startup slot: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer hold.Close() //nolint:errcheck // the test is over
	open := func() (time.Duration, error) {
		start := time.Now()
		s, err := session.Open(t.Context(), session.Config{
			Host:     proxy,
			Address:  proxy,
			Binaries: helperbin.Binaries(),
			Hello:    protocol.Hello{Run: "test-max-startups", User: "test", Machine: "test"},
			Progress: color.NewWriter(io.Discard, secret.NewFilter().Parts, false),
		})
		if err == nil {
			s.Close()
		}
		return time.Since(start), err
	}

	elapsed, err := open()
	t.Logf("open while the slot is held: %v after %s", err, elapsed)
	if err == nil || !strings.Contains(err.Error(), "Connection closed by") {
		t.Fatalf("error = %v, want a closed connection", err)
	}
	if n := starts.Load(); n != 2 {
		t.Errorf("open while the slot is held started ssh %d times, want 2", n)
	}

	go func() {
		<-release
		hold.Close() //nolint:errcheck // the slot is free either way
	}()
	elapsed, err = open()
	if err != nil {
		t.Fatalf("open after %s: %v", elapsed, err)
	}
	if elapsed < 2*time.Second {
		t.Errorf("open took %s, want the 2s wait before the retry", elapsed)
	}
	if n := starts.Load() - 2; n != 2 {
		t.Errorf("open started ssh %d times, want 2", n)
	}
}

// spec: Remote execution/Sessions
func TestCloseAfterBannerRetry(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "banner-close")
	data, err := os.ReadFile(filepath.Join(lab.Dir, "hosts", vm.Name+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(string(data[strings.Index(string(data), "Port "):]), "Port %d", &port); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// The proxy closes its first connection after sshd's banner, as sshd does
	// while it executes itself again after a reload. The lab's LogLevel ERROR
	// hides ssh's message, so ssh exits 255 with no output.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var starts atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n := starts.Add(1)
			go func() {
				defer c.Close() //nolint:errcheck // the copy is over
				vc, err := net.Dial("tcp", addr)
				if err != nil {
					t.Errorf("proxy: %v", err)
					return
				}
				defer vc.Close() //nolint:errcheck // the copy is over
				if n == 1 {
					banner, err := bufio.NewReader(vc).ReadString('\n')
					if err != nil {
						t.Errorf("proxy: read the banner: %v", err)
						return
					}
					c.Write([]byte(banner))       //nolint:errcheck // ssh sees the close either way
					c.(*net.TCPConn).CloseWrite() //nolint:errcheck // the close of c follows
					io.Copy(io.Discard, c)        //nolint:errcheck // ssh closes c
					return
				}
				go func() {
					io.Copy(vc, c) //nolint:errcheck // the close ends the other copy
					vc.Close()     //nolint:errcheck // the copy is over
				}()
				io.Copy(c, vc) //nolint:errcheck // ssh sees the end and closes c
			}()
		}
	}()
	proxy := vm.Name + "-proxy"
	conf, err := lab.WriteHost(proxy, fmt.Sprintf("Host %s\n  HostName 127.0.0.1\n  Port %d\n", proxy, l.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(conf) })

	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  " + proxy + ": {}\n",
		"pipelines/site.yaml": `stages:
  - name: one
    hosts: all
    steps:
      - file:
          path: /tmp/wt
          content: "x\n"
`,
	})
	start := time.Now()
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 {
		t.Fatalf("plan: exit %d: %s", r.Code, r.Stderr)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Errorf("plan took %s, want the 2s wait before the retry", elapsed)
	}
	if n := starts.Load(); n != 2 {
		t.Errorf("plan started ssh %d times, want 2", n)
	}
}
