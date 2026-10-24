// Package session runs the helper on a host over OpenSSH.
package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

const StateDir = "/var/lib/winch"

type Config struct {
	// Host is the inventory name, for messages.
	Host     string
	Address  string
	User     string
	Dir      string
	Binaries []helperbin.Binary
	Hello    protocol.Hello
	Progress io.Writer
}

// Session is one ssh process with the helper at the other end.
type Session struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *limitedBuffer
	id     int

	waitOnce sync.Once
	waitErr  error
}

// wait closes stdin and waits for ssh to end.
func (s *Session) wait() error {
	s.waitOnce.Do(func() {
		s.stdin.Close()
		s.waitErr = s.cmd.Wait()
	})
	return s.waitErr
}

var archNames = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}

// Script returns the shell script that runs as root on the host. It picks the
// helper for the architecture, receives it when it is missing, and starts it.
// It prints "have", or "need <arch>" and then "got" after it received the
// helper. winch sends nothing else before "got", so head cannot read past the
// helper.
func Script(bins []helperbin.Binary, dir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "set -e\nd=%s\ncase $(uname -m) in\n", dir)
	for _, bin := range bins {
		fmt.Fprintf(&b, "%s) a=%s h=%s n=%d ;;\n", archNames[bin.Arch], bin.Arch, bin.SHA256, len(bin.Data))
	}
	b.WriteString(`*) echo "winch: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
b=$d/bin/$h
if [ -x "$b" ]; then
  echo have
else
  mkdir -p "$d/bin"
  chmod 700 "$d"
  t=$b.$$
  echo "need $a"
  head -c "$n" > "$t"
  set -- $(sha256sum "$t")
  if [ "$1" != "$h" ]; then rm -f "$t"; echo "winch: the helper has the wrong hash" >&2; exit 1; fi
  chmod 755 "$t"
  mv "$t" "$b"
  echo got
fi
exec "$b"
`)
	return b.String()
}

// command runs the script as root: directly for root, else with sudo -n.
func command(script string) string {
	return "s='" + script + `'; if [ "$(id -u)" -eq 0 ]; then exec sh -c "$s"; fi; ` +
		`sudo -n true 2>/dev/null || { echo "winch: the login user needs passwordless sudo" >&2; exit 1; }; ` +
		`exec sudo -n sh -c "$s"`
}

func Open(ctx context.Context, cfg Config) (*Session, error) {
	dir := cfg.Dir
	if dir == "" {
		dir = StateDir
	}
	args := []string{"-T", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15"}
	if cfg.User != "" {
		args = append(args, "-l", cfg.User)
	}
	args = append(args, "--", cfg.Address, command(Script(cfg.Binaries, dir)))
	cmd := exec.CommandContext(ctx, "ssh", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	s := &Session{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: &limitedBuffer{max: 64 << 10}}
	cmd.Stderr = s.stderr
	// A child of ssh, such as a ProxyCommand, can keep stderr open.
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ssh: %w", err)
	}
	if err := s.start(cfg); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) start(cfg Config) error {
	line, err := s.stdout.ReadString('\n')
	if err != nil {
		return s.fail(err)
	}
	line = strings.TrimSpace(line)
	if arch, ok := strings.CutPrefix(line, "need "); ok {
		i := slices.IndexFunc(cfg.Binaries, func(b helperbin.Binary) bool { return b.Arch == arch })
		if i < 0 {
			return fmt.Errorf("no helper for %s", arch)
		}
		fmt.Fprintf(cfg.Progress, "%s: sending the helper (%s)\n", cfg.Host, arch)
		if _, err := s.stdin.Write(cfg.Binaries[i].Data); err != nil {
			return s.fail(err)
		}
		if line, err = s.stdout.ReadString('\n'); err != nil {
			return s.fail(err)
		}
		if line = strings.TrimSpace(line); line != "got" {
			return fmt.Errorf("unexpected output from the host: %q", line)
		}
	} else if line != "have" {
		return fmt.Errorf("unexpected output from the host: %q", line)
	}
	return s.call("hello", cfg.Hello, nil)
}

// fail ends the session after err. The error output of ssh, when there is
// any, explains the failure better than err.
func (s *Session) fail(err error) error {
	waitErr := s.wait()
	if err == nil && waitErr == nil {
		return nil
	}
	if msg := strings.TrimSpace(s.stderr.String()); msg != "" {
		return errors.New(msg)
	}
	return fmt.Errorf("session: %w", errors.Join(err, waitErr))
}

func (s *Session) call(method string, params, result any) error {
	s.id++
	p, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := json.Marshal(protocol.Request{ID: s.id, Method: method, Params: p})
	if err != nil {
		return err
	}
	if _, err := s.stdin.Write(append(req, '\n')); err != nil {
		return s.fail(err)
	}
	line, err := s.stdout.ReadBytes('\n')
	if err != nil {
		return s.fail(err)
	}
	var resp protocol.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("bad response from the helper: %w", err)
	}
	if resp.ID != s.id {
		return fmt.Errorf("response %d to request %d", resp.ID, s.id)
	}
	if resp.NeedContent {
		return errNeedContent
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, result)
}

var errNeedContent = errors.New("the helper needs the content")

func withoutContent(m module.Module) module.Module {
	if c, ok := m.(module.WithContent); ok {
		return c.WithoutContent()
	}
	return m
}

// Check checks a step and updates st. It sends only the hash of the content.
func (s *Session) Check(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error) {
	return s.step("check", name, withoutContent(m), st)
}

// Apply checks a step again, makes its changes, and updates st. It sends the
// content only when the helper must write it.
func (s *Session) Apply(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error) {
	res, err := s.step("apply", name, withoutContent(m), st)
	if errors.Is(err, errNeedContent) {
		return s.step("apply", name, m, st)
	}
	return res, err
}

func (s *Session) step(method, name string, m module.Module, st *module.State) (module.Result, error) {
	args, err := json.Marshal(m)
	if err != nil {
		return module.Result{}, err
	}
	var res protocol.StepResult
	if err := s.call(method, protocol.Step{Module: name, Args: args, State: *st}, &res); err != nil {
		return module.Result{}, err
	}
	*st = res.State
	return res.Result, nil
}

// Close ends the helper and waits for ssh.
func (s *Session) Close() error {
	return s.fail(nil)
}

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
