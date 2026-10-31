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
	"net"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
)

const StateDir = "/var/lib/winch"

// ErrUnreachable is the cause of a failed connect when ssh fails before the
// script on the host starts: no route, a timeout, a host key, or a refused
// login.
var ErrUnreachable = errors.New("unreachable")

// unreachable marks an error so that errors.Is finds ErrUnreachable. Its text
// stays the same.
type unreachable struct{ error }

func (unreachable) Is(target error) bool { return target == ErrUnreachable }

func (u unreachable) Unwrap() error { return u.error }

type Config struct {
	// Host is the inventory name and the ssh target. An Address that differs
	// from it becomes the HostName.
	Host     string
	Address  string
	User     string
	Dir      string
	Binaries []helperbin.Binary
	Hello    protocol.Hello
	Progress *color.Writer
	// Hold is nil, or hides the progress until the function it returns runs.
	// It covers the login, where ssh can ask a question on the terminal.
	Hold func() func()
	// RetryDelay is the wait before another ssh start: the retry of a
	// dropped connection, and each connect after a reboot. Zero means 2s.
	RetryDelay time.Duration
	// Batch makes ssh ask no questions. A check of the access and a
	// reconnect after a reboot always set it: they can run on several hosts
	// at once.
	Batch bool
	// Want is nil, or the destination of the plan. A login fails before it
	// starts when ssh resolves another host name, port, or jump host, and
	// after the hello when the login user differs. A check of the access and
	// a reconnect after a reboot want the destination of their session.
	Want *protocol.Destination
}

// Session is one ssh process with the helper at the other end.
type Session struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   *bufio.Reader
	stderr   *limitedBuffer
	id       int
	host     string
	progress *color.Writer
	// cfg and ctx are those of Open: a check of the access and a reboot
	// open more connections.
	cfg        Config
	ctx        context.Context
	dest       protocol.Destination
	prompted   bool
	newHostKey bool

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
// helper for the architecture, receives it when it is missing or has another
// hash, and starts it with the script's first argument.
// It prints "have", or "need <arch>" and then "got" after it received the
// helper. winch sends nothing else before "got", so head cannot read past the
// helper.
func Script(bins []helperbin.Binary, dir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "set -e\nc=$1\nd=%s\ncase $(uname -m) in\n", dir)
	for _, bin := range bins {
		fmt.Fprintf(&b, "%s) a=%s h=%s n=%d ;;\n", archNames[bin.Arch], bin.Arch, bin.SHA256, len(bin.Data))
	}
	b.WriteString(`*) echo "winch: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
mkdir -p -m 700 "$d" "$d/bin"
b=$d/bin/$h
for p in "$d/" "$d/bin/" "$b"; do
  [ -e "$p" ] || continue
  set -- $(ls -ldn "$p")
  case $1 in
  [!d-]*) echo "winch: ${p%/} is not a directory or a regular file" >&2; exit 1 ;;
  ?????[!w]??[!w]*) [ "$3" = 0 ] && continue ;;
  esac
  echo "winch: ${p%/} is not owned by root, or the group or others can write it" >&2; exit 1
done
if [ -x "$b" ] && [ "$(sha256sum < "$b")" = "$h  -" ]; then
  echo have
else
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
exec "$b" "$c"
`)
	return b.String()
}

// command runs the script as root: directly for root, else with sudo -n. The
// script gets SSH_CONNECTION as its argument, since sudo removes it from the
// environment.
func command(script string) string {
	return "s='" + script + `'; if [ "$(id -u)" -eq 0 ]; then exec sh -c "$s" sh "$SSH_CONNECTION"; fi; ` +
		`e=$(sudo -n true 2>&1) || { printf "winch: the login user needs passwordless sudo%s\n" "${e:+: $e}" >&2; exit 1; }; ` +
		`exec sudo -n sh -c "$s" sh "$SSH_CONNECTION"`
}

// Open starts ssh and the helper. When the host closes the connection before
// the SSH handshake, as a busy sshd does at its MaxStartups limit, Open starts
// ssh once more after RetryDelay. It does not retry another failure in batch
// mode, so a retry never counts as a second failed login.
//
// Without Batch, Open logs in with BatchMode=yes first, so it learns whether
// the access check can log in. Only after a refused login or an unknown host
// key does it log in again, and ssh may ask. ssh checks the host key before
// the login, so after a new host key only Prompted tells about the login.
func Open(ctx context.Context, cfg Config) (*Session, error) {
	r, err := resolve(ctx, cfg)
	if err != nil {
		return nil, err
	}
	batch := cfg
	batch.Batch = true
	s, exit, err := dial(ctx, batch)
	if !exit.started && Dropped(exit.code, exit.stderr, r.logLevel) {
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(cfg.retryDelay()):
		}
		s, exit, err = dial(ctx, batch)
	}
	login := strings.Contains(exit.stderr, "Permission denied (")
	// A changed host key is no question that ssh asks.
	hostKey := strings.Contains(exit.stderr, "Host key verification failed.") && !strings.Contains(exit.stderr, "HAS CHANGED")
	if err != nil && !cfg.Batch && (login || hostKey) {
		s, _, err = dial(ctx, cfg)
	}
	if err != nil {
		return nil, err
	}
	s.prompted, s.newHostKey = login, hostKey && !login
	s.dest.HostName, s.dest.Port, s.dest.Jump = r.hostName, r.port, r.jump
	if err := s.changed(cfg.Want); err != nil {
		return nil, err
	}
	return s, nil
}

// changed ends s and returns an error when want is not nil and the
// destination of s differs from it.
func (s *Session) changed(want *protocol.Destination) error {
	if want == nil || s.dest == *want {
		return nil
	}
	s.Close() //nolint:errcheck // the host fails already
	return DestinationChanged(*want, s.dest)
}

// DestinationChanged is the error of a login whose destination differs from
// the plan's.
func DestinationChanged(old, now protocol.Destination) error {
	return fmt.Errorf("the SSH destination changed since the plan: %s → %s; run winch plan again and check the new destination", destination(old), destination(now))
}

func destination(d protocol.Destination) string {
	s := fmt.Sprintf("%s (uid %d)", net.JoinHostPort(d.HostName, d.Port), d.UID)
	if d.User != "" {
		s = d.User + "@" + s
	}
	if d.Jump != "" {
		s += " through " + d.Jump
	}
	return s
}

// Resolve returns the host name, the port, and the jump host that ssh
// resolves for the host of cfg. The jump host is the ProxyJump or the
// ProxyCommand, or empty.
func Resolve(ctx context.Context, cfg Config) (hostName, port, jump string, err error) {
	r, err := resolve(ctx, cfg)
	return r.hostName, r.port, r.jump, err
}

type resolved struct {
	hostName, port, jump, user, logLevel string
}

// resolve reads the SSH config of the host of cfg with ssh -G. It fails when
// the host name, port, or jump host differs from cfg.Want.
func resolve(ctx context.Context, cfg Config) (resolved, error) {
	out, err := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, argv(cfg)...)...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			err = errors.New(strings.TrimSpace(string(exit.Stderr)))
		}
		return resolved{}, fmt.Errorf("read the SSH config: %w", err)
	}
	var r resolved
	for line := range strings.Lines(string(out)) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch key {
		case "hostname":
			r.hostName = value
		case "port":
			r.port = value
		case "proxyjump", "proxycommand":
			r.jump = value
		case "user":
			r.user = value
		case "loglevel":
			r.logLevel = value
		}
	}
	if w := cfg.Want; w != nil && (r.hostName != w.HostName || r.port != w.Port || r.jump != w.Jump) {
		now := *w
		now.HostName, now.Port, now.Jump = r.hostName, r.port, r.jump
		return r, DestinationChanged(*w, now)
	}
	return r, nil
}

// argv returns the arguments of ssh for the host of cfg, up to the target.
func argv(cfg Config) []string {
	args := []string{"-T", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
		"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "RemoteCommand=none", "-o", "PermitLocalCommand=no",
		"-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no"}
	if cfg.Batch {
		args = append(args, "-o", "BatchMode=yes")
	}
	// The host name stays the target, so the Host blocks of the SSH config
	// match it. ssh expands % tokens in HostName.
	if cfg.Address != cfg.Host {
		args = append(args, "-o", "HostName="+strings.ReplaceAll(cfg.Address, "%", "%%"))
	}
	if cfg.User != "" {
		args = append(args, "-l", cfg.User)
	}
	return append(args, "--", cfg.Host)
}

// sshExit is how ssh ended after a failed dial.
type sshExit struct {
	code   int
	stderr string
	// started is true when the script on the host printed its first line.
	started bool
}

// dial starts ssh and the helper. When it fails after ssh started, it also
// returns how ssh ended.
func dial(ctx context.Context, cfg Config) (*Session, sshExit, error) {
	dir := cfg.Dir
	if dir == "" {
		dir = StateDir
	}
	args := append(argv(cfg), command(Script(cfg.Binaries, dir)))
	// ssh keeps an ignored SIGINT ignored, so a Ctrl-C in the terminal reaches
	// only winch. ssh stays in the terminal's process group and can still ask
	// for a host key or a passphrase.
	cmd := exec.CommandContext(ctx, "sh", append([]string{"-c", `trap "" INT; exec ssh "$@"`, "ssh"}, args...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, sshExit{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, sshExit{}, err
	}
	s := &Session{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: &limitedBuffer{max: 64 << 10}, host: cfg.Host, progress: cfg.Progress, cfg: cfg, ctx: ctx}
	cmd.Stderr = s.stderr
	// A child of ssh, such as a ProxyCommand, can keep stderr open.
	cmd.WaitDelay = 5 * time.Second
	resume := func() {}
	if cfg.Hold != nil {
		resume = cfg.Hold()
	}
	if err := cmd.Start(); err != nil {
		resume()
		return nil, sshExit{}, fmt.Errorf("start ssh: %w", err)
	}
	line, err := s.stdout.ReadString('\n')
	resume()
	if err != nil {
		err = s.fail(err)
		if s.cmd.ProcessState.ExitCode() == 255 {
			err = unreachable{hint(cfg, err)}
		}
		return nil, s.exit(), err
	}
	if err := s.start(cfg, strings.TrimSpace(line)); err != nil {
		// ssh can block on a full pipe, or the host can print without end.
		_ = cmd.Process.Kill()
		s.Close()
		exit := s.exit()
		exit.started = true
		return nil, exit, err
	}
	return s, sshExit{}, nil
}

// hint adds to err, an error of ssh in batch mode, how to answer the question
// that ssh could not ask: a new host key, or a key passphrase or a password.
func hint(cfg Config, err error) error {
	msg := err.Error()
	switch {
	case !cfg.Batch:
		return err
	case strings.Contains(msg, "Permission denied ("):
		return fmt.Errorf("%w (batch mode cannot type a passphrase or a password; if the key needs one, add it to the agent with ssh-add)", err)
	// A changed host key is no question that ssh asks.
	case strings.Contains(msg, "HAS CHANGED") || !strings.Contains(msg, "Host key verification failed"):
		return err
	}
	cmd := "ssh"
	if cfg.Address != cfg.Host {
		cmd += " -o HostName=" + cfg.Address
	}
	if cfg.User != "" {
		cmd += " -l " + cfg.User
	}
	return fmt.Errorf("%w (in batch mode ssh asks nothing; accept the host key once with: %s %s)", err, cmd, cfg.Host)
}

func (s *Session) exit() sshExit {
	return sshExit{code: s.cmd.ProcessState.ExitCode(), stderr: s.stderr.String()}
}

// Dropped reports whether ssh exited with code and stderr after the host
// closed or reset the connection before the SSH handshake. Each line of the
// error output must say so. Another line, such as a refused login on a jump
// host before the close of the proxy, means that the host did more than drop
// the connection. No output counts at log level ERROR only: ssh then prints
// nothing for a close after the banner, as sshd does while it executes itself
// again after a reload, but it prints a refused login. At QUIET, it prints
// nothing for a refused login either.
func Dropped(code int, stderr, logLevel string) bool {
	if code != 255 {
		return false
	}
	out := strings.TrimSpace(stderr)
	if out == "" {
		return logLevel == "ERROR"
	}
	for line := range strings.Lines(out) {
		if !droppedLine(strings.TrimSpace(line)) {
			return false
		}
	}
	return true
}

// droppedLine reports whether line is one that OpenSSH prints for a close or
// a reset before the handshake. The "kex_exchange_identification:" lines show
// at log level ERROR, the others at INFO.
func droppedLine(line string) bool {
	if kex, ok := strings.CutPrefix(line, "kex_exchange_identification: "); ok {
		return kex == "Connection closed by remote host" || kex == "read: Connection reset by peer"
	}
	return strings.HasPrefix(line, "Connection closed by ") || strings.HasPrefix(line, "Connection reset by ")
}

func (s *Session) start(cfg Config, line string) error {
	if arch, ok := strings.CutPrefix(line, "need "); ok {
		i := slices.IndexFunc(cfg.Binaries, func(b helperbin.Binary) bool { return b.Arch == arch })
		if i < 0 {
			return fmt.Errorf("no helper for %s", arch)
		}
		fmt.Fprintf(cfg.Progress, "%s: sending the helper (%s)\n", cfg.Host, arch)
		if _, err := s.stdin.Write(cfg.Binaries[i].Data); err != nil {
			return s.fail(err)
		}
		got, err := s.stdout.ReadString('\n')
		if err != nil {
			return s.fail(err)
		}
		if got = strings.TrimSpace(got); got != "got" {
			return fmt.Errorf("unexpected output from the host: %q", got)
		}
	} else if line != "have" {
		return s.printed(line)
	}
	var w protocol.Welcome
	if err := s.call("hello", cfg.Hello, &w); err != nil {
		return err
	}
	s.dest.User, s.dest.UID = w.Login, w.LoginUID
	return nil
}

// printed returns the error of a login that printed line before the script.
// When the login ends without a line of the script and without error output,
// another command than winch's printed line.
func (s *Session) printed(line string) error {
	shell := func(text string) error {
		return fmt.Errorf("the login shell printed %q before winch started; remove it from the shell startup files, such as ~/.bashrc", text)
	}
	// Text without a newline comes before the line of the script.
	for _, end := range []string{"have", "need amd64", "need arm64"} {
		if before, ok := strings.CutSuffix(line, end); ok {
			return shell(before)
		}
	}
	text := line
	for n := len(line); n < 4<<10; {
		next, err := s.stdout.ReadSlice('\n')
		n += len(next)
		got := strings.TrimSpace(string(next))
		if got == "have" || strings.HasPrefix(got, "need ") {
			break
		}
		if got != "" {
			text += "\n" + got
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			s.wait() //nolint:errcheck // the error output tells more than the exit
			if strings.TrimSpace(s.stderr.String()) == "" {
				return notRun(text)
			}
			break
		}
	}
	return shell(line)
}

// notRun is the error of a login that printed text and did not run winch's
// command.
func notRun(text string) error {
	return fmt.Errorf("the login did not run winch's command; a command= line in authorized_keys or a nologin shell prints this: %s", text)
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
	if err := s.send(method, params); err != nil {
		return err
	}
	return s.receive(result)
}

func (s *Session) send(method string, params any) error {
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
	return nil
}

func (s *Session) receive(result any) error {
	var resp protocol.Response
	for {
		line, err := s.stdout.ReadBytes('\n')
		if err != nil {
			return s.fail(err)
		}
		resp = protocol.Response{}
		if err := json.Unmarshal(line, &resp); err != nil {
			return fmt.Errorf("bad response from the helper: %w", err)
		}
		if resp.ID != s.id {
			return fmt.Errorf("response %d to request %d", resp.ID, s.id)
		}
		if resp.Note == "" {
			break
		}
		fmt.Fprintf(s.progress, "%s: %s\n", s.host, secret.Printable(resp.Note))
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

func (s *Session) Facts(ctx context.Context) (facts.Facts, error) {
	var f facts.Facts
	err := s.call("facts", nil, &f)
	return f, err
}

// Check checks a step and updates st. It sends only the hash of the content.
func (s *Session) Check(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error) {
	return s.step("check", withoutContent(m), protocol.Step{Module: name, State: *st}, st)
}

// Apply checks a step again, makes its changes, and updates st. It sends the
// content only when the helper must write it.
func (s *Session) Apply(ctx context.Context, name string, m module.Module, st *module.State, notify []string, then *protocol.Then, check *protocol.Check, guard protocol.Guard) (module.Result, error) {
	step := protocol.Step{Module: name, State: *st, Notify: notify, Then: then, Check: check, Guard: guard}
	res, err := s.step("apply", withoutContent(m), step, st)
	if errors.Is(err, errNeedContent) {
		return s.step("apply", m, step, st)
	}
	return res, err
}

const accessMarker = "winch-access"

// accessCommand runs the marker the way the session start runs its script, so
// it proves what the next session needs.
var accessCommand = command("echo " + accessMarker)

// Access opens a new SSH connection to the host and runs a command that needs the login and sudo.
// Like the session start, it fails when the login prints to stdout.
func (s *Session) Access(ctx context.Context) error {
	cfg := s.cfg
	cfg.Batch, cfg.Want = true, &s.dest
	r, err := resolve(ctx, cfg)
	if err != nil {
		return err
	}
	// This login has no hello, so ssh's user stands for the login user. The
	// helper may not know the name of the login user, as for an LDAP account.
	if s.dest.User != "" && r.user != s.dest.User {
		now := s.dest
		now.User = r.user
		return DestinationChanged(s.dest, now)
	}
	cmd := exec.CommandContext(ctx, "sh", append([]string{"-c", `trap "" INT; exec ssh "$@"`, "ssh"}, append(argv(cfg), accessCommand)...)...)
	stdout, stderr := &limitedBuffer{max: 4 << 10}, &limitedBuffer{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	msg := strings.TrimSpace(stderr.String())
	extra, ok := strings.CutSuffix(stdout.String(), accessMarker+"\n")
	extra = strings.TrimSpace(extra)
	switch {
	// Open logged in without a prompt, so the change refuses the login.
	case err != nil && strings.Contains(msg, "Permission denied ("):
		return fmt.Errorf("the access check cannot log in after this change: %s", msg)
	case err != nil && msg != "":
		return hint(cfg, errors.New(msg))
	case !ok && extra != "":
		return notRun(extra)
	case err != nil:
		return err
	case !ok:
		return errors.New("the login did not run winch's command")
	case extra != "":
		return fmt.Errorf("the login shell printed %q; remove it from the shell startup files, such as ~/.bashrc", extra)
	}
	return nil
}

// Confirm stops the rollback timer on the host.
func (s *Session) Confirm(ctx context.Context) error {
	return s.call("confirm", nil, nil)
}

// Rollback ends the rollback timer on the host at once: the old files come
// back.
func (s *Session) Rollback(ctx context.Context) error {
	return s.call("rollback", nil, nil)
}

// Reboot reboots the host, and connects again until the host has a new boot
// ID, within wait. It then waits for the system to start, within the same
// time.
func (s *Session) Reboot(ctx context.Context, wait time.Duration) (protocol.Boot, error) {
	deadline := time.Now().Add(wait)
	var id string
	if err := s.call("reboot", nil, &id); err != nil {
		return protocol.Boot{}, err
	}
	// The helper ends when its input closes, before the reboot.
	s.Close() //nolint:errcheck // the reboot ends the connection
	cfg := s.cfg
	cfg.Batch, cfg.Hold = true, nil
	cfg.Hello.Resume = true
	cfg.Want = &s.dest
	last := errors.New("no connection yet")
	for {
		select {
		case <-s.ctx.Done():
			return protocol.Boot{}, s.ctx.Err()
		case <-time.After(cfg.retryDelay()):
		}
		if time.Now().After(deadline) {
			return protocol.Boot{}, fmt.Errorf("the host did not come back within %s: %w", wait, last)
		}
		r, err := resolve(s.ctx, cfg)
		if err != nil {
			return protocol.Boot{}, err
		}
		n, exit, err := dial(s.ctx, cfg)
		if err != nil {
			if refused(exit.stderr) {
				return protocol.Boot{}, fmt.Errorf("connect after the reboot: %w", err)
			}
			last = err
			continue
		}
		n.dest.HostName, n.dest.Port, n.dest.Jump = r.hostName, r.port, r.jump
		if err := n.changed(cfg.Want); err != nil {
			return protocol.Boot{}, err
		}
		var b protocol.Boot
		if err := n.call("booted", protocol.Booted{Old: id, Wait: time.Until(deadline)}, &b); err != nil {
			n.Close() //nolint:errcheck // the call failed already
			last = err
			continue
		}
		if b.RebootError != "" {
			n.Close() //nolint:errcheck // the step fails already
			return protocol.Boot{}, fmt.Errorf("the reboot command failed: %s", b.RebootError)
		}
		if b.Same {
			n.Close() //nolint:errcheck // the next connect tries again
			last = errors.New("the host has not rebooted yet")
			continue
		}
		s.cmd, s.stdin, s.stdout, s.stderr, s.id = n.cmd, n.stdin, n.stdout, n.stderr, n.id
		s.waitOnce, s.waitErr = sync.Once{}, nil
		if b.State != "running" && b.State != "degraded" {
			return b, fmt.Errorf("the host did not start within %s: systemctl is-system-running says %s", wait, b.State)
		}
		return b, nil
	}
}

// refused reports whether the error output of ssh shows a refused login or
// host key. Another try fails the same way, and OpenSSH's PerSourcePenalties
// count each refused login. A pam_nologin refusal while the host boots shows
// no such line: ssh prints the text of /run/nologin, or nothing at log level
// ERROR, and "Connection closed".
func refused(stderr string) bool {
	return strings.Contains(stderr, "Permission denied (") ||
		strings.Contains(stderr, "Too many authentication failures") ||
		strings.Contains(stderr, "Host key verification failed.")
}

func (cfg Config) retryDelay() time.Duration {
	if cfg.RetryDelay == 0 {
		return 2 * time.Second
	}
	return cfg.RetryDelay
}

func (s *Session) Pending(ctx context.Context) (protocol.Pending, error) {
	var p protocol.Pending
	err := s.call("pending", nil, &p)
	return p, err
}

func (s *Session) Handled(ctx context.Context, handler string) error {
	return s.call("handled", protocol.Handled{Name: handler}, nil)
}

// Pend records a pending health gate or assert on the host.
func (s *Session) Pend(ctx context.Context, c protocol.Check) error {
	return s.call("pend", c, nil)
}

// Passed removes the record of a health gate or assert.
func (s *Session) Passed(ctx context.Context, c protocol.Check) error {
	return s.call("passed", c, nil)
}

// DropThen removes the record of a then that matches no step.
func (s *Session) DropThen(ctx context.Context, t protocol.Then) error {
	return s.call("dropthen", t, nil)
}

// Command runs the command of a then as root on the host, and then removes
// the records that match it.
func (s *Session) Command(ctx context.Context, command string, then protocol.Then) error {
	return s.call("command", protocol.Command{Command: command, Then: then}, nil)
}

// Health runs a health gate on the host, and then removes its record.
func (s *Session) Health(ctx context.Context, h protocol.Health) error {
	return s.call("health", h, nil)
}

// Exec runs a command of winch exec as root on the host. When ctx ends, it
// closes the input of the helper, and the helper stops the command.
func (s *Session) Exec(ctx context.Context, command string) (module.ExecResult, error) {
	var res module.ExecResult
	if err := s.send("exec", protocol.Exec{Command: command}); err != nil {
		return res, err
	}
	defer context.AfterFunc(ctx, func() { s.stdin.Close() })()
	err := s.receive(&res)
	return res, err
}

// step sends the step with the arguments m, and updates st.
func (s *Session) step(method string, m module.Module, step protocol.Step, st *module.State) (module.Result, error) {
	var err error
	if step.Args, err = json.Marshal(m); err != nil {
		return module.Result{}, err
	}
	var res protocol.StepResult
	if err := s.call(method, step, &res); err != nil {
		return module.Result{}, err
	}
	*st = res.State
	return res.Result, nil
}

func (s *Session) Destination() protocol.Destination { return s.dest }

// Prompted reports whether the login needed a prompt. After a login that
// accepted a new host key, it runs the access check once to find out.
func (s *Session) Prompted(ctx context.Context) bool {
	if s.newHostKey {
		s.newHostKey = false
		err := s.Access(ctx)
		s.prompted = err != nil && strings.Contains(err.Error(), "Permission denied (")
	}
	return s.prompted
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
