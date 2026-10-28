package module

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	commandLimit = 10 * time.Minute
	// KillDelay is the time between SIGTERM and SIGKILL for a command that
	// runs too long.
	KillDelay = 10 * time.Second
)

// run runs a command and returns its output. On a failure, the error holds
// the end of the output.
func run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	return runLimited(ctx, commandLimit, KillDelay, env, "", name, args...)
}

// runInput is run with stdin from input.
func runInput(ctx context.Context, env []string, input, name string, args ...string) (string, error) {
	return runLimited(ctx, commandLimit, KillDelay, env, input, name, args...)
}

// runLimited runs a command with the time limit limit. A zero limit is no
// limit.
func runLimited(ctx context.Context, limit, killDelay time.Duration, env []string, input, name string, args ...string) (string, error) {
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, limit, fmt.Errorf("no result after %s", limit))
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), env...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := wait(ctx, cmd, killDelay); err != nil {
		what := name
		if len(args) > 0 {
			what += " " + args[0]
		}
		return stdout.String(), failure(what, err, stdout.String()+stderr.String())
	}
	return stdout.String(), nil
}

func failure(what string, err error, out string) error {
	out = strings.TrimSpace(out)
	if out == "" {
		return fmt.Errorf("%s: %w", what, err)
	}
	lines := strings.Split(out, "\n")
	return fmt.Errorf("%s: %w: %s", what, err, strings.Join(lines[max(0, len(lines)-10):], "\n"))
}

// Shell runs a command of the project through sh -ec, in / and with stdin
// from /dev/null. On a failure, the error holds the end of the output.
func Shell(ctx context.Context, command string) error {
	return ShellLimit(ctx, command, commandLimit, KillDelay)
}

// ShellLimit is Shell with the time limit limit. After the limit, the command
// gets SIGTERM, and SIGKILL when it still runs after killDelay.
func ShellLimit(ctx context.Context, command string, limit, killDelay time.Duration) error {
	return shellLimit(ctx, command, "/", nil, limit, killDelay)
}

// runAs is the user that a command runs as, with the IDs of its groups.
type runAs struct {
	user   passwdEntry
	groups []uint32
}

// shellLimit is ShellLimit in dir, and as the user as when it is not nil.
func shellLimit(ctx context.Context, command, dir string, as *runAs, limit, killDelay time.Duration) error {
	// The error shows only the end of the output.
	out := &tailBuffer{max: 64 << 10}
	if err := shell(ctx, "-ec", command, dir, as, limit, killDelay, out); err != nil {
		return failure(command, err, string(out.tail()))
	}
	return nil
}

// shell runs command in dir, with its output in out. With as,
// it runs as that user, with the user's HOME, USER, and LOGNAME.
func shell(ctx context.Context, options, command, dir string, as *runAs, limit, killDelay time.Duration, out *tailBuffer) error {
	ctx, cancel := context.WithTimeoutCause(ctx, limit, fmt.Errorf("no result after %s", limit))
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", options, command)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = out, out
	if as != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: as.user.uid, Gid: as.user.gid, Groups: as.groups}}
		cmd.Env = append(cmd.Environ(), "HOME="+as.user.home, "USER="+as.user.name, "LOGNAME="+as.user.name)
	}
	return wait(ctx, cmd, killDelay)
}

// wait runs cmd in its own process group. When ctx ends, the group gets
// SIGTERM after a time limit and SIGINT after a cancel, as from a Ctrl-C in a
// terminal. It gets SIGKILL when it still has a process after killDelay.
// After a cancel, the exit of cmd is the result.
func wait(ctx context.Context, cmd *exec.Cmd, killDelay time.Duration) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	var timedOut bool
	cmd.Cancel = func() error {
		timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		sig := syscall.SIGINT
		if timedOut {
			sig = syscall.SIGTERM
		}
		group := -cmd.Process.Pid
		_ = syscall.Kill(group, sig)
		for end := time.Now().Add(killDelay); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			if errors.Is(syscall.Kill(group, 0), syscall.ESRCH) {
				return nil
			}
		}
		return syscall.Kill(group, syscall.SIGKILL)
	}
	// A daemon that the command starts can keep the output open.
	cmd.WaitDelay = killDelay
	err := cmd.Run()
	if timedOut {
		return context.Cause(ctx)
	}
	// Run fails also when the command succeeded: when a child process keeps
	// the output open, or when the command exits 0 after a cancel.
	if cmd.ProcessState != nil && cmd.ProcessState.Success() {
		return nil
	}
	return err
}

// tailBuffer keeps the last max bytes written to it. It trims only at twice
// max, so a long output is not copied at each write.
type tailBuffer struct {
	b   []byte
	max int
	cut bool
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 2*t.max {
		t.b = append(t.b[:0], t.tail()...)
	}
	return len(p), nil
}

// tail returns the last max bytes, and records when it drops some.
func (t *tailBuffer) tail() []byte {
	if over := len(t.b) - t.max; over > 0 {
		t.cut = true
		return t.b[over:]
	}
	return t.b
}

// ExecResult is the result of a command of winch exec.
type ExecResult struct {
	Output   string `json:"output"`
	ExitCode int    `json:"exit_code"`
	// Signal is the signal that ended the command, or 0.
	Signal int `json:"signal,omitempty"`
}

// Exec runs a command of winch exec through sh -c.
func Exec(ctx context.Context, command string) (ExecResult, error) {
	return execLimit(ctx, command, commandLimit, KillDelay)
}

// execLimit is Exec with the time limit limit. Exit codes and signals are
// results; the time limit is an error.
func execLimit(ctx context.Context, command string, limit, killDelay time.Duration) (ExecResult, error) {
	out := &tailBuffer{max: 1 << 20}
	err := shell(ctx, "-c", command, "/", nil, limit, killDelay, out)
	tail := out.tail()
	if err != nil && !errors.As(err, new(*exec.ExitError)) {
		return ExecResult{}, failure(command, err, string(tail))
	}
	res := ExecResult{Output: string(tail)}
	if out.cut {
		res.Output = "(output cut to the last 1 MiB)\n" + res.Output
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		res.ExitCode = exit.ExitCode()
		if ws := exit.Sys().(syscall.WaitStatus); ws.Signaled() {
			res.Signal = int(ws.Signal())
			res.ExitCode = 128 + res.Signal
		}
	}
	return res, nil
}
