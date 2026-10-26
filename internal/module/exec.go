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

func runLimited(ctx context.Context, limit, killDelay time.Duration, env []string, input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeoutCause(ctx, limit, fmt.Errorf("no result after %s", limit))
	defer cancel()
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
		return stdout.String(), fmt.Errorf("%s: %w: %s", what, err, tail(stdout.String()+stderr.String(), 10))
	}
	return stdout.String(), nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// Shell runs a command of the project through sh -c, in / and with stdin
// from /dev/null. On a failure, the error holds the end of the output.
func Shell(ctx context.Context, command string) error {
	return ShellLimit(ctx, command, commandLimit, KillDelay)
}

// ShellLimit is Shell with the time limit limit. After the limit, the command
// gets SIGTERM, and SIGKILL when it still runs after killDelay.
func ShellLimit(ctx context.Context, command string, limit, killDelay time.Duration) error {
	ctx, cancel := context.WithTimeoutCause(ctx, limit, fmt.Errorf("no result after %s", limit))
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = "/"
	// The error shows only the end of the output.
	out := &tailBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	err := wait(ctx, cmd, killDelay)
	switch {
	// A daemon that the command starts can keep the output open; the command
	// itself succeeded.
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
		return nil
	case len(out.b) == 0:
		return fmt.Errorf("%s: %w", command, err)
	}
	return fmt.Errorf("%s: %w: %s", command, err, tail(string(out.b), 10))
}

// wait runs cmd in its own process group. When ctx ends, the group gets
// SIGTERM, and SIGKILL when it still has a process after killDelay.
func wait(ctx context.Context, cmd *exec.Cmd, killDelay time.Duration) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stopped bool
	cmd.Cancel = func() error {
		stopped = true
		group := -cmd.Process.Pid
		_ = syscall.Kill(group, syscall.SIGTERM)
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
	if stopped {
		return context.Cause(ctx)
	}
	return err
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	b   []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if over := len(t.b) - t.max; over > 0 {
		t.b = append(t.b[:0], t.b[over:]...)
	}
	return len(p), nil
}
