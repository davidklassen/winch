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

// run runs a command and returns its output. On a failure, the error holds
// the end of the output.
func run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// A daemon that a package script starts can keep the output open.
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s", name, args[0], err, tail(stdout.String()+stderr.String(), 10))
	}
	return stdout.String(), nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// commandLimit is the time that a command of the project can run.
const commandLimit = 10 * time.Minute

// Shell runs a command of the project through sh -c, in / and with stdin
// from /dev/null. After the time limit, it kills the process group of the
// command. On a failure, the error holds the end of the output.
func Shell(ctx context.Context, command string) error {
	return shell(ctx, command, commandLimit)
}

func shell(ctx context.Context, command string, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	// The error shows only the end of the output.
	out := &tailBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	switch {
	// A daemon that the command starts can keep the output open; the command
	// itself succeeded.
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
		return nil
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%s: no result after %s: %s", command, limit, tail(string(out.b), 10))
	case len(out.b) == 0:
		return fmt.Errorf("%s: %w", command, err)
	}
	return fmt.Errorf("%s: %w: %s", command, err, tail(string(out.b), 10))
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
