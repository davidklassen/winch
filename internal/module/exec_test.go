package module

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunErrorEndsWithStderr(t *testing.T) {
	_, err := run(t.Context(), "sh", "-c", "seq 20; echo 'E: the cause' >&2; exit 1")
	if err == nil || !strings.HasSuffix(err.Error(), "E: the cause") {
		t.Fatalf("error = %v, want it to end with the stderr line", err)
	}
}

// spec: Modules; Steps
func TestShell(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"ok", "true", ""},
		{"failure without output", "exit 2", "exit 2: exit status 2"},
		{"stops at the first failure", "false; echo after", "false; echo after: exit status 1"},
		{"runs in /", `[ "$(pwd)" = / ]`, ""},
		{"a background child keeps the output open", "sleep 15 &", ""},
		{"a script of several lines", "true\nfalse\ntrue\n", "true ...: exit status 1"},
		{"failure", "echo 'the cause' >&2; seq 30; exit 3", "echo 'the cause' >&2; seq 30; exit 3: exit status 3: the cause\n" + seqLines(30)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			if err := Shell(t.Context(), tt.command); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Modules (commands)
func TestShellLimitLeavesOutTheCommand(t *testing.T) {
	if err := ShellLimit(t.Context(), "exit 2", commandLimit, time.Second); err == nil || err.Error() != "exit status 2" {
		t.Errorf("error = %v, want exit status 2", err)
	}
}

func seqLines(n int) string {
	var lines []string
	for i := 1; i <= n; i++ {
		lines = append(lines, strconv.Itoa(i))
	}
	return strings.Join(lines, "\n")
}

// spec: Modules (every command on the host)
func TestShellLongOutput(t *testing.T) {
	t.Parallel()
	const cut = "(output cut to the last 64 KiB)\n"
	xs := func(n int) string { return "head -c " + strconv.Itoa(n) + " /dev/zero | tr '\\0' x" }
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"64 KiB", xs(64<<10-1) + "; echo; exit 1", strings.Repeat("x", 64<<10-1)},
		{"one byte more", "echo; " + xs(64<<10-1) + "; echo; exit 1", cut + strings.Repeat("x", 64<<10-1)},
		{"the cut drops the rest of its line", "echo first; " + xs(70000) + "; echo; echo last; exit 1", cut + "last"},
		{"a last line longer than 64 KiB", xs(70000) + "; exit 1", strings.TrimSuffix(cut, "\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ShellLimit(t.Context(), tt.command, commandLimit, time.Second)
			if err == nil {
				t.Fatal("error = nil")
			}
			if _, got, _ := strings.Cut(err.Error(), "exit status 1: "); got != tt.want {
				t.Errorf("output = %.80q ... (%d bytes), want %.80q ... (%d bytes)", got, len(got), tt.want, len(tt.want))
			}
		})
	}
	full := seqLines(40000)
	err := ShellLimit(t.Context(), "seq 40000; exit 1", commandLimit, time.Second)
	_, got, _ := strings.Cut(fmt.Sprint(err), "exit status 1: ")
	kept, ok := strings.CutPrefix(got, cut)
	if !ok || !strings.HasSuffix(full, "\n"+kept) || len(kept) < 64<<10-10 || len(kept) > 64<<10 {
		t.Errorf("output = %.80q (%d bytes), want the cut line, then the whole lines of the last 64 KiB", got, len(got))
	}
}

// spec: Secrets
func TestShellScriptNotInArguments(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	// The PID keeps other processes with the test's text out.
	secret := "S3cretValue" + strconv.Itoa(os.Getpid())
	done := make(chan struct{})
	// The duration tells the test's sleep from others. Two commands, so that
	// sh does not exec sleep in its place.
	sleep := "sleep 5." + strconv.Itoa(os.Getpid())
	go func() {
		// The cancel at the end fails the command.
		_ = ShellLimit(ctx, sleep+"; true # "+secret, commandLimit, time.Second)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	for end := time.Now().Add(4 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		out, err := exec.Command("ps", "-A", "-o", "args=").Output()
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(string(out)) {
			if strings.Contains(line, secret) {
				t.Fatalf("a process has the script in its arguments: %s", line)
			}
		}
		if strings.Contains(string(out), sleep) {
			return
		}
	}
	t.Fatal("the command did not start")
}

// limitRunners runs a command as a module command and as a project command,
// with the time limit 1s.
func limitRunners(killDelay time.Duration) []struct {
	name string
	run  func(ctx context.Context, command string) error
} {
	return []struct {
		name string
		run  func(ctx context.Context, command string) error
	}{
		{"module command", func(ctx context.Context, command string) error {
			_, err := runLimited(ctx, time.Second, killDelay, nil, "", "sh", "-c", command)
			return err
		}},
		{"project command", func(ctx context.Context, command string) error {
			return ShellLimit(ctx, command, time.Second, killDelay)
		}},
	}
}

// spec: Modules
func TestTimeLimit(t *testing.T) {
	t.Parallel()
	for _, tt := range limitRunners(time.Second) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			// The command stops on SIGTERM. Its child records SIGTERM and keeps
			// running and the output open, so only SIGKILL stops it.
			command := "trap 'echo TERM > " + dir + "/term; exit 0' TERM; seq 20; echo waiting; " +
				"sh -c 'trap \"echo TERM > " + dir + "/child-term\" TERM; for i in $(seq 30); do sleep 1; done' 2>/dev/null & " +
				"echo $! > " + dir + "/pid; wait"
			start := time.Now()
			err := tt.run(t.Context(), command)
			if err == nil || !strings.HasSuffix(err.Error(), "stopped after 1s: "+seqLines(20)+"\nwaiting") {
				t.Fatalf("error = %v, want the time limit", err)
			}
			if d := time.Since(start); d < 2*time.Second || d >= time.Second+KillDelay {
				t.Errorf("returned after %s, want the limit and the kill delay", d)
			}
			for _, f := range []string{"term", "child-term"} {
				if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
					t.Errorf("no SIGTERM: %v", err)
				}
			}
			data, err := os.ReadFile(filepath.Join(dir, "pid"))
			if err != nil {
				t.Fatal(err)
			}
			pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			// The child is killed, but it can stay a zombie for a moment.
			for range 50 {
				if syscall.Kill(pid, 0) != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Errorf("the child %d of the command still runs", pid)
		})
	}
}

// spec: Modules
func TestTimeLimitEndsWhenTheCommandStops(t *testing.T) {
	t.Parallel()
	killDelay := 10 * time.Second
	for _, tt := range limitRunners(killDelay) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			err := tt.run(t.Context(), "sleep 30 & wait")
			if err == nil || !strings.HasSuffix(err.Error(), "stopped after 1s") {
				t.Fatalf("error = %v, want it to end at the time limit", err)
			}
			if d := time.Since(start); d >= time.Second+killDelay {
				t.Errorf("returned after %s, want before the kill delay ends", d)
			}
		})
	}
}

func TestTailBuffer(t *testing.T) {
	b := &tailBuffer{max: 4}
	for _, s := range []string{"ab", "cde", "f"} {
		if _, err := b.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if string(b.tail()) != "cdef" {
		t.Errorf("tail = %q, want cdef", b.tail())
	}
}

// spec: Modules
func TestTimeLimitAfterExit(t *testing.T) {
	t.Parallel()
	for _, tt := range limitRunners(2 * time.Second) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The command exits before the limit, but its background child keeps
			// the output open past the limit and the kill delay.
			if err := tt.run(t.Context(), "sleep 4 & echo done"); err != nil {
				t.Errorf("error = %v, want nil", err)
			}
		})
	}
}

// spec: Modules
func TestFailureWhileAChildKeepsTheOutputOpen(t *testing.T) {
	t.Parallel()
	for _, tt := range limitRunners(time.Second) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.run(t.Context(), "sleep 3 & exit 1"); err == nil || !strings.HasSuffix(err.Error(), "exit status 1") {
				t.Errorf("error = %v, want the exit status", err)
			}
		})
	}
}

func TestRunOutputWhileAChildKeepsItOpen(t *testing.T) {
	t.Parallel()
	out, err := runLimited(t.Context(), commandLimit, time.Second, nil, "", "sh", "-c", "sleep 3 & echo done")
	if err != nil || out != "done\n" {
		t.Errorf("run = %q, %v, want done", out, err)
	}
}

// spec: Modules
func TestFailureWithoutOutput(t *testing.T) {
	t.Parallel()
	for _, tt := range limitRunners(time.Second) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, command := range []string{"exit 2", "echo; exit 2"} {
				if err := tt.run(t.Context(), command); err == nil || !strings.HasSuffix(err.Error(), "exit status 2") {
					t.Errorf("%s: error = %v, want it to end at the exit status", command, err)
				}
			}
		})
	}
}

// spec: Modules
func TestRunWithoutLimit(t *testing.T) {
	t.Parallel()
	if _, err := runLimited(t.Context(), 0, time.Second, nil, "", "sh", "-c", "sleep 1.5"); err != nil {
		t.Errorf("error = %v, want nil", err)
	}
}

// spec: CLI/Messages
func TestNoResultSeconds(t *testing.T) {
	for limit, want := range map[time.Duration]string{
		commandLimit:            "stopped after 600s",
		90 * time.Second:        "stopped after 90s",
		1500 * time.Millisecond: "stopped after 1.5s",
		1000000 * time.Second:   "stopped after 1000000s",
	} {
		if got := noResult(limit).Error(); got != want {
			t.Errorf("%v: got %q, want %q", limit, got, want)
		}
	}
}

// spec: CLI/Messages
func TestRunMissingTool(t *testing.T) {
	_, err := runLimited(t.Context(), commandLimit, time.Second, nil, "", "winch-no-such-tool", "x")
	if err == nil || err.Error() != "winch-no-such-tool is missing" {
		t.Errorf("got %v", err)
	}
}
