package module

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunErrorEndsWithStderr(t *testing.T) {
	_, err := run(t.Context(), nil, "sh", "-c", "seq 20; echo 'E: the cause' >&2; exit 1")
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
		{"runs in /", `[ "$(pwd)" = / ]`, ""},
		{"a background child keeps the output open", "sleep 15 &", ""},
		{"failure", "seq 20; echo 'the cause' >&2; exit 3", "seq 20; echo 'the cause' >&2; exit 3: exit status 3: 12\n13\n14\n15\n16\n17\n18\n19\n20\nthe cause"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			if err := ShellLimit(t.Context(), tt.command, commandLimit, time.Second); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
		})
	}
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
			if err == nil || !strings.HasSuffix(err.Error(), "no result after 1s: 12\n13\n14\n15\n16\n17\n18\n19\n20\nwaiting") {
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
			if err == nil || !strings.Contains(err.Error(), "no result after 1s") {
				t.Fatalf("error = %v, want the time limit", err)
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
	if string(b.b) != "cdef" {
		t.Errorf("tail = %q, want cdef", b.b)
	}
}

// spec: Modules
func TestTimeLimitAfterExit(t *testing.T) {
	t.Parallel()
	// The command exits before the limit, but its background child keeps the
	// output open past the limit.
	command := "sleep 3 & echo done"
	t.Run("module command", func(t *testing.T) {
		t.Parallel()
		if _, err := runLimited(t.Context(), time.Second, 2*time.Second, nil, "", "sh", "-c", command); err != nil && strings.Contains(err.Error(), "no result") {
			t.Errorf("error = %v, want no time limit", err)
		}
	})
	t.Run("project command", func(t *testing.T) {
		t.Parallel()
		if err := ShellLimit(t.Context(), command, time.Second, 2*time.Second); err != nil {
			t.Errorf("error = %v, want nil", err)
		}
	})
}
