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
			if err := Shell(t.Context(), tt.command); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Modules
func TestTimeLimit(t *testing.T) {
	tests := []struct {
		name string
		run  func(ctx context.Context, command string) error
	}{
		{"module command", func(ctx context.Context, command string) error {
			_, err := runLimited(ctx, time.Second, time.Second, nil, "sh", "-c", command)
			return err
		}},
		{"project command", func(ctx context.Context, command string) error {
			return shell(ctx, command, time.Second, time.Second)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			if d := time.Since(start); d < 2*time.Second || d > 4*time.Second {
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
	// The command exits before the limit, but its background child keeps the
	// output open past the limit.
	command := "sleep 3 & echo done"
	if _, err := runLimited(t.Context(), time.Second, 2*time.Second, nil, "sh", "-c", command); err != nil && strings.Contains(err.Error(), "no result") {
		t.Errorf("module command: error = %v, want no time limit", err)
	}
	if err := shell(t.Context(), command, time.Second, 2*time.Second); err != nil {
		t.Errorf("project command: error = %v, want nil", err)
	}
}
