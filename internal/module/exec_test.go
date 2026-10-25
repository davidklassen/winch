package module

import (
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
func TestShellTimeLimit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	start := time.Now()
	err := shell(t.Context(), "echo waiting; sleep 60 & echo $! > '"+pidFile+"'; wait", time.Second)
	if err == nil || !strings.HasSuffix(err.Error(), "no result after 1s: waiting") {
		t.Fatalf("error = %v, want the time limit", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("shell returned after %s", d)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	// The child is killed, but it can stay a zombie of the killed shell for a
	// moment.
	for range 50 {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("the child %d of the command still runs", pid)
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
