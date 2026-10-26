package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/davidklassen/winch/internal/protocol"
)

// counter returns a command that counts its runs in a file and exits with
// the result of check, a shell test on $n, and a function that reads the
// count.
func counter(t *testing.T, check string) (string, func() int) {
	file := filepath.Join(t.TempDir(), "n")
	cmd := fmt.Sprintf(`n=$(cat %[1]s 2>/dev/null || echo 0); n=$((n+1)); echo $n > %[1]s; echo "run $n"; %[2]s`, file, check)
	return cmd, func() int {
		b, _ := os.ReadFile(file)
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return n
	}
}

// spec: Running a pipeline/Health gates
func TestHealth(t *testing.T) {
	const interval = 50 * time.Millisecond
	tests := []struct {
		name    string
		check   string
		stable  time.Duration
		timeout time.Duration
		wantErr string
		runs    int
		took    time.Duration
	}{
		{name: "passes at once", check: "true", timeout: time.Second, runs: 1, took: 0},
		{name: "passes after two failures", check: "[ $n -ge 3 ]", timeout: time.Second, runs: 3, took: 100 * time.Millisecond},
		{name: "stays healthy for stable", check: "true", stable: 200 * time.Millisecond, timeout: time.Second, runs: 5, took: 200 * time.Millisecond},
		{name: "a failure during the stable time starts the count again", check: "[ $n -ne 2 ]", stable: 150 * time.Millisecond, timeout: time.Second,
			runs: 6, took: 250 * time.Millisecond},
		{name: "fails at the timeout with the last output", check: "exit 1", timeout: 300 * time.Millisecond,
			wantErr: "did not pass within 0.3s: exit status 1: run 6", runs: 6, took: 300 * time.Millisecond},
		{name: "passing without the stable time fails at the timeout", check: "[ $n -ge 4 ]", stable: time.Second, timeout: 400 * time.Millisecond,
			wantErr: "passed, but not for 1s within 0.4s", runs: 8, took: 400 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cmd, runs := counter(t, tt.check)
				start := time.Now()
				err := health(context.Background(), protocol.Health{Command: cmd, Stable: tt.stable, Timeout: tt.timeout}, interval, 100*time.Millisecond)
				took := time.Since(start)
				switch {
				case tt.wantErr == "" && err != nil:
					t.Errorf("error %v", err)
				case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
					t.Errorf("error %v, want %q", err, tt.wantErr)
				}
				if n := runs(); n != tt.runs {
					t.Errorf("%d runs, want %d", n, tt.runs)
				}
				if took != tt.took {
					t.Errorf("the gate took %s, want %s", took, tt.took)
				}
			})
		})
	}

	t.Run("a cancel ends the gate", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			cmd, runs := counter(t, "true")
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(120*time.Millisecond, cancel)
			start := time.Now()
			err := health(ctx, protocol.Health{Command: cmd, Stable: time.Second, Timeout: 2 * time.Second}, interval, 100*time.Millisecond)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("error %v, want %v", err, context.Canceled)
			}
			if n := runs(); n != 3 {
				t.Errorf("%d runs, want 3", n)
			}
			if took := time.Since(start); took != 120*time.Millisecond {
				t.Errorf("the gate took %s, want 120ms", took)
			}
		})
	})

	// A run gets only the time left, so a command that hangs on a later run
	// ends at the timeout, not one timeout after that run starts. In a synctest
	// bubble the clock stops while a command runs, so this case takes real time.
	t.Run("a command that hangs ends at the timeout", func(t *testing.T) {
		cmd, _ := counter(t, "[ $n -ge 2 ] && sleep 30; exit 1")
		start := time.Now()
		err := health(context.Background(), protocol.Health{Command: cmd, Timeout: 2 * time.Second}, time.Second, 100*time.Millisecond)
		if want := "did not pass within 2s"; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v, want %q", err, want)
		}
		if took, most := time.Since(start), 2600*time.Millisecond; took > most {
			t.Errorf("the gate took %s, want at most %s", took, most)
		}
	})
}
