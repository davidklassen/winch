package helper

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
		// runs is the least number of runs.
		runs int
		// most is the most time the gate may take.
		most time.Duration
		// last is true when the error must end with the output of the last
		// run.
		last bool
	}{
		{name: "passes at once", check: "true", timeout: time.Second, runs: 1, most: 500 * time.Millisecond},
		{name: "passes after two failures", check: "[ $n -ge 3 ]", timeout: 2 * time.Second, runs: 3, most: time.Second},
		{name: "stays healthy for stable", check: "true", stable: 200 * time.Millisecond, timeout: 2 * time.Second, runs: 5, most: time.Second},
		{name: "a failure during the stable time starts the count again", check: "[ $n -ne 2 ]", stable: 150 * time.Millisecond, timeout: 2 * time.Second, runs: 6, most: time.Second},
		{name: "fails at the timeout with the last output", check: "exit 1", timeout: 300 * time.Millisecond,
			wantErr: "did not pass within 0.3s: exit status 1: run ", last: true, runs: 2, most: time.Second},
		{name: "passing without the stable time fails at the timeout", check: "[ $n -ge 4 ]", stable: time.Second, timeout: 400 * time.Millisecond,
			wantErr: "passed, but not for 1s within 0.4s", runs: 4, most: time.Second},
		{name: "a command that hangs ends at the timeout", check: "sleep 30", timeout: 300 * time.Millisecond,
			wantErr: "did not pass within 0.3s", runs: 1, most: 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			if want := fmt.Sprintf("run %d", runs()); tt.last && (err == nil || !strings.HasSuffix(err.Error(), want)) {
				t.Errorf("error %v, want the output of the last run, %q", err, want)
			}
			if n := runs(); n < tt.runs {
				t.Errorf("%d runs, want at least %d", n, tt.runs)
			}
			if took > tt.most {
				t.Errorf("the gate took %s, want at most %s", took, tt.most)
			}
		})
	}
}
