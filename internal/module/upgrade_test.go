package module

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// spec: Modules/upgrade
func TestUpgradeValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"safe", "mode: safe\n", ""},
		{"full", "mode: full\n", ""},
		{"no mode", "{}\n", `t.yaml:1:1: missing key "mode"`},
		{"other mode", "mode: dist\n", `t.yaml:1:7: mode: must be safe or full, not "dist"`},
		{"unknown key", "mode: safe\nautoremove: true\n", `t.yaml:2:1: unknown key "autoremove"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Upgrade{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/upgrade
func TestParseUpgrade(t *testing.T) {
	out := `NOTE: This is only a simulation!
Reading package lists...
The following packages will be REMOVED:
  winch-up-old
Remv winch-up-old [1]
Inst winch-up [1] (2 localhost [all])
Inst winch-up-new (1 localhost [all])
Inst libc6 [2.41-12] (2.41-12+deb13u1 Debian:13.2/stable [arm64]) []
Conf winch-up-new (1 localhost [all])
Conf winch-up (2 localhost [all])
`
	want := []string{"remove winch-up-old", "upgrade winch-up 1 → 2", "install winch-up-new 1", "upgrade libc6 2.41-12 → 2.41-12+deb13u1"}
	if got := parseUpgrade(out); !slices.Equal(got, want) {
		t.Errorf("parseUpgrade =\n%q\nwant\n%q", got, want)
	}
	if got := parseUpgrade("Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n"); got != nil {
		t.Errorf("parseUpgrade of no change = %q, want nil", got)
	}
}

// spec: Modules; CLI (winch exec)
func TestExecCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    ExecResult
	}{
		{"output and exit code", "echo a; echo b >&2; exit 3", ExecResult{Output: "a\nb\n", ExitCode: 3}},
		{"runs in / with stdin from /dev/null", "pwd; cat", ExecResult{Output: "/\n"}},
		{"a signal", "echo x; kill -9 $$", ExecResult{Output: "x\n", ExitCode: 137, Signal: 9}},
		{"a background child keeps the output open", "sleep 15 & echo done", ExecResult{Output: "done\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := execLimit(t.Context(), tt.command, commandLimit, time.Second)
			if err != nil || got != tt.want {
				t.Errorf("exec = %+v, %v, want %+v", got, err, tt.want)
			}
		})
	}
}

// spec: CLI (winch exec)
func TestExecLongOutput(t *testing.T) {
	t.Parallel()
	got, err := execLimit(t.Context(), "seq 300000; echo end", commandLimit, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Output, "(output cut to the last 1 MiB)\n") || !strings.HasSuffix(got.Output, "\n300000\nend\n") || len(got.Output) > 1<<20+100 {
		t.Errorf("output of %d bytes starts %q, want the last 1 MiB after a note", len(got.Output), got.Output[:min(40, len(got.Output))])
	}
}

// cancelWhenReady cancels the returned context when the command has created
// the file ready.
func cancelWhenReady(t *testing.T, ready string) context.Context {
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		for {
			if _, err := os.Stat(ready); err == nil {
				cancel()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return ctx
}

// spec: CLI (winch exec)
func TestExecInterrupt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    ExecResult
	}{
		{"SIGINT", "touch $R; sleep 30", ExecResult{ExitCode: 130, Signal: 2}},
		{"SIGKILL when SIGINT is ignored", "trap '' INT; touch $R; sleep 30", ExecResult{ExitCode: 137, Signal: 9}},
		{"an exit 0 on SIGINT", "trap 'echo bye; exit 0' INT; touch $R; sleep 30", ExecResult{Output: "bye\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ready := filepath.Join(t.TempDir(), "ready")
			got, err := execLimit(cancelWhenReady(t, ready), "R="+ready+"; "+tt.command, commandLimit, 5*time.Second)
			if err != nil || got != tt.want {
				t.Errorf("exec = %+v, %v, want %+v", got, err, tt.want)
			}
		})
	}
}

// spec: Modules (time limit)
func TestExecTimeLimitSendsSIGTERM(t *testing.T) {
	t.Parallel()
	_, err := execLimit(t.Context(), "trap 'echo term; exit 1' TERM; sleep 30 & wait", time.Second, time.Second)
	if err == nil || !strings.HasSuffix(err.Error(), "no result after 1s: term") {
		t.Errorf("error = %v, want SIGTERM at the time limit", err)
	}
}

// spec: Modules (time limit)
func TestExecTimeLimit(t *testing.T) {
	t.Parallel()
	_, err := execLimit(t.Context(), "echo started; sleep 30", time.Second, time.Second)
	if err == nil || !strings.HasSuffix(err.Error(), "no result after 1s: started") {
		t.Errorf("error = %v, want the time limit with the output", err)
	}
}
