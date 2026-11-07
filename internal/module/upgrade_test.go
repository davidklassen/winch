package module

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
		{"no mode", "{}\n", `t.yaml:1:1: an upgrade step needs mode`},
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
		{"an earlier failure does not stop exec", "false\ntrue", ExecResult{}},
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
func TestExecNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	got, err := execLimit(t.Context(), "echo $NO_COLOR", commandLimit, time.Second)
	if err != nil || got.Output != "1\n" {
		t.Errorf("exec = %+v, %v, want NO_COLOR=1", got, err)
	}
}

// spec: CLI (winch exec)
func TestExecLongOutput(t *testing.T) {
	t.Parallel()
	const cut = "(output cut to the last 1 MiB)\n"
	xs := func(n int) string { return "head -c " + strconv.Itoa(n) + " /dev/zero | tr '\\0' x" }
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"1 MiB", xs(1<<20-1) + "; echo", strings.Repeat("x", 1<<20-1) + "\n"},
		{"one byte more", "echo; " + xs(1<<20-1) + "; echo", cut + strings.Repeat("x", 1<<20-1) + "\n"},
		{"the cut drops the rest of its line", "echo first; " + xs(1<<20+100) + "; echo; echo last", cut + "last\n"},
		{"a last line longer than 1 MiB", xs(1<<20 + 100), cut},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := execLimit(t.Context(), tt.command, commandLimit, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got.Output != tt.want {
				t.Errorf("output = %.80q ... (%d bytes), want %.80q ... (%d bytes)", got.Output, len(got.Output), tt.want, len(tt.want))
			}
		})
	}
}

// cancelWhenReady cancels the returned context when the command has created
// the file ready.
func cancelWhenReady(t *testing.T, ready string) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan bool, 1)
	t.Cleanup(func() {
		cancel()
		if !<-done {
			t.Error("exec did not become ready")
		}
	})
	go func() {
		seen := false
		defer func() {
			cancel()
			done <- seen
		}()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err := os.Stat(ready); err == nil {
				seen = true
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
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
		delay   time.Duration
		want    ExecResult
	}{
		// Keep execution in the ready shell so SIGINT cannot race a child startup.
		{"SIGINT", ": > $R; while :; do :; done", 5 * time.Second, ExecResult{ExitCode: 130, Signal: 2}},
		{"SIGKILL when SIGINT is ignored", "trap '' INT; : > $R; exec sleep 30", 100 * time.Millisecond, ExecResult{ExitCode: 137, Signal: 9}},
		{"an exit 0 on SIGINT", "trap 'echo bye; exit 0' INT; : > $R; while :; do :; done", 5 * time.Second, ExecResult{Output: "bye\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ready := filepath.Join(t.TempDir(), "ready")
			got, err := execLimit(cancelWhenReady(t, ready), "R="+ready+"; "+tt.command, commandLimit, tt.delay)
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
	if err == nil || !strings.HasSuffix(err.Error(), "stopped after 1s; set --timeout for a longer limit: term") {
		t.Errorf("error = %v, want SIGTERM at the time limit", err)
	}
}

// spec: Modules (time limit)
func TestExecTimeLimit(t *testing.T) {
	t.Parallel()
	_, err := execLimit(t.Context(), "echo started; sleep 30", time.Second, time.Second)
	if err == nil || !strings.HasSuffix(err.Error(), "stopped after 1s; set --timeout for a longer limit: started") {
		t.Errorf("error = %v, want the time limit with the output", err)
	}
}

// spec: Running a pipeline/Lockout protection (an upgrade whose simulation
// upgrades openssh-server loads sshd)
func TestUpgradesSSHServer(t *testing.T) {
	for _, tt := range []struct {
		name, out string
		want      bool
	}{
		{"upgrade", "Inst openssh-server [1:10.0p1-7] (1:10.0p1-8 Debian:13 [arm64])\n", true},
		{"install", "Inst openssh-server (1:10.0p1-8 Debian:13 [arm64])\n", false},
		{"removal", "Remv openssh-server [1:10.0p1-7]\n", false},
		{"another package", "Inst openssh-sftp-server [1:10.0p1-7] (1:10.0p1-8 Debian:13 [arm64])\n", false},
		{"nothing", "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", false},
	} {
		if got := UpgradesSSHServer(parseUpgrade(tt.out)); got != tt.want {
			t.Errorf("%s: UpgradesSSHServer = %t, want %t", tt.name, got, tt.want)
		}
	}
}
