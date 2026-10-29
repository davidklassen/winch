package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/protocol"
)

// spec: Running a pipeline/Lockout protection (a second SSH connection runs
// a marker; through sudo -n for a login user other than root, in the form of
// the session start)
func TestAccess(t *testing.T) {
	s := &Session{cfg: Config{Host: "web1", Address: "192.0.2.1", User: "admin", Batch: true}}
	tests := []struct {
		name, uid, sudo string
		wantSudo        string
		wantErr         string
	}{
		{"root", "0", "#!/bin/sh\nexit 1\n", "", ""},
		{"sudo works", "1000", goodSudo, "-n true\n-n sh\n", ""},
		{"sudo fails", "1000", "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n", "", "sudo: a password is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", tt.uid, tt.sudo)
			calls := sudoCalls(t)
			argsFile := filepath.Join(t.TempDir(), "args")
			t.Setenv("SSH_ARGS", argsFile)
			err := s.Access(context.Background())
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("Access = %v, want %q", err, tt.wantErr)
			}
			if got := calls(); got != tt.wantSudo {
				t.Errorf("sudo calls %q, want %q", got, tt.wantSudo)
			}
			data, _ := os.ReadFile(argsFile)
			args := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
			for _, want := range []string{"ControlMaster=no", "ControlPath=none", "BatchMode=yes", "HostName=192.0.2.1"} {
				if !slices.Contains(args, want) {
					t.Errorf("ssh arguments %q have no -o %s", args, want)
				}
			}
		})
	}
}

// rebootHelper is a fake helper. The first connection answers reboot, the
// second says that the host has not rebooted yet, and the third gives a
// degraded system.
const rebootHelper = `#!/bin/sh
n=$(cat "$REBOOT_STATE" 2>/dev/null || echo 0)
n=$((n+1))
echo $n > "$REBOOT_STATE"
while read -r line; do
  id=$(echo "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
  case $line in
  *'"method":"hello"'*'"resume":true'*) echo "{\"id\":$id,\"result\":{}}" ;;
  *'"method":"hello"'*) if [ $n -eq 1 ]; then echo "{\"id\":$id,\"result\":{}}"; else echo "{\"id\":$id,\"error\":\"a reconnect without resume\"}"; fi ;;
  *'"method":"reboot"'*) echo "{\"id\":$id,\"result\":\"boot-1\"}" ;;
  *'"method":"booted"'*'"old":"boot-1"'*)
    if [ $n -le 2 ]; then echo "{\"id\":$id,\"result\":{\"same\":true}}"
    else echo "{\"id\":$id,\"result\":{\"state\":\"${BOOT_STATE:-degraded}\",\"failed\":[\"a.service\"]}}"; fi ;;
  *'"method":"facts"'*) echo "$n" >> "$REBOOT_STATE.facts"; echo "{\"id\":$id,\"result\":{\"os\":{\"id\":\"debian\"}}}" ;;
  *) echo "{\"id\":$id,\"error\":\"unexpected $line\"}" ;;
  esac
done
`

// spec: Modules/reboot (reboot, wait until the helper answers again);
// roadmap phase 16 (the reconnect passes ControlMaster=no and
// ControlPath=none; a degraded system does not fail the step)
func TestReboot(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	state := filepath.Join(t.TempDir(), "state")
	t.Setenv("REBOOT_STATE", state)
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("SSH_ARGS", argsFile)
	s, err := Open(context.Background(), Config{
		Host:       "web1",
		Address:    "web1",
		Dir:        t.TempDir(),
		Binaries:   []helperbin.Binary{helperbin.New("arm64", []byte(rebootHelper))},
		Hello:      protocol.Hello{Run: "r1"},
		Progress:   plain(&bytes.Buffer{}),
		RetryDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if data, _ := os.ReadFile(argsFile); strings.Contains(string(data), "ControlPath=none") {
		t.Error("the first connection passes ControlPath=none")
	}
	b, err := s.Reboot(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if b.State != "degraded" || !slices.Equal(b.Failed, []string{"a.service"}) {
		t.Errorf("Reboot = %+v", b)
	}
	if data, _ := os.ReadFile(argsFile); !strings.Contains(string(data), "\nControlMaster=no\n-o\nControlPath=none\n") {
		t.Errorf("the reconnect passes %q", data)
	}
	if _, err := s.Facts(context.Background()); err != nil {
		t.Errorf("the session after the reboot: %v", err)
	}
	if data, _ := os.ReadFile(state + ".facts"); string(data) != "3\n" {
		t.Errorf("facts read on connections %q, want 3", data)
	}
}

// spec: Modules/reboot (timeout)
func TestRebootTimeout(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	t.Setenv("REBOOT_STATE", filepath.Join(t.TempDir(), "state"))
	s, err := Open(context.Background(), Config{
		Host:       "web1",
		Address:    "web1",
		Dir:        t.TempDir(),
		Binaries:   []helperbin.Binary{helperbin.New("arm64", []byte(rebootHelper))},
		Hello:      protocol.Hello{Run: "r1"},
		Progress:   plain(&bytes.Buffer{}),
		RetryDelay: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.Reboot(context.Background(), 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "the host did not come back within 200ms") {
		t.Errorf("Reboot = %v", err)
	}
}

// spec: Modules/reboot (gap: another state than running or degraded fails
// the step)
func TestRebootMaintenance(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	t.Setenv("REBOOT_STATE", filepath.Join(t.TempDir(), "state"))
	t.Setenv("BOOT_STATE", "maintenance")
	s, err := Open(context.Background(), Config{
		Host:       "web1",
		Address:    "web1",
		Dir:        t.TempDir(),
		Binaries:   []helperbin.Binary{helperbin.New("arm64", []byte(rebootHelper))},
		Hello:      protocol.Hello{Run: "r1"},
		Progress:   plain(&bytes.Buffer{}),
		RetryDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.Reboot(context.Background(), time.Minute)
	if err == nil || !strings.Contains(err.Error(), "systemctl is-system-running says maintenance") {
		t.Errorf("Reboot = %v", err)
	}
}

// spec: Modules/reboot (winch connects again after a failed connection or a
// pam_nologin refusal; a refused key or host key fails the step at once)
func TestRebootRetry(t *testing.T) {
	tests := []struct {
		name, stdout, stderr string
		code                 int
		retry                bool
	}{
		{"refused connection", "", "ssh: connect to host web1 port 22: Connection refused", 255, true},
		{"closed", "", closed, 255, true},
		{"nologin", "", "System is booting up. Unprivileged users are not permitted to log in yet. Please come back later. For technical details, see pam_nologin(8).\n\n" + closed, 255, true},
		{"nologin, log level error", "", "", 255, true},
		{"refused key", "", "admin@web1: Permission denied (publickey).", 255, false},
		{"refused key on the jump host", "", "admin@bastion: Permission denied (publickey).\nConnection closed by UNKNOWN port 65535", 255, false},
		{"too many keys", "", "Received disconnect from 192.0.2.10 port 22:2: Too many authentication failures\nDisconnected from 192.0.2.10 port 22", 255, false},
		{"host key", "", "Host key verification failed.", 255, false},
		{"connection lost after the login", "have", "Connection to web1 closed by remote host.", 255, true},
		{"missing sudo", "", "winch: the login user needs passwordless sudo", 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			t.Setenv("REBOOT_STATE", filepath.Join(t.TempDir(), "state"))
			s, err := Open(context.Background(), Config{
				Host:       "web1",
				Address:    "web1",
				Dir:        t.TempDir(),
				Binaries:   []helperbin.Binary{helperbin.New("arm64", []byte(rebootHelper))},
				Hello:      protocol.Hello{Run: "r1"},
				Progress:   plain(&bytes.Buffer{}),
				RetryDelay: 10 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			failed := failOnce(t, tt.stdout, tt.stderr, tt.code)
			_, err = s.Reboot(context.Background(), time.Minute)
			if tt.retry {
				if err != nil {
					t.Errorf("Reboot = %v, want a retry that works", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.stderr[strings.LastIndex(tt.stderr, "\n")+1:]) {
				t.Errorf("Reboot = %v, want the failure of ssh", err)
			}
			if _, err := os.Stat(failed + ".again"); err == nil {
				t.Error("ssh started again after the failure")
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (gap: the batch mode of the
// run's sessions)
func TestAccessWithoutBatch(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("SSH_ARGS", argsFile)
	s := &Session{cfg: Config{Host: "web1", Address: "web1"}}
	if err := s.Access(context.Background()); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(argsFile); strings.Contains(string(data), "BatchMode") {
		t.Errorf("an access check without batch mode passes %q", data)
	}
}

// spec: Running a pipeline/Lockout protection (the check passes when stdout
// holds only the marker)
func TestAccessLoginShellText(t *testing.T) {
	s := &Session{cfg: Config{Host: "web1", Address: "web1"}}
	for _, uid := range []string{"0", "1000"} {
		t.Run(uid, func(t *testing.T) {
			fakeBin(t, "aarch64", uid, goodSudo)
			t.Setenv("SSH_BANNER", "Welcome")
			err := s.Access(context.Background())
			want := `the login shell printed "Welcome"; remove it from the shell startup files, such as ~/.bashrc`
			if err == nil || err.Error() != want {
				t.Errorf("Access = %v, want %q", err, want)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (stderr, such as sudo's
// unable to resolve host, does not fail the check)
func TestAccessStderr(t *testing.T) {
	fakeBin(t, "aarch64", "1000", "#!/bin/sh\necho 'sudo: unable to resolve host web1' >&2\nshift\nexec \"$@\"\n")
	s := &Session{cfg: Config{Host: "web1", Address: "web1"}}
	if err := s.Access(context.Background()); err != nil {
		t.Errorf("Access = %v", err)
	}
}

// spec: Running a pipeline/Lockout protection (gap: a refusal on stdout,
// such as from nologin, names the reason)
func TestAccessRefusalOnStdout(t *testing.T) {
	fakeBin(t, "aarch64", "1000", goodSudo)
	t.Setenv("SSH_FAIL_ONCE", filepath.Join(t.TempDir(), "failed"))
	t.Setenv("SSH_FAIL_OUT", "This account is currently not available.")
	t.Setenv("SSH_FAIL_CODE", "1")
	s := &Session{cfg: Config{Host: "web1", Address: "web1"}}
	err := s.Access(context.Background())
	if want := "exit status 1: This account is currently not available."; err == nil || err.Error() != want {
		t.Errorf("Access = %v, want %q", err, want)
	}
}

// spec: Running a pipeline/Lockout protection (gap: a login that does not
// run the command, such as ForceCommand internal-sftp, fails the check)
func TestAccessNoOutput(t *testing.T) {
	fakeBin(t, "aarch64", "1000", "#!/bin/sh\nexit 0\n")
	s := &Session{cfg: Config{Host: "web1", Address: "web1"}}
	err := s.Access(context.Background())
	if want := "the login did not run winch's command"; err == nil || err.Error() != want {
		t.Errorf("Access = %v, want %q", err, want)
	}
}
