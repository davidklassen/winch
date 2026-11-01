package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
)

// plain writes to b without color, through a filter without secrets.
func plain(b *bytes.Buffer) *color.Writer {
	return color.NewWriter(b, secret.NewFilter().Parts, false)
}

// fakeHelper answers hello with an error that names its architecture, so a
// test can see which helper ran.
func fakeHelper(arch string) helperbin.Binary {
	return helperbin.New(arch, []byte("#!/bin/sh\nread line\necho '{\"id\":1,\"error\":\"ran "+arch+"\"}'\n"))
}

// stateDir is the state directory that the tests share, so that each helper
// is sent and checked only once.
var stateDir string

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	root, err := os.MkdirTemp("", "winch-session")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(root)
	stateDir = filepath.Join(root, "state")
	if err := fakeSSH(filepath.Join(root, "bin")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}

// fakeSSH puts fake ssh, uname, id, sudo, and ls in bin, and bin first in PATH.
// The tests share them: macOS checks each new executable file on its first
// run, and that takes up to half a second.
//
// ssh -G writes its arguments to $SSH_G_ARGS when it is set. It prints
// $SSH_G, or prints $SSH_G_ERR on stderr and exits with 255 when that is
// set. ssh sends itself SIGINT when $SSH_INT is set. It
// writes its arguments to $SSH_ARGS when it is set, prints $SSH_BANNER and
// the output of $SSH_BANNER_CMD when they are set, runs $SSH_CHILD with its
// stdout and stderr when it is set, and runs its last argument
// with sh, on this machine. When $SSH_FAIL_ONCE is a missing file, ssh creates it and
// fails once: it prints $SSH_FAIL_OUT on stdout when it is set, prints
// $SSH_FAIL_ERR on stderr, and exits with $SSH_FAIL_CODE. A later start
// creates $SSH_FAIL_ONCE.again. uname prints $FAKE_UNAME, id prints
// $FAKE_UID, and sudo runs the script $FAKE_SUDO with its arguments. ls -ldn
// shows root as the owner, except for the path $FAKE_LS_USER.
func fakeSSH(bin string) error {
	if err := os.Mkdir(bin, 0o755); err != nil {
		return err
	}
	scripts := map[string]string{
		"ssh": "#!/bin/sh\nif [ \"$1\" = -G ]; then\n[ -z \"$SSH_G_ARGS\" ] || printf '%s\\n' \"$@\" > \"$SSH_G_ARGS\"\n" +
			"[ -z \"$SSH_G_ERR\" ] || { printf '%s\\n' \"$SSH_G_ERR\" >&2; exit 255; }\nprintf '%s\\n' \"$SSH_G\"; exit\nfi\n" +
			"[ -z \"$SSH_INT\" ] || kill -INT $$\n[ -z \"$SSH_FAIL_ONCE\" ] || [ ! -e \"$SSH_FAIL_ONCE\" ] || : > \"$SSH_FAIL_ONCE.again\"\n" +
			"if [ -n \"$SSH_FAIL_ONCE\" ] && [ ! -e \"$SSH_FAIL_ONCE\" ]; then : > \"$SSH_FAIL_ONCE\"; [ -z \"$SSH_FAIL_OUT\" ] || printf '%s\\n' \"$SSH_FAIL_OUT\"; printf '%s\\n' \"$SSH_FAIL_ERR\" >&2; exit \"$SSH_FAIL_CODE\"; fi\n" +
			"[ -z \"$SSH_ARGS\" ] || printf '%s\\n' \"$@\" > \"$SSH_ARGS\"\n[ -z \"$SSH_BANNER\" ] || echo \"$SSH_BANNER\"\n[ -z \"$SSH_BANNER_CMD\" ] || sh -c \"$SSH_BANNER_CMD\" 2>/dev/null\n[ -z \"$SSH_CHILD\" ] || sh -c \"$SSH_CHILD\"\neval \"cmd=\\${$#}\"\nexec sh -c \"$cmd\"\n",
		"uname": "#!/bin/sh\necho \"$FAKE_UNAME\"\n",
		"id":    "#!/bin/sh\necho \"$FAKE_UID\"\n",
		"sudo":  "#!/bin/sh\nexec sh -c \"$FAKE_SUDO\" sudo \"$@\"\n",
		"ls":    "#!/bin/sh\nset -- \"$2\" $(/bin/ls \"$@\")\nu=0\n[ \"$1\" != \"$FAKE_LS_USER\" ] || u=$4\necho \"$2 $3 $u $5\"\n",
	}
	for name, s := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(s), 0o755); err != nil {
			return err
		}
	}
	return os.Setenv("PATH", bin+":"+os.Getenv("PATH"))
}

// fakeBin sets what the fake uname, id, and sudo do.
func fakeBin(t *testing.T, arch, uid, sudo string) {
	t.Helper()
	t.Setenv("FAKE_UNAME", arch)
	t.Setenv("FAKE_UID", uid)
	t.Setenv("FAKE_SUDO", sudo)
}

// goodSudo writes its first two arguments as one line to $SUDO_LOG, so a test
// can see how sudo ran.
const goodSudo = "#!/bin/sh\n[ -z \"$SUDO_LOG\" ] || echo \"$1 $2\" >> \"$SUDO_LOG\"\n[ \"$1\" = -n ] || exit 2\nshift\nexec \"$@\"\n"

func sudoCalls(t *testing.T) func() string {
	log := filepath.Join(t.TempDir(), "sudo-log")
	t.Setenv("SUDO_LOG", log)
	return func() string {
		data, _ := os.ReadFile(log)
		return string(data)
	}
}

func open(t *testing.T, dir string, bins []helperbin.Binary) (string, error) {
	t.Helper()
	var progress bytes.Buffer
	s, err := Open(context.Background(), Config{
		Host:       "web1",
		Address:    "web1",
		Dir:        dir,
		Binaries:   bins,
		Hello:      protocol.Hello{Run: "r1"},
		Progress:   plain(&progress),
		RetryDelay: retryDelay,
		Batch:      true,
	})
	if s != nil {
		s.Close()
	}
	return progress.String(), err
}

// spec: Remote execution/Helper
func TestOpenArchitecture(t *testing.T) {
	bins := []helperbin.Binary{fakeHelper("amd64"), fakeHelper("arm64")}
	tests := []struct {
		uname   string
		wantErr string
	}{
		{"x86_64", "ran amd64"},
		{"aarch64", "ran arm64"},
		{"riscv64", "unsupported architecture riscv64"},
	}
	for _, tt := range tests {
		t.Run(tt.uname, func(t *testing.T) {
			fakeBin(t, tt.uname, "0", goodSudo)
			_, err := open(t, stateDir, bins)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// spec: Remote execution/Helper
func TestOpenUploadsOnce(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	dir := t.TempDir()
	bins := []helperbin.Binary{fakeHelper("amd64"), fakeHelper("arm64")}
	progress, _ := open(t, dir, bins)
	if !strings.Contains(progress, "web1: sending the helper (arm64)") {
		t.Errorf("first open progress = %q", progress)
	}
	progress, err := open(t, dir, bins)
	if progress != "" {
		t.Errorf("second open progress = %q, want none", progress)
	}
	if err == nil || !strings.Contains(err.Error(), "ran arm64") {
		t.Errorf("second open error = %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "bin"))
	if len(entries) != 1 || entries[0].Name() != bins[1].SHA256 {
		t.Errorf("bin holds %v, want one file named by the hash", entries)
	}
}

// spec: Remote execution/Helper
func TestOpenBadHash(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	bad := fakeHelper("arm64")
	bad.SHA256 = strings.Repeat("0", 64)
	dir := t.TempDir()
	_, err := open(t, dir, []helperbin.Binary{fakeHelper("amd64"), bad})
	if err == nil || !strings.Contains(err.Error(), "the helper has the wrong hash") {
		t.Errorf("error = %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "bin")); len(entries) != 0 {
		t.Errorf("bin holds %v after a bad upload", entries)
	}
}

// spec: Remote execution/Helper
func TestOpenUnsafeStateDir(t *testing.T) {
	bins := []helperbin.Binary{fakeHelper("arm64")}
	helper := filepath.Join("bin", bins[0].SHA256)
	tests := []struct {
		name string
		path string
		// mode zero means another owner.
		mode os.FileMode
		// have opens once first, so the helper is there.
		have bool
	}{
		{"dir of another user", ".", 0, false},
		{"bin of another user", "bin", 0, false},
		{"dir written by others", ".", 0o702, false},
		{"bin written by the group", "bin", 0o770, false},
		{"dir of another user with a helper", ".", 0, true},
		{"helper of another user", helper, 0, true},
		{"helper written by others", helper, 0o757, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			dir := filepath.Join(t.TempDir(), "state")
			if tt.have {
				_, _ = open(t, dir, bins)
			} else if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tt.path)
			if tt.mode != 0 {
				if err := os.Chmod(path, tt.mode); err != nil {
					t.Fatal(err)
				}
			} else if tt.path == helper {
				t.Setenv("FAKE_LS_USER", path)
			} else {
				t.Setenv("FAKE_LS_USER", path+"/")
			}
			progress, err := open(t, dir, bins)
			want := path + " is not owned by root, or the group or others can write it"
			if err == nil || err.Error() != want {
				t.Errorf("error = %v, want %q", err, want)
			}
			if progress != "" {
				t.Errorf("progress = %q, want no helper sent", progress)
			}
		})
	}
}

// spec: Remote execution/Helper
func TestOpenLinkedHelper(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	bins := []helperbin.Binary{fakeHelper("arm64")}
	dir := filepath.Join(t.TempDir(), "state")
	_, _ = open(t, dir, bins)
	path := filepath.Join(dir, "bin", bins[0].SHA256)
	if err := os.Rename(path, path+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".real", path); err != nil {
		t.Fatal(err)
	}
	_, err := open(t, dir, bins)
	if want := path + " is not a directory or a regular file"; err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

// spec: Remote execution/Helper
func TestOpenLooseUmask(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	defer syscall.Umask(syscall.Umask(0))
	_, err := open(t, filepath.Join(t.TempDir(), "state"), []helperbin.Binary{fakeHelper("arm64")})
	if err == nil || !strings.Contains(err.Error(), "ran arm64") {
		t.Errorf("error = %v", err)
	}
}

// spec: Remote execution/Helper
func TestOpenCutHelper(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	dir := t.TempDir()
	bins := []helperbin.Binary{fakeHelper("arm64")}
	_, _ = open(t, dir, bins)
	path := filepath.Join(dir, "bin", bins[0].SHA256)
	if err := os.Truncate(path, 10); err != nil {
		t.Fatal(err)
	}
	progress, err := open(t, dir, bins)
	if !strings.Contains(progress, "web1: sending the helper (arm64)") {
		t.Errorf("progress = %q, want the helper sent again", progress)
	}
	if err == nil || !strings.Contains(err.Error(), "ran arm64") {
		t.Errorf("error = %v", err)
	}
	if data, _ := os.ReadFile(path); !bytes.Equal(data, bins[0].Data) {
		t.Errorf("helper = %q, want the full helper", data)
	}
}

// spec: Remote execution/Helper
func TestOpenSudo(t *testing.T) {
	bins := []helperbin.Binary{fakeHelper("amd64"), fakeHelper("arm64")}
	t.Run("non-root uses sudo -n", func(t *testing.T) {
		fakeBin(t, "aarch64", "1000", goodSudo)
		calls := sudoCalls(t)
		_, err := open(t, stateDir, bins)
		if err == nil || !strings.Contains(err.Error(), "ran arm64") {
			t.Errorf("error = %v", err)
		}
		if got, want := calls(), "-n true\n-n sh\n"; got != want {
			t.Errorf("sudo calls = %q, want %q", got, want)
		}
	})
	t.Run("root does not use sudo", func(t *testing.T) {
		fakeBin(t, "aarch64", "0", goodSudo)
		calls := sudoCalls(t)
		_, err := open(t, stateDir, bins)
		if err == nil || !strings.Contains(err.Error(), "ran arm64") {
			t.Errorf("error = %v", err)
		}
		if got := calls(); got != "" {
			t.Errorf("root used sudo: %q", got)
		}
	})
	t.Run("password required", func(t *testing.T) {
		fakeBin(t, "aarch64", "1000", "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")
		_, err := open(t, stateDir, bins)
		want := "the login user needs passwordless sudo: sudo: a password is required"
		if err == nil || err.Error() != want {
			t.Errorf("error = %v, want %q", err, want)
		}
	})
	t.Run("only the probe fails", func(t *testing.T) {
		fakeBin(t, "aarch64", "1000", "#!/bin/sh\necho \"$1 $2\" >> \"$SUDO_LOG\"\nif [ \"$2\" = true ]; then echo 'sudo: a password is required' >&2; exit 1; fi\nshift\nexec \"$@\"\n")
		calls := sudoCalls(t)
		_, err := open(t, stateDir, bins)
		want := "the login user needs passwordless sudo: sudo: a password is required"
		if err == nil || err.Error() != want {
			t.Errorf("error = %v, want %q", err, want)
		}
		if got := calls(); got != "-n true\n" {
			t.Errorf("sudo calls = %q, want only the probe", got)
		}
	})
}

// spec: Remote execution/Helper
func TestOpenLoginShellText(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	t.Setenv("SSH_BANNER", "Welcome")
	_, err := open(t, t.TempDir(), []helperbin.Binary{fakeHelper("arm64")})
	want := `the login shell printed "Welcome" before winch started; remove it from the shell startup files, such as ~/.bashrc`
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

// spec: Remote execution/Helper
func TestOpenMuchLoginShellText(t *testing.T) {
	tests := []struct{ name, banner string }{
		{"1 MB", "echo Welcome; head -c 1048576 /dev/zero"},
		{"without end", "echo Welcome; yes"},
		{"without a newline", "printf Welcome"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			t.Setenv("SSH_BANNER_CMD", tt.banner)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := Open(ctx, Config{
				Host: "web1", Address: "web1", Dir: t.TempDir(),
				Binaries: []helperbin.Binary{fakeHelper("arm64")},
				Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
			})
			if ctx.Err() != nil {
				t.Error("Open did not end before the 5s timeout")
			}
			want := `the login shell printed "Welcome" before winch started`
			if err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Errorf("error = %v, want %q", err, want)
			}
		})
	}
}

// spec: CLI/Messages (a message names a fix only when the fix works)
func TestOpenForcedCommand(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	// cloud-init puts such a command= line in root's authorized_keys.
	failOnce(t, `Please login as the user "debian" rather than the user "root".`, "", 142)
	_, err := open(t, t.TempDir(), []helperbin.Binary{fakeHelper("arm64")})
	want := `the login did not run winch's command; a command= line in authorized_keys or a nologin shell prints this: Please login as the user "debian" rather than the user "root".`
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

// spec: Modules/user and group
func TestOpenPassesSSHConnection(t *testing.T) {
	helper := helperbin.New("amd64", []byte("#!/bin/sh\nread line\necho \"{\\\"id\\\":1,\\\"error\\\":\\\"conn $1\\\"}\"\n"))
	t.Setenv("SSH_CONNECTION", "10.0.2.2 51234 10.0.2.15 22")
	for _, uid := range []string{"1000", "0"} {
		fakeBin(t, "x86_64", uid, goodSudo)
		_, err := open(t, stateDir, []helperbin.Binary{helper})
		if want := "conn 10.0.2.2 51234 10.0.2.15 22"; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("uid %s: error = %v, want %q", uid, err, want)
		}
	}
}

// The script travels inside single quotes.
func TestScriptHasNoSingleQuote(t *testing.T) {
	s := Script([]helperbin.Binary{fakeHelper("amd64"), fakeHelper("arm64")}, StateDir)
	if s == "" || strings.Contains(s, "'") {
		t.Errorf("script is empty or has a single quote:\n%s", s)
	}
}

// recordingHelper answers every request and appends each request line to
// $REQUESTS when it is set. A first apply without content gets need_content.
func recordingHelper(arch string) helperbin.Binary {
	script := `#!/bin/sh
while read -r line; do
  [ -z "$REQUESTS" ] || printf '%s\n' "$line" >> "$REQUESTS"
  id=$(printf '%s' "$line" | sed 's/^{"id":\([0-9]*\).*/\1/')
  case "$line" in
  *'"method":"apply"'*'"data":"'*) echo '{"id":'$id',"result":{"status":"change","action":"create"}}' ;;
  *'"method":"facts"'*) echo '{"id":'$id',"result":{"os":{"id":"debian","version":"13","codename":"trixie","arch":"arm64"}}}' ;;
  *'"method":"apply"'*) echo '{"id":'$id',"error":"apply needs the content","need_content":true}' ;;
  *) echo '{"id":'$id',"result":{"status":"ok"}}' ;;
  esac
done
`
	return helperbin.New(arch, []byte(script))
}

// spec: Running a pipeline/Plan
func TestDestination(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	t.Setenv("SSH_G", "user admin\nhostname 192.0.2.10\nport 2222\nconnecttimeout 15")
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("SSH_G_ARGS", argsFile)
	helper := helperbin.New("arm64", []byte("#!/bin/sh\nread line\necho '{\"id\":1,\"result\":{\"login\":\"deploy\",\"login_uid\":1001}}'\ncat >/dev/null\n"))
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "192.0.2.10", User: "admin", Dir: stateDir,
		Binaries: []helperbin.Binary{helper},
		Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, want := s.Destination(), (protocol.Destination{User: "deploy", UID: 1001, HostName: "192.0.2.10", Port: "2222"}); got != want {
		t.Errorf("destination = %+v, want %+v", got, want)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := "\n" + string(data)
	for _, want := range []string{"\n-G\n", "\n-o\nHostName=192.0.2.10\n", "\n-l\nadmin\n", "\n-o\nConnectTimeout=15\n"} {
		if !strings.Contains(args, want) {
			t.Errorf("ssh -G arguments %q have no %q", args, want)
		}
	}
	if !strings.HasSuffix(args, "\n--\nweb1\n") {
		t.Errorf("ssh -G arguments %q do not end with -- web1", args)
	}
}

// spec: Inventory
func TestResolveJump(t *testing.T) {
	tests := []struct{ config, want string }{
		{"hostname 10.0.0.5\nport 22", ""},
		{"hostname 10.0.0.5\nport 22\nproxyjump bastion-eu", "bastion-eu"},
		{"hostname 10.0.0.5\nport 22\nproxycommand nc %h %p", "nc %h %p"},
	}
	for _, tt := range tests {
		t.Setenv("SSH_G", tt.config)
		hostName, port, jump, err := Resolve(context.Background(), Config{Host: "db"})
		if err != nil {
			t.Fatal(err)
		}
		if hostName != "10.0.0.5" || port != "22" || jump != tt.want {
			t.Errorf("%q: Resolve = %q, %q, %q; want 10.0.0.5, 22, %q", tt.config, hostName, port, jump, tt.want)
		}
	}
}

// spec: Running a pipeline/Plan
func TestDestinationBadSSHConfig(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	t.Setenv("SSH_G_ERR", "/home/a/.ssh/config line 3: Bad configuration option: hostnme")
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "web1", Dir: stateDir,
		Binaries: []helperbin.Binary{recordingHelper("arm64")},
		Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
	})
	if s != nil {
		s.Close()
	}
	if want := "read the SSH config: /home/a/.ssh/config line 3: Bad configuration option: hostnme"; err == nil || err.Error() != want {
		t.Errorf("error = %v, want %s", err, want)
	}
}

// spec: Running a pipeline/Plan (apply fails a host whose resolved host
// name, port, jump host, or login user differs from the plan's)
func TestOpenDestinationChanged(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	helper := helperbin.New("arm64", []byte("#!/bin/sh\nread line\necho \"{\\\"id\\\":1,\\\"result\\\":$WELCOME}\"\ncat >/dev/null\n"))
	want := protocol.Destination{User: "deploy", UID: 1001, HostName: "192.0.2.10", Port: "22"}
	tests := []struct {
		name, sshG, welcome string
		wantErr             string
		login               bool
	}{
		{"same", "hostname 192.0.2.10\nport 22", `{"login":"deploy","login_uid":1001}`, "", true},
		{"host name", "hostname 192.0.2.11\nport 22", `{"login":"deploy","login_uid":1001}`, "deploy@192.0.2.11:22 (uid 1001)", false},
		{"port", "hostname 192.0.2.10\nport 2222", `{"login":"deploy","login_uid":1001}`, "deploy@192.0.2.10:2222 (uid 1001)", false},
		{"jump host", "hostname 192.0.2.10\nport 22\nproxyjump bastion", `{"login":"deploy","login_uid":1001}`, "deploy@192.0.2.10:22 (uid 1001) through bastion", false},
		{"user", "hostname 192.0.2.10\nport 22", `{"login":"admin","login_uid":1000}`, "admin@192.0.2.10:22 (uid 1000)", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SSH_G", tt.sshG)
			t.Setenv("WELCOME", tt.welcome)
			argsFile := filepath.Join(t.TempDir(), "args")
			t.Setenv("SSH_ARGS", argsFile)
			s, err := Open(context.Background(), Config{
				Host: "web1", Address: "web1", Dir: stateDir,
				Binaries: []helperbin.Binary{helper},
				Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
				Want: &want,
			})
			if s != nil {
				s.Close()
			}
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("Open = %v", err)
			case tt.wantErr != "" && (err == nil || err.Error() != "the SSH destination changed since the plan: deploy@192.0.2.10:22 (uid 1001) → "+tt.wantErr+"; run winch plan again and check the new destination"):
				t.Errorf("Open = %v, want the changed destination %s", err, tt.wantErr)
			}
			if _, err := os.Stat(argsFile); (err == nil) != tt.login {
				t.Errorf("ssh logged in: %v, want %v", err == nil, tt.login)
			}
		})
	}
}

// spec: Remote execution/Facts
func TestFacts(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "web1", Dir: stateDir,
		Binaries: []helperbin.Binary{fakeHelper("amd64"), recordingHelper("arm64")},
		Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f, err := s.Facts(context.Background())
	if want := (facts.OS{ID: "debian", Version: "13", Codename: "trixie", Arch: "arm64"}); err != nil || f.OS != want {
		t.Errorf("facts = %+v, %v; want %+v", f, err, want)
	}
}

// spec: Remote execution/Helper
func TestContentOnlyWhenNeeded(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	file := filepath.Join(t.TempDir(), "requests")
	t.Setenv("REQUESTS", file)
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "web1", Dir: stateDir,
		Binaries: []helperbin.Binary{fakeHelper("amd64"), recordingHelper("arm64")},
		Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	content := "secret text"
	f := &module.File{Path: "/etc/motd", Data: []byte(content)}
	wire := base64.StdEncoding.EncodeToString(f.Data)
	if _, err := s.Check(context.Background(), "file", f, &module.State{}); err != nil {
		t.Fatal(err)
	}
	res, err := s.Apply(context.Background(), "file", f, &module.State{}, nil, nil, nil, protocol.Guard{})
	if err != nil || res.Action != module.Create {
		t.Fatalf("apply = %+v, %v", res, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 {
		t.Fatalf("requests:\n%s", data)
	}
	for i, wantContent := range []bool{false, false, false, true} {
		if got := strings.Contains(lines[i], wire); got != wantContent {
			t.Errorf("request %d has content = %v, want %v: %s", i+1, got, wantContent, lines[i])
		}
	}
	if !strings.Contains(lines[1], `"data_sha256":`) {
		t.Errorf("check has no hash: %s", lines[1])
	}
	if string(f.Data) != content {
		t.Error("check changed the step")
	}
}

// sshArgs opens a session to host at address with a fake ssh. It returns the
// ssh options before "--" and the target after it.
func sshArgs(t *testing.T, host, address string) (options, target string) {
	t.Helper()
	fakeBin(t, "aarch64", "0", goodSudo)
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("SSH_ARGS", argsFile)
	s, err := Open(context.Background(), Config{
		Host:     host,
		Address:  address,
		Dir:      stateDir,
		Binaries: []helperbin.Binary{fakeHelper("arm64")},
		Hello:    protocol.Hello{Run: "r1"},
		Progress: plain(&bytes.Buffer{}),
	})
	if s != nil {
		s.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "ran arm64") {
		t.Fatalf("error = %v", err)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	options, rest, _ := strings.Cut(string(data), "\n--\n")
	target, _, _ = strings.Cut(rest, "\n")
	return options + "\n", target
}

// spec: Remote execution/Sessions
func TestOpenOptions(t *testing.T) {
	options, _ := sshArgs(t, "web1", "web1")
	for _, want := range []string{"ConnectTimeout=15", "ServerAliveInterval=15", "ServerAliveCountMax=3", "ControlMaster=no",
		"ControlPath=none", "RemoteCommand=none", "PermitLocalCommand=no", "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no"} {
		if !strings.Contains(options, "-o\n"+want+"\n") {
			t.Errorf("ssh arguments have no -o %s", want)
		}
	}
}

// spec: Inventory
func TestOpenHostName(t *testing.T) {
	tests := []struct {
		address, wantHostName string
	}{
		{"mail.acme.com", ""},
		{"192.0.2.10", "192.0.2.10"},
		{"fe80::1%eth0", "fe80::1%%eth0"},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			options, target := sshArgs(t, "mail.acme.com", tt.address)
			if target != "mail.acme.com" {
				t.Errorf("target = %q, want mail.acme.com", target)
			}
			if tt.wantHostName == "" {
				if strings.Contains(options, "HostName=") {
					t.Errorf("options %q have a HostName", options)
				}
			} else if !strings.Contains(options, "-o\nHostName="+tt.wantHostName+"\n") {
				t.Errorf("options %q have no -o HostName=%s", options, tt.wantHostName)
			}
		})
	}
}

// spec: Modules/pkg; CLI/Messages (notes)
func TestNotesAndProgress(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	helper := helperbin.New("arm64", []byte(`#!/bin/sh
read -r line
echo '{"id":1,"result":{}}'
read -r line
echo '{"id":2,"progress":"\\u001b[2Kwaiting for apt-get (pid 42), which holds the package locks"}'
echo '{"id":2,"note":"apt does not know hello"}'
echo '{"id":2,"warning":"the certificate a expires on 2026-11-20"}'
echo '{"id":2,"result":{"status":"ok"}}'
cat >/dev/null
`))
	var progress bytes.Buffer
	var notes []string
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "web1", Dir: stateDir,
		Binaries: []helperbin.Binary{helper},
		Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&progress),
		Note: func(text string, warning bool) { notes = append(notes, fmt.Sprintf("%s %t", text, warning)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	progress.Reset()
	res, err := s.Check(context.Background(), "pkg", &module.Pkg{Name: []string{"hello"}}, &module.State{})
	if err != nil || res.Status != module.OK {
		t.Fatalf("check = %+v, %v", res, err)
	}
	if want := "web1: ?[2Kwaiting for apt-get (pid 42), which holds the package locks\n"; progress.String() != want {
		t.Errorf("progress = %q, want %q", progress.String(), want)
	}
	if want := []string{"apt does not know hello false", "the certificate a expires on 2026-11-20 true"}; !slices.Equal(notes, want) {
		t.Errorf("notes = %q, want %q", notes, want)
	}
}

const retryDelay = 100 * time.Millisecond

// failOnce makes the fake ssh fail its first start with this output and
// exit code. It returns the file that the first start creates.
func failOnce(t *testing.T, stdout, stderr string, code int) string {
	t.Helper()
	failed := filepath.Join(t.TempDir(), "failed")
	t.Setenv("SSH_FAIL_ONCE", failed)
	t.Setenv("SSH_FAIL_OUT", stdout)
	t.Setenv("SSH_FAIL_ERR", stderr)
	t.Setenv("SSH_FAIL_CODE", strconv.Itoa(code))
	return failed
}

// OpenSSH 9.6 and later print only the last line of a close before the
// banner at the default log level. Earlier versions print both lines.
const closed = "Connection closed by 192.0.2.10 port 22"

// spec: Remote execution/Sessions
func TestOpenRetry(t *testing.T) {
	// ssh fails only its first start, so a retry ends without an error.
	tests := []struct {
		name, stdout, stderr string
		code                 int
		retry                bool
	}{
		{"closed", "", closed, 255, true},
		{"closed, OpenSSH 9.5", "", "kex_exchange_identification: Connection closed by remote host\n" + closed, 255, true},
		{"closed, OpenSSH 9.5, log level error", "", "kex_exchange_identification: Connection closed by remote host", 255, true},
		{"busy jump host", "", "Connection closed by 192.0.2.1 port 22\nConnection closed by UNKNOWN port 65535", 255, true},
		{"refused login on the jump host", "", "admin@bastion: Permission denied (publickey).\nConnection closed by UNKNOWN port 65535", 255, false},
		{"jump host timeout", "", "ssh: connect to host bastion port 22: Connection timed out\nConnection closed by UNKNOWN port 65535", 255, false},
		{"kex timeout", "", "kex_exchange_identification: read: Operation timed out", 255, false},
		{"reset", "", "kex_exchange_identification: read: Connection reset by peer\nConnection reset by 192.0.2.10 port 22", 255, true},
		{"reset, log level error", "", "kex_exchange_identification: read: Connection reset by peer", 255, true},
		{"connect timeout", "", "ssh: connect to host web1 port 22: Connection timed out", 255, false},
		{"banner timeout", "", "Connection timed out during banner exchange\nConnection to 192.0.2.10 port 22 timed out", 255, false},
		{"refused", "", "ssh: connect to host web1 port 22: Connection refused", 255, false},
		{"refused login", "", "admin@web1: Permission denied (publickey).", 255, false},
		{"keepalive", "", "Timeout, server web1 not responding.", 255, false},
		{"close text from the script", "", closed, 1, false},
		{"closed after have", "have", closed, 255, false},
		{"closed after need", "need arm64", closed, 255, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			failed := failOnce(t, tt.stdout, tt.stderr, tt.code)
			_, err := open(t, stateDir, []helperbin.Binary{recordingHelper("arm64")})
			if !tt.retry {
				last := tt.stderr[strings.LastIndex(tt.stderr, "\n")+1:]
				if err == nil || !strings.Contains(err.Error(), last) {
					t.Errorf("error = %v, want %q without a retry", err, last)
				}
				return
			}
			if err != nil {
				t.Errorf("error = %v, want a retry that works", err)
			}
			first, err1 := os.Stat(failed)
			second, err2 := os.Stat(failed + ".again")
			if err1 != nil || err2 != nil {
				t.Fatalf("ssh starts: %v, %v", err1, err2)
			}
			if gap := second.ModTime().Sub(first.ModTime()); gap < retryDelay {
				t.Errorf("second start %s after the first, want at least %s", gap, retryDelay)
			}
		})
	}
}

// spec: Remote execution/Sessions
func TestOpenRetrySilentClose(t *testing.T) {
	// At log level ERROR, ssh prints nothing for a close after the banner,
	// as while sshd executes itself again after a reload. At QUIET, it prints
	// nothing for a refused login either.
	tests := []struct {
		name, level, stdout string
		code                int
		retry               bool
	}{
		{"error", "ERROR", "", 255, true},
		{"quiet", "QUIET", "", 255, false},
		{"fatal", "FATAL", "", 255, false},
		{"info", "INFO", "", 255, false},
		{"no output from the script", "ERROR", "", 1, false},
		{"no output after have", "ERROR", "have", 255, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			t.Setenv("SSH_G", "hostname web1\nport 22\nloglevel "+tt.level)
			failed := failOnce(t, tt.stdout, "", tt.code)
			_, err := open(t, stateDir, []helperbin.Binary{recordingHelper("arm64")})
			second, again := os.Stat(failed + ".again")
			if !tt.retry {
				if err == nil || again == nil {
					t.Errorf("error = %v, second start: %v; want a failure without a retry", err, again)
				}
				return
			}
			if err != nil || again != nil {
				t.Fatalf("error = %v, second start: %v; want a retry that works", err, again)
			}
			first, err := os.Stat(failed)
			if err != nil {
				t.Fatal(err)
			}
			if gap := second.ModTime().Sub(first.ModTime()); gap < retryDelay {
				t.Errorf("second start %s after the first, want at least %s", gap, retryDelay)
			}
		})
	}
}

// spec: Remote execution/Sessions
func TestOpenRetryCancelled(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	failed := failOnce(t, "", closed, 255)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	s, err := Open(ctx, Config{
		Host: "web1", Address: "web1", Dir: t.TempDir(),
		Binaries: []helperbin.Binary{fakeHelper("arm64")},
		Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
		RetryDelay: time.Minute,
	})
	if s != nil {
		s.Close()
	}
	if err == nil {
		t.Error("Open succeeded after the context ended")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Open ended after %s, want right after the context ended", elapsed)
	}
	if _, err := os.Stat(failed + ".again"); err == nil {
		t.Error("ssh started again after the context ended")
	}
}

// spec: CLI/Exit codes ("4: one or more hosts were unreachable")
func TestOpenUnreachable(t *testing.T) {
	tests := []struct {
		name, stdout, stderr string
		code                 int
		unreachable          bool
	}{
		{"refused", "", "ssh: connect to host web1 port 22: Connection refused", 255, true},
		{"timeout", "", "ssh: connect to host web1 port 22: Connection timed out", 255, true},
		{"name", "", "ssh: Could not resolve hostname web1: nodename nor servname provided, or not known", 255, true},
		{"host key", "", "Host key verification failed.", 255, true},
		{"refused login", "", "admin@web1: Permission denied (publickey).", 255, true},
		{"error of the script", "", "unsupported architecture mips", 1, false},
		{"closed after have", "have", closed, 255, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			failOnce(t, tt.stdout, tt.stderr, tt.code)
			_, err := open(t, t.TempDir(), []helperbin.Binary{fakeHelper("arm64")})
			if err == nil || errors.Is(err, ErrUnreachable) != tt.unreachable {
				t.Errorf("error %v, unreachable %v, want %v", err, errors.Is(err, ErrUnreachable), tt.unreachable)
			}
			if err != nil && !strings.HasPrefix(err.Error(), tt.stderr) {
				t.Errorf("error %q, want the text of ssh %q", err, tt.stderr)
			}
		})
	}
	t.Run("missing sudo", func(t *testing.T) {
		fakeBin(t, "aarch64", "1000", "#!/bin/sh\nexit 1\n")
		_, err := open(t, t.TempDir(), []helperbin.Binary{fakeHelper("arm64")})
		if err == nil || errors.Is(err, ErrUnreachable) || err.Error() != "the login user needs passwordless sudo" {
			t.Errorf("error %v, want the sudo failure, not unreachable", err)
		}
	})
}

// spec: Running a pipeline/Apply ("Ctrl-C reaches only winch, not its SSH
// sessions")
func TestSSHIgnoresInterrupt(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	t.Setenv("SSH_INT", "1")
	_, err := open(t, stateDir, []helperbin.Binary{fakeHelper("arm64")})
	if err == nil || err.Error() != "ran arm64" {
		t.Errorf("error = %v, want the helper to run", err)
	}
}

// spec: Remote execution/Sessions (at a terminal, a session logs in with
// BatchMode=yes first, and logs in again with prompts only when the host
// refuses that login)
func TestOpenBatch(t *testing.T) {
	tests := []struct {
		name, stderr string
		batch        bool
		// again is whether ssh starts a second time, and batchArgs whether
		// the login that works has BatchMode=yes.
		again, batchArgs, prompted bool
	}{
		{"terminal", "", false, false, true, false},
		{"batch", "", true, false, true, false},
		{"terminal, refused login", "admin@web1: Permission denied (publickey).", false, true, false, true},
		{"terminal, unknown host key", "Host key verification failed.", false, true, false, false},
		{"terminal, changed host key", "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.", false, false, false, false},
		{"terminal, timeout", "ssh: connect to host web1 port 22: Connection timed out", false, false, false, false},
		{"terminal, closed", closed, false, true, true, false},
		{"batch, refused login", "admin@web1: Permission denied (publickey).", true, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			failed := ""
			if tt.stderr != "" {
				failed = failOnce(t, "", tt.stderr, 255)
			}
			argsFile := filepath.Join(t.TempDir(), "args")
			t.Setenv("SSH_ARGS", argsFile)
			s, err := Open(context.Background(), Config{
				Host: "web1", Address: "web1", Dir: stateDir, Batch: tt.batch,
				Binaries: []helperbin.Binary{helperbin.New("arm64", []byte("#!/bin/sh\nread -r line\necho '{\"id\":1,\"result\":{}}'\ncat >/dev/null\n"))},
				Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
			})
			if failed != "" {
				if _, serr := os.Stat(failed + ".again"); (serr == nil) != tt.again {
					t.Errorf("second start: %v, want %v", serr == nil, tt.again)
				}
				if !tt.again {
					if err == nil {
						t.Error("Open worked, want the error of ssh")
					}
					return
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			data, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(data), "-o\nBatchMode=yes\n"); got != tt.batchArgs {
				t.Errorf("ssh arguments have BatchMode=yes: %v, want %v", got, tt.batchArgs)
			}
			if got := s.Prompted(context.Background()); got != tt.prompted {
				t.Errorf("Prompted = %v, want %v", got, tt.prompted)
			}
		})
	}
}

// spec: Remote execution/Sessions (after a login that accepted a new host key,
// the access check tells whether the login needed a prompt)
func TestOpenNewHostKey(t *testing.T) {
	for _, tt := range []struct {
		name, stderr string
		prompted     bool
	}{
		{"agent", "", false},
		{"passphrase", "admin@web1: Permission denied (publickey).", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			failOnce(t, "", "Host key verification failed.", 255)
			s, err := Open(context.Background(), Config{
				Host: "web1", Address: "web1", Dir: stateDir,
				Binaries: []helperbin.Binary{helperbin.New("arm64", []byte("#!/bin/sh\nread -r line\necho '{\"id\":1,\"result\":{}}'\ncat >/dev/null\n"))},
				Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if tt.stderr != "" {
				failOnce(t, "", tt.stderr, 255)
			}
			if got := s.Prompted(context.Background()); got != tt.prompted {
				t.Errorf("Prompted = %v, want %v", got, tt.prompted)
			}
		})
	}
}

// spec: Remote execution/Sessions ("the error says to run ssh <host> once")
func TestOpenBatchHint(t *testing.T) {
	tests := []struct {
		name, stderr string
		batch        bool
		address      string
		user         string
		want         string
	}{
		{"host key", "Host key verification failed.", true, "web1", "",
			`Host key verification failed. (in batch mode ssh asks nothing; accept the host key once with: ssh web1)`},
		{"host key of an address", "Host key verification failed.", true, "192.0.2.1", "",
			`Host key verification failed. (in batch mode ssh asks nothing; accept the host key once with: ssh -o HostName=192.0.2.1 web1)`},
		{"host key of a user", "Host key verification failed.", true, "web1", "deploy",
			`Host key verification failed. (in batch mode ssh asks nothing; accept the host key once with: ssh -l deploy web1)`},
		{"host key of a user with a space", "Host key verification failed.", true, "web1", "a b",
			`Host key verification failed. (in batch mode ssh asks nothing; accept the host key once with: ssh -l 'a b' web1)`},
		{"host key of an address with a percent sign", "Host key verification failed.", true, "fe80::1%eth0", "",
			`Host key verification failed. (in batch mode ssh asks nothing; accept the host key once with: ssh -o HostName=fe80::1%%eth0 web1)`},
		{"host key of an address with a quote", "Host key verification failed.", true, "x'y", "",
			`Host key verification failed. (in batch mode ssh asks nothing; accept the host key once with: ssh -o 'HostName=x'\''y' web1)`},
		{"refused login", "admin@web1: Permission denied (publickey).", true, "192.0.2.1", "",
			`admin@web1: Permission denied (publickey). (batch mode cannot type a passphrase or a password; if the key needs one, add it to the agent with ssh-add)`},
		{"changed host key", "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.", true, "web1", "",
			"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed."},
		{"refused connection", "ssh: connect to host web1 port 22: Connection refused", true, "web1", "",
			"ssh: connect to host web1 port 22: Connection refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			failOnce(t, "", tt.stderr, 255)
			_, err := Open(context.Background(), Config{
				Host: "web1", Address: tt.address, Dir: t.TempDir(), Batch: tt.batch, User: tt.user,
				Binaries: []helperbin.Binary{fakeHelper("arm64")}, Hello: protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
			})
			if err == nil || err.Error() != tt.want || !errors.Is(err, ErrUnreachable) {
				t.Errorf("error %v, want %q and unreachable", err, tt.want)
			}
		})
	}
}

// spec: CLI/Output (progress)
func TestHoldDuringLogin(t *testing.T) {
	const refused = "admin@web1: Permission denied (publickey)."
	held := []string{"hold after the batch login", `resume after ""`}
	tests := []struct {
		name, stderr string
		batch        bool
		// noSudo makes the interactive login fail after ssh starts.
		noSudo bool
		ok     bool
		want   []string
	}{
		{"batch login", "", false, false, true, nil},
		{"refused batch login", refused, false, false, true, held},
		{"unknown host key", "Host key verification failed.", false, false, true, held},
		{"failed interactive login", refused, false, true, false, held},
		{"refused connection", "ssh: connect to host web1 port 22: Connection refused", false, false, false, nil},
		{"refused login in batch mode", refused, true, false, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.noSudo {
				fakeBin(t, "aarch64", "1000", "#!/bin/sh\nexit 1\n")
			} else {
				fakeBin(t, "aarch64", "0", goodSudo)
			}
			failed := filepath.Join(t.TempDir(), "failed")
			if tt.stderr != "" {
				failed = failOnce(t, "", tt.stderr, 255)
			}
			var log []string
			var progress bytes.Buffer
			s, err := Open(context.Background(), Config{
				Host: "web1", Address: "web1", Dir: stateDir, Batch: tt.batch,
				Binaries: []helperbin.Binary{helperbin.New("arm64", []byte("#!/bin/sh\nread -r line\necho '{\"id\":1,\"result\":{}}'\ncat >/dev/null\n"))},
				Hello:    protocol.Hello{Run: "r1"},
				Progress: plain(&progress),
				Hold: func() func() {
					if _, err := os.Stat(failed); err == nil {
						log = append(log, "hold after the batch login")
					} else {
						log = append(log, "hold before the batch login")
					}
					return func() { log = append(log, "resume after "+strconv.Quote(progress.String())) }
				},
			})
			if s != nil {
				s.Close()
			}
			if (err == nil) != tt.ok {
				t.Fatalf("error %v, want ok %v", err, tt.ok)
			}
			if !slices.Equal(log, tt.want) {
				t.Errorf("holds %q, want %q", log, tt.want)
			}
		})
	}
}

// spec: CLI/Messages
func TestOpenHelperEndsSilently(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	_, err := open(t, t.TempDir(), []helperbin.Binary{helperbin.New("arm64", []byte("#!/bin/sh\nexit 1\n"))})
	want := "the session ended without an error message (ssh: exit status 1)"
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

// spec: CLI/Messages
func TestOpenLoginShellTextWithQuotes(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	t.Setenv("SSH_BANNER", `say "hi"`)
	_, err := open(t, t.TempDir(), []helperbin.Binary{fakeHelper("arm64")})
	want := `the login shell printed "say "hi"" before winch started; remove it from the shell startup files, such as ~/.bashrc`
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

// spec: CLI/Messages
func TestOpenHelperSendsText(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	_, err := open(t, t.TempDir(), []helperbin.Binary{helperbin.New("arm64", []byte("#!/bin/sh\nread line\necho 'not json'\n"))})
	want := "the helper sent a line that is not a response: not json"
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

// spec: Remote execution/Sessions (the access check of lockout protection
// always uses BatchMode=yes)
func TestProxyCommand(t *testing.T) {
	opts := []string{"-o", "BatchMode=yes"}
	tests := []struct{ jump, want string }{
		{"a", `ssh '-o' 'BatchMode=yes' -W '[%h]:%p' -- 'a'`},
		{"u%x@[2001:db8::1]", `ssh '-o' 'BatchMode=yes' -W '[%h]:%p' -l 'u%%x' -- '2001:db8::1'`},
		{"jdoe@corp@[fe80::1%en0]:2222", `ssh '-o' 'BatchMode=yes' -W '[%h]:%p' -l 'jdoe@corp' -p '2222' -- 'fe80::1%%en0'`},
		{"u@b:2222,c", `ssh '-o' 'BatchMode=yes' -o 'ProxyCommand=ssh '\''-o'\'' '\''BatchMode=yes'\'' -W '\''[%%h]:%%p'\'' -l '\''u'\'' -p '\''2222'\'' -- '\''b'\''' -W '[%h]:%p' -- 'c'`},
	}
	for _, tt := range tests {
		if got := proxyCommand(opts, tt.jump); got != tt.want {
			t.Errorf("proxyCommand(%q)\n got %s\nwant %s", tt.jump, got, tt.want)
		}
	}
}
