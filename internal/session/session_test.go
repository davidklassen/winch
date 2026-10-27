package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// ssh sends itself SIGINT when $SSH_INT is set. It writes its arguments to
// $SSH_ARGS when it is set, prints $SSH_BANNER and the output of
// $SSH_BANNER_CMD when they are set, and runs its last argument with sh, on
// this machine. When $SSH_FAIL_ONCE is a missing file, ssh creates it and
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
		"ssh": "#!/bin/sh\n[ -z \"$SSH_INT\" ] || kill -INT $$\n[ -z \"$SSH_FAIL_ONCE\" ] || [ ! -e \"$SSH_FAIL_ONCE\" ] || : > \"$SSH_FAIL_ONCE.again\"\n" +
			"if [ -n \"$SSH_FAIL_ONCE\" ] && [ ! -e \"$SSH_FAIL_ONCE\" ]; then : > \"$SSH_FAIL_ONCE\"; [ -z \"$SSH_FAIL_OUT\" ] || printf '%s\\n' \"$SSH_FAIL_OUT\"; printf '%s\\n' \"$SSH_FAIL_ERR\" >&2; exit \"$SSH_FAIL_CODE\"; fi\n" +
			"[ -z \"$SSH_ARGS\" ] || printf '%s\\n' \"$@\" > \"$SSH_ARGS\"\n[ -z \"$SSH_BANNER\" ] || echo \"$SSH_BANNER\"\n[ -z \"$SSH_BANNER_CMD\" ] || sh -c \"$SSH_BANNER_CMD\" 2>/dev/null\neval \"cmd=\\${$#}\"\nexec sh -c \"$cmd\"\n",
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
			want := "winch: " + path + " is not owned by root or can be written by others"
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
		want := "winch: the login user needs passwordless sudo: sudo: a password is required"
		if err == nil || err.Error() != want {
			t.Errorf("error = %v, want %q", err, want)
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
	res, err := s.Apply(context.Background(), "file", f, &module.State{}, nil, nil)
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
	for _, want := range []string{"ConnectTimeout=15", "ServerAliveInterval=15", "ServerAliveCountMax=3", "RemoteCommand=none",
		"PermitLocalCommand=no", "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no"} {
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

// spec: Modules/pkg
func TestNotesGoToProgress(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	helper := helperbin.New("arm64", []byte(`#!/bin/sh
read -r line
echo '{"id":1}'
read -r line
echo '{"id":2,"note":"\\u001b[2Kwaiting for another apt run (pid 42)"}'
echo '{"id":2,"result":{"status":"ok"}}'
cat >/dev/null
`))
	var progress bytes.Buffer
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "web1", Dir: stateDir,
		Binaries: []helperbin.Binary{helper},
		Hello:    protocol.Hello{Run: "r1"}, Progress: plain(&progress),
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
	if want := "web1: ?[2Kwaiting for another apt run (pid 42)\n"; progress.String() != want {
		t.Errorf("progress = %q, want %q", progress.String(), want)
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
		{"error of the script", "", "winch: unsupported architecture mips", 1, false},
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
			if err != nil && err.Error() != tt.stderr {
				t.Errorf("error %q, want the text of ssh %q", err, tt.stderr)
			}
		})
	}
	t.Run("missing sudo", func(t *testing.T) {
		fakeBin(t, "aarch64", "1000", "#!/bin/sh\nexit 1\n")
		_, err := open(t, t.TempDir(), []helperbin.Binary{fakeHelper("arm64")})
		if err == nil || errors.Is(err, ErrUnreachable) || err.Error() != "winch: the login user needs passwordless sudo" {
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

// spec: Remote execution/Sessions
func TestOpenBatch(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "batch"}[batch], func(t *testing.T) {
			fakeBin(t, "aarch64", "0", goodSudo)
			argsFile := filepath.Join(t.TempDir(), "args")
			t.Setenv("SSH_ARGS", argsFile)
			s, err := Open(context.Background(), Config{
				Host: "web1", Address: "web1", Dir: stateDir, Batch: batch,
				Binaries: []helperbin.Binary{fakeHelper("arm64")}, Hello: protocol.Hello{Run: "r1"}, Progress: plain(&bytes.Buffer{}),
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
			if got := strings.Contains(string(data), "-o\nBatchMode=yes\n"); got != batch {
				t.Errorf("ssh arguments have BatchMode=yes: %v, want %v", got, batch)
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
			`Host key verification failed. (in batch mode ssh asks nothing; run "ssh web1" once)`},
		{"host key of an address", "Host key verification failed.", true, "192.0.2.1", "",
			`Host key verification failed. (in batch mode ssh asks nothing; run "ssh -o HostName=192.0.2.1 web1" once)`},
		{"host key of a user", "Host key verification failed.", true, "web1", "deploy",
			`Host key verification failed. (in batch mode ssh asks nothing; run "ssh -l deploy web1" once)`},
		{"refused login", "admin@web1: Permission denied (publickey).", true, "192.0.2.1", "",
			`admin@web1: Permission denied (publickey). (batch mode cannot type a key passphrase or a password; add the key to the agent with ssh-add)`},
		{"changed host key", "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.", true, "web1", "",
			"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed."},
		{"refused connection", "ssh: connect to host web1 port 22: Connection refused", true, "web1", "",
			"ssh: connect to host web1 port 22: Connection refused"},
		{"host key with a terminal", "Host key verification failed.", false, "web1", "",
			"Host key verification failed."},
		{"refused login with a terminal", "admin@web1: Permission denied (publickey).", false, "web1", "",
			"admin@web1: Permission denied (publickey)."},
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
