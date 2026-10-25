package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

// fakeHelper answers hello with an error that names its architecture, so a
// test can see which helper ran.
func fakeHelper(arch string) helperbin.Binary {
	return helperbin.New(arch, []byte("#!/bin/sh\nread line\necho '{\"id\":1,\"error\":\"ran "+arch+"\"}'\n"))
}

// fakeBin puts fake ssh, uname, id, and sudo first in PATH. ssh writes its
// arguments to $SSH_ARGS when it is set, prints $SSH_BANNER and the output of
// $SSH_BANNER_CMD when they are set, and runs its last argument with sh, on
// this machine.
func fakeBin(t *testing.T, arch, uid, sudo string) {
	t.Helper()
	bin := t.TempDir()
	scripts := map[string]string{
		"ssh":   "#!/bin/sh\n[ -z \"$SSH_ARGS\" ] || printf '%s\\n' \"$@\" > \"$SSH_ARGS\"\n[ -z \"$SSH_BANNER\" ] || echo \"$SSH_BANNER\"\n[ -z \"$SSH_BANNER_CMD\" ] || sh -c \"$SSH_BANNER_CMD\" 2>/dev/null\neval \"cmd=\\${$#}\"\nexec sh -c \"$cmd\"\n",
		"uname": "#!/bin/sh\necho " + arch + "\n",
		"id":    "#!/bin/sh\necho " + uid + "\n",
		"sudo":  sudo,
	}
	for name, s := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
}

// goodSudo creates the file $SUDO_MARK, so a test can see that it ran.
const goodSudo = "#!/bin/sh\n[ \"$1\" = -n ] || exit 2\nshift\n[ -z \"$SUDO_MARK\" ] || touch \"$SUDO_MARK\"\nexec \"$@\"\n"

func sudoRan(t *testing.T) func() bool {
	mark := filepath.Join(t.TempDir(), "sudo-ran")
	t.Setenv("SUDO_MARK", mark)
	return func() bool {
		_, err := os.Stat(mark)
		return err == nil
	}
}

func open(t *testing.T, dir string, bins []helperbin.Binary) (string, error) {
	t.Helper()
	var progress bytes.Buffer
	s, err := Open(context.Background(), Config{
		Host:     "web1",
		Address:  "web1",
		Dir:      dir,
		Binaries: bins,
		Hello:    protocol.Hello{Run: "r1"},
		Progress: &progress,
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
			_, err := open(t, t.TempDir(), bins)
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
func TestOpenSudo(t *testing.T) {
	bins := []helperbin.Binary{fakeHelper("amd64"), fakeHelper("arm64")}
	t.Run("non-root uses sudo -n", func(t *testing.T) {
		fakeBin(t, "aarch64", "1000", goodSudo)
		ran := sudoRan(t)
		_, err := open(t, t.TempDir(), bins)
		if err == nil || !strings.Contains(err.Error(), "ran arm64") {
			t.Errorf("error = %v", err)
		}
		if !ran() {
			t.Error("sudo -n did not run")
		}
	})
	t.Run("root does not use sudo", func(t *testing.T) {
		fakeBin(t, "aarch64", "0", goodSudo)
		ran := sudoRan(t)
		_, err := open(t, t.TempDir(), bins)
		if err == nil || !strings.Contains(err.Error(), "ran arm64") {
			t.Errorf("error = %v", err)
		}
		if ran() {
			t.Error("root used sudo")
		}
	})
	t.Run("password required", func(t *testing.T) {
		fakeBin(t, "aarch64", "1000", "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")
		_, err := open(t, t.TempDir(), bins)
		want := "winch: the login user needs passwordless sudo"
		if err == nil || !strings.Contains(err.Error(), want) {
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
				Hello:    protocol.Hello{Run: "r1"}, Progress: &bytes.Buffer{},
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
// file. A first apply without content gets need_content.
func recordingHelper(arch, file string) helperbin.Binary {
	script := `#!/bin/sh
while read -r line; do
  printf '%s\n' "$line" >> ` + file + `
  id=$(printf '%s' "$line" | sed 's/^{"id":\([0-9]*\).*/\1/')
  case "$line" in
  *'"method":"apply"'*'"data":"'*) echo '{"id":'$id',"result":{"status":"change","action":"create"}}' ;;
  *'"method":"facts"'*) echo '{"id":'$id',"result":{"os":{"id":"debian","version":"13","codename":"trixie"}}}' ;;
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
	dir := t.TempDir()
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "web1", Dir: dir,
		Binaries: []helperbin.Binary{fakeHelper("amd64"), recordingHelper("arm64", filepath.Join(dir, "requests"))},
		Hello:    protocol.Hello{Run: "r1"}, Progress: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f, err := s.Facts(context.Background())
	if want := (facts.OS{ID: "debian", Version: "13", Codename: "trixie"}); err != nil || f.OS != want {
		t.Errorf("facts = %+v, %v; want %+v", f, err, want)
	}
}

// spec: Remote execution/Helper
func TestContentOnlyWhenNeeded(t *testing.T) {
	fakeBin(t, "aarch64", "0", goodSudo)
	dir := t.TempDir()
	file := filepath.Join(dir, "requests")
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "web1", Dir: dir,
		Binaries: []helperbin.Binary{fakeHelper("amd64"), recordingHelper("arm64", file)},
		Hello:    protocol.Hello{Run: "r1"}, Progress: &bytes.Buffer{},
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
	res, err := s.Apply(context.Background(), "file", f, &module.State{})
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
		Dir:      t.TempDir(),
		Binaries: []helperbin.Binary{fakeHelper("arm64")},
		Hello:    protocol.Hello{Run: "r1"},
		Progress: &bytes.Buffer{},
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
func TestOpenTimeouts(t *testing.T) {
	options, _ := sshArgs(t, "web1", "web1")
	for _, want := range []string{"ConnectTimeout=15", "ServerAliveInterval=15"} {
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
echo '{"id":2,"note":"waiting for another apt run (pid 42)"}'
echo '{"id":2,"result":{"status":"ok"}}'
cat >/dev/null
`))
	var progress bytes.Buffer
	s, err := Open(context.Background(), Config{
		Host: "web1", Address: "web1", Dir: t.TempDir(),
		Binaries: []helperbin.Binary{helper},
		Hello:    protocol.Hello{Run: "r1"}, Progress: &progress,
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
	if want := "web1: waiting for another apt run (pid 42)\n"; progress.String() != want {
		t.Errorf("progress = %q, want %q", progress.String(), want)
	}
}
