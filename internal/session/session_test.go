package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

// fakeHelper answers hello with an error that names its architecture, so a
// test can see which helper ran.
func fakeHelper(arch string) helperbin.Binary {
	return helperbin.New(arch, []byte("#!/bin/sh\nread line\necho '{\"id\":1,\"error\":\"ran "+arch+"\"}'\n"))
}

// fakeBin puts fake ssh, uname, id, and sudo first in PATH. ssh runs its
// last argument with sh, on this machine.
func fakeBin(t *testing.T, arch, uid, sudo string) {
	t.Helper()
	bin := t.TempDir()
	scripts := map[string]string{
		"ssh":   "#!/bin/sh\neval \"cmd=\\${$#}\"\nexec sh -c \"$cmd\"\n",
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
  *'"method":"apply"'*'"content":'*) echo '{"id":'$id',"result":{"status":"change","action":"create"}}' ;;
  *'"method":"apply"'*) echo '{"id":'$id',"error":"apply needs the content","need_content":true}' ;;
  *) echo '{"id":'$id',"result":{"status":"ok"}}' ;;
  esac
done
`
	return helperbin.New(arch, []byte(script))
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
	f := &module.File{Path: "/etc/motd", Content: &content}
	if _, err := s.Check(context.Background(), "file", f); err != nil {
		t.Fatal(err)
	}
	res, err := s.Apply(context.Background(), "file", f)
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
		if got := strings.Contains(lines[i], content); got != wantContent {
			t.Errorf("request %d has content = %v, want %v: %s", i+1, got, wantContent, lines[i])
		}
	}
	if !strings.Contains(lines[1], `"content_sha256":`) {
		t.Errorf("check has no hash: %s", lines[1])
	}
	if f.Content == nil || *f.Content != content {
		t.Error("check changed the step")
	}
}
