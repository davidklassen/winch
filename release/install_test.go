package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The fake curl serves the release URLs from $RELEASES, as curl -f does:
// a missing file is error 22. It logs each call to $RELEASES/curl.log.
const fakeCurl = `#!/bin/sh
echo "$@" >>"$RELEASES/curl.log"
if [ "$1" != -fsSL ]; then
	echo "fake curl: the first argument is $1, want -fsSL" >&2
	exit 2
fi
out= url=
while [ $# -gt 0 ]; do
	case $1 in
	-o) out=$2; shift ;;
	-*) ;;
	*) url=$1 ;;
	esac
	shift
done
file=$RELEASES/${url#https://github.com/davidklassen/winch/releases/}
if [ ! -f "$file" ]; then
	echo "curl: (22) The requested URL returned error: 404" >&2
	exit 22
fi
cp "$file" "$out"
`

const fakeUname = `#!/bin/sh
case $1 in -s) echo "$UNAME_S" ;; -m) echo "$UNAME_M" ;; esac
`

var (
	platforms = []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64"}
	tools     = []string{"sh", "awk", "cat", "chmod", "cp", "cut", "gzip", "mkdir", "mktemp", "mv", "rm", "tar"}
	// fakes holds curl and uname. macOS checks each new executable file at
	// its first run, which takes a fraction of a second, so all tests share
	// one copy.
	fakes string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "winch-install-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fakes = dir
	for name, content := range map[string]string{"curl": fakeCurl, "uname": fakeUname} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

type install struct {
	t        *testing.T
	releases string
	bin      string
	home     string
}

// newInstall makes a fake GitHub with the release latest/download and the
// pre-release v0.2.0-rc.1, and a PATH with only the tools the script needs
// and the checksum tools in sums.
func newInstall(t *testing.T, sums []string) *install {
	t.Helper()
	dir := t.TempDir()
	in := &install{t: t, releases: filepath.Join(dir, "releases"), bin: filepath.Join(dir, "bin"), home: filepath.Join(dir, "home")}
	in.release("latest/download", "winch v0.1.0")
	in.release("download/v0.2.0-rc.1", "winch v0.2.0-rc.1")
	for _, d := range []string{in.bin, in.home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range append(tools, sums...) {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("%s is not installed", name)
		}
		if err := os.Symlink(path, filepath.Join(in.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	return in
}

// sumTools returns the checksum tools of this machine.
func sumTools(t *testing.T) []string {
	var found []string
	for _, name := range []string{"sha256sum", "shasum"} {
		if _, err := exec.LookPath(name); err == nil {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		t.Fatal("neither sha256sum nor shasum is installed")
	}
	return found
}

func (in *install) write(path, content string) {
	in.t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		in.t.Fatal(err)
	}
}

// release writes the four archives, whose winch prints line, and
// checksums.txt into dir.
func (in *install) release(dir, line string) {
	in.t.Helper()
	dir = filepath.Join(in.releases, dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		in.t.Fatal(err)
	}
	var sums strings.Builder
	for _, p := range platforms {
		name := "winch-" + p + ".tar.gz"
		data := archive(in.t, fmt.Sprintf("#!/bin/sh\necho '%s %s'\n", line, strings.Replace(p, "-", "/", 1)))
		in.write(filepath.Join(dir, name), string(data))
		fmt.Fprintf(&sums, "%s  %s\n", sum(data), name)
	}
	in.write(filepath.Join(dir, "checksums.txt"), sums.String())
}

// archive makes a release archive whose winch is the script winch.
func archive(t *testing.T, winch string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name, content string
		mode          int64
	}{{"winch", winch, 0o755}, {"LICENSE", "license\n", 0o644}, {"README.md", "readme\n", 0o644}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// run pipes install.sh into sh, as curl | sh does, on the platform of
// uname -s and uname -m. PATH in env replaces the default PATH.
func (in *install) run(osName, arch string, env ...string) (string, error) {
	in.t.Helper()
	script, err := os.Open("install.sh")
	if err != nil {
		in.t.Fatal(err)
	}
	defer script.Close()
	cmd := exec.Command(filepath.Join(in.bin, "sh"))
	cmd.Stdin = script
	cmd.Env = append([]string{"PATH=" + fakes + ":" + in.bin, "HOME=" + in.home, "RELEASES=" + in.releases,
		"UNAME_S=" + osName, "UNAME_M=" + arch}, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// spec: docs/design/release.md Install/Install script
func TestInstall(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, os, arch string
		env            []string
		dir            string // WINCH_INSTALL_DIR under HOME
		inPath         bool
		edit           func(in *install)
		wantErr        string
		want           string // the line the installed winch prints
	}{
		{name: "darwin arm64", os: "Darwin", arch: "arm64", want: "winch v0.1.0 darwin/arm64"},
		{name: "darwin amd64", os: "Darwin", arch: "x86_64", want: "winch v0.1.0 darwin/amd64"},
		{name: "linux amd64", os: "Linux", arch: "x86_64", want: "winch v0.1.0 linux/amd64"},
		{name: "linux arm64", os: "Linux", arch: "aarch64", want: "winch v0.1.0 linux/arm64"},
		{name: "linux arm64 as arm64", os: "Linux", arch: "arm64", want: "winch v0.1.0 linux/arm64"},
		{name: "install dir", os: "Linux", arch: "x86_64", dir: "tools", want: "winch v0.1.0 linux/amd64"},
		{name: "in PATH", os: "Linux", arch: "x86_64", dir: "tools", inPath: true, want: "winch v0.1.0 linux/amd64"},
		{name: "no HOME", os: "Linux", arch: "x86_64", env: []string{"HOME="},
			wantErr: "install.sh: HOME is not set; set WINCH_INSTALL_DIR to the directory for winch\n"},
		{name: "version", os: "Linux", arch: "aarch64", env: []string{"WINCH_VERSION=v0.2.0-rc.1"}, want: "winch v0.2.0-rc.1 linux/arm64"},
		{name: "unknown os", os: "FreeBSD", arch: "amd64",
			wantErr: "install.sh: winch has no build for FreeBSD amd64; it runs on macOS and Linux, on amd64 and arm64\n"},
		{name: "unknown arch", os: "Linux", arch: "armv7l",
			wantErr: "install.sh: winch has no build for Linux armv7l; it runs on macOS and Linux, on amd64 and arm64\n"},
		{name: "unknown version", os: "Linux", arch: "x86_64", env: []string{"WINCH_VERSION=v9.9.9"},
			wantErr: "curl: (22) The requested URL returned error: 404\n" +
				"install.sh: cannot download https://github.com/davidklassen/winch/releases/download/v9.9.9/winch-linux-amd64.tar.gz; check WINCH_VERSION\n"},
		{name: "missing archive", os: "Linux", arch: "x86_64",
			edit: func(in *install) {
				if err := os.Remove(filepath.Join(in.releases, "latest/download/winch-linux-amd64.tar.gz")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "curl: (22) The requested URL returned error: 404\n" +
				"install.sh: cannot download https://github.com/davidklassen/winch/releases/latest/download/winch-linux-amd64.tar.gz\n"},
		{name: "bad checksum", os: "Darwin", arch: "arm64",
			edit: func(in *install) {
				in.write(filepath.Join(in.releases, "latest/download/winch-darwin-arm64.tar.gz"), "not the archive")
			},
			wantErr: "install.sh: the SHA-256 of winch-darwin-arm64.tar.gz is not the one in checksums.txt; nothing is installed\n"},
		{name: "no checksum line", os: "Darwin", arch: "arm64",
			edit: func(in *install) {
				in.write(filepath.Join(in.releases, "latest/download/checksums.txt"), "")
			},
			wantErr: "install.sh: checksums.txt has no line for winch-darwin-arm64.tar.gz; nothing is installed\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := newInstall(t, sumTools(t))
			if tc.edit != nil {
				tc.edit(in)
			}
			dir := filepath.Join(in.home, ".local/bin")
			env := tc.env
			if tc.dir != "" {
				dir = filepath.Join(in.home, tc.dir)
				env = append(env, "WINCH_INSTALL_DIR="+dir)
			}
			if tc.inPath {
				env = append(env, "PATH="+fakes+":"+in.bin+":"+dir)
			}
			out, err := in.run(tc.os, tc.arch, env...)
			if tc.wantErr != "" {
				if err == nil || out != tc.wantErr {
					t.Fatalf("err %v, output:\n%s\nwant an error with:\n%s", err, out, tc.wantErr)
				}
				if _, err := os.Stat(filepath.Join(dir, "winch")); !os.IsNotExist(err) {
					t.Errorf("winch is installed after an error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			want := "installed " + filepath.Join(dir, "winch") + "\n" + tc.want + "\n"
			if !tc.inPath {
				want += fmt.Sprintf("%s is not in PATH; add it with:\nexport PATH=\"%s:$PATH\"\n", dir, dir)
			}
			if out != want {
				t.Errorf("output:\n%s\nwant:\n%s", out, want)
			}
			fi, err := os.Stat(filepath.Join(dir, "winch"))
			if err != nil || fi.Mode().Perm() != 0o755 {
				t.Fatalf("installed winch: %v, mode %v", err, fi.Mode())
			}
		})
	}
}

// spec: docs/design/release.md Install/Install script
func TestInstallReplaces(t *testing.T) {
	t.Parallel()
	in := newInstall(t, sumTools(t))
	dir := filepath.Join(in.home, ".local/bin")
	if out, err := in.run("Linux", "x86_64", "WINCH_VERSION=v0.2.0-rc.1"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err := in.run("Linux", "x86_64")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "\nwinch v0.1.0 linux/amd64\n") {
		t.Errorf("second run output:\n%s\nwant the newest release", out)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("install dir holds %v (%v), want only winch", entries, err)
	}
}

// spec: docs/design/release.md Install/Install script
func TestInstallChecksumTools(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tools   []string
		wantErr string
	}{
		{tools: []string{"sha256sum"}},
		{tools: []string{"shasum"}},
		{tools: nil, wantErr: "install.sh: needs sha256sum or shasum to check the download\n"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.tools), func(t *testing.T) {
			t.Parallel()
			for _, name := range tc.tools {
				if _, err := exec.LookPath(name); err != nil {
					t.Skipf("%s is not installed", name)
				}
			}
			in := newInstall(t, tc.tools)
			out, err := in.run("Darwin", "arm64")
			if tc.wantErr != "" {
				if err == nil || out != tc.wantErr {
					t.Fatalf("err %v, output:\n%s\nwant an error with:\n%s", err, out, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}

// spec: docs/design/release.md Install/Install script
func TestInstallKeepsOldOnError(t *testing.T) {
	t.Parallel()
	in := newInstall(t, sumTools(t))
	dir := filepath.Join(in.home, ".local/bin")
	if out, err := in.run("Linux", "x86_64", "WINCH_VERSION=v0.2.0-rc.1"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	in.write(filepath.Join(in.releases, "latest/download/winch-linux-amd64.tar.gz"), "not the archive")
	if out, err := in.run("Linux", "x86_64"); err == nil {
		t.Fatalf("a bad checksum installs:\n%s", out)
	}
	out, err := exec.Command(filepath.Join(dir, "winch")).Output()
	if err != nil || string(out) != "winch v0.2.0-rc.1 linux/amd64\n" {
		t.Errorf("the old winch prints %q (%v), want the pre-release", out, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("install dir holds %v (%v), want only winch", entries, err)
	}
}

// spec: docs/design/release.md Install/Install script
func TestInstallWinchFails(t *testing.T) {
	t.Parallel()
	in := newInstall(t, sumTools(t))
	data := archive(t, "#!/bin/sh\nexit 3\n")
	in.write(filepath.Join(in.releases, "latest/download/winch-linux-amd64.tar.gz"), string(data))
	in.write(filepath.Join(in.releases, "latest/download/checksums.txt"), sum(data)+"  winch-linux-amd64.tar.gz\n")
	out, err := in.run("Linux", "x86_64")
	path := filepath.Join(in.home, ".local/bin/winch")
	want := "installed " + path + "\ninstall.sh: " + path + " does not run\n"
	if err == nil || out != want {
		t.Errorf("err %v, output:\n%s\nwant an error with:\n%s", err, out, want)
	}
}

// spec: docs/design/release.md Install/Install script
func TestInstallCut(t *testing.T) {
	t.Parallel()
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	in := newInstall(t, sumTools(t))
	for i := range len(script) - 1 {
		if script[i] != '\n' {
			continue
		}
		cmd := exec.Command(filepath.Join(in.bin, "sh"))
		cmd.Stdin = bytes.NewReader(script[:i+1])
		cmd.Env = []string{"PATH=" + fakes + ":" + in.bin, "HOME=" + in.home, "RELEASES=" + in.releases, "UNAME_S=Linux", "UNAME_M=x86_64"}
		out, _ := cmd.CombinedOutput()
		if _, err := os.Stat(filepath.Join(in.releases, "curl.log")); !os.IsNotExist(err) {
			t.Fatalf("the script cut after byte %d calls curl:\n%s", i+1, out)
		}
		if _, err := os.Stat(filepath.Join(in.home, ".local")); !os.IsNotExist(err) {
			t.Fatalf("the script cut after byte %d makes the install directory:\n%s", i+1, out)
		}
	}
}
