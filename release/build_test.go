//go:build release

package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/buildinfo"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/helperbin"
)

// These tests check the output of a GoReleaser build in ../dist, such as
// goreleaser release --snapshot --clean.

func unpack(t *testing.T, name string, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	files := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		files[h.Name] = content
	}
}

func readArchive(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../dist", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// spec: docs/design/release.md Platforms; Assets
func TestArchives(t *testing.T) {
	sums, err := os.ReadFile("../dist/checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, p := range platforms {
		name := "winch-" + p + ".tar.gz"
		data := readArchive(t, name)
		want = append(want, sum(data)+"  "+name)
		var names []string
		for n := range unpack(t, name, data) {
			names = append(names, n)
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"LICENSE", "README.md", "winch"}) {
			t.Errorf("%s holds %v, want LICENSE, README.md, winch", name, names)
		}
		checkBuild(t, name, p, unpack(t, name, data)["winch"])
	}
	if got := strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n"); !slices.Equal(got, want) {
		t.Errorf("checksums.txt:\n%s\nwant:\n%s", sums, strings.Join(want, "\n"))
	}
}

// checkBuild checks the build info of winch against the design: the
// platform of its archive, pure Go, -trimpath, and the version from git.
func checkBuild(t *testing.T, name, platform string, winch []byte) {
	t.Helper()
	info, err := buildinfo.Read(bytes.NewReader(winch))
	if err != nil {
		t.Errorf("%s: %v", name, err)
		return
	}
	goos, goarch, _ := strings.Cut(platform, "-")
	want := map[string]string{"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0", "-trimpath": "true"}
	for _, s := range info.Settings {
		if w, ok := want[s.Key]; ok {
			if s.Value != w {
				t.Errorf("%s: %s=%s, want %s", name, s.Key, s.Value, w)
			}
			delete(want, s.Key)
		}
		if s.Key == "-ldflags" && strings.Contains(s.Value, "-X") {
			t.Errorf("%s: -ldflags %q sets a variable; the version comes from git", name, s.Value)
		}
	}
	for k, w := range want {
		t.Errorf("%s: no %s, want %s", name, k, w)
	}
	if v := info.Main.Version; v == "" || v == "(devel)" || strings.HasSuffix(v, "+dirty") {
		t.Errorf("%s: version %q, want the version of a clean git commit", name, v)
	}
}

// spec: docs/design/release.md Install/Install script
func TestInstallBuild(t *testing.T) {
	dist, err := filepath.Abs("../dist")
	if err != nil {
		t.Fatal(err)
	}
	in := newInstall(t, sumTools(t))
	if err := os.RemoveAll(filepath.Join(in.releases, "latest/download")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dist, filepath.Join(in.releases, "latest/download")); err != nil {
		t.Fatal(err)
	}
	unameS := map[string]string{"darwin": "Darwin", "linux": "Linux"}[runtime.GOOS]
	unameM := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
	out, err := in.run(unameS, unameM)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "winch v") || !strings.HasSuffix(lines[1], " "+runtime.GOOS+"/"+runtime.GOARCH) {
		t.Errorf("output:\n%s\nwant winch version of the build on the second line", out)
	}
}

// spec: docs/design/release.md Platforms
func TestHelperBytes(t *testing.T) {
	if n := len(helperbin.Binaries()); n != 2 {
		t.Fatalf("the test binary holds %d helpers, want 2", n)
	}
	for _, p := range platforms {
		name := "winch-" + p + ".tar.gz"
		winch := unpack(t, name, readArchive(t, name))["winch"]
		for _, b := range helperbin.Binaries() {
			if !bytes.Contains(winch, b.Data) {
				t.Errorf("%s does not hold the bytes of helper-linux-%s", name, b.Arch)
			}
		}
	}
}

// spec: docs/design/release.md Platforms
func TestHelperReproducible(t *testing.T) {
	head, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "src")
	if out, err := exec.Command("git", "worktree", "add", "--detach", dir, strings.TrimSpace(string(head))).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("git", "worktree", "remove", "--force", dir).CombinedOutput(); err != nil {
			t.Errorf("%v\n%s", err, out)
		}
	})
	build := exec.Command("make", "helpers")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOCACHE="+t.TempDir())
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, b := range helperbin.Binaries() {
		data, err := os.ReadFile(filepath.Join(dir, "internal/helperbin/bin/helper-linux-"+b.Arch))
		if err != nil {
			t.Fatal(err)
		}
		if again := sum(data); again != b.SHA256 {
			t.Errorf("helper-linux-%s: %s, and %s from a second build of the commit", b.Arch, b.SHA256, again)
		}
	}
}
