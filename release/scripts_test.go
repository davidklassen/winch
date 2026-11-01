package release

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/golden"
)

const changelog = `# Changelog

## v0.2.0

### Breaking changes

- A break.

### Added

- A module.

## v0.1.0

### Added

- The first module.
`

// spec: docs/design/release.md Build; Release notes
func TestNotes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(changelog), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ tag, file, want, wantErr string }{
		{tag: "v0.2.0", want: "### Breaking changes\n\n- A break.\n\n### Added\n\n- A module.\n"},
		{tag: "v0.1.0", want: "### Added\n\n- The first module.\n"},
		{tag: "v0.2.0-rc.1", want: "### Breaking changes\n\n- A break.\n\n### Added\n\n- A module.\n"},
		{tag: "v0.3.0", wantErr: "notes.sh: " + path + " has no section ## v0.3.0\n"},
		{tag: "v0.1.0", file: path + ".missing", wantErr: "notes.sh: " + path + ".missing does not exist\n"},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			var stderr []byte
			file := path
			if tc.file != "" {
				file = tc.file
			}
			out, err := exec.Command("sh", "notes.sh", tc.tag, file).Output()
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = ee.Stderr
			}
			if tc.wantErr != "" {
				if err == nil || string(stderr) != tc.wantErr {
					t.Fatalf("err %v, stderr %q, want %q", err, stderr, tc.wantErr)
				}
				return
			}
			if err != nil || string(out) != tc.want {
				t.Errorf("err %v, stderr %q\nnotes:\n%s\nwant:\n%s", err, stderr, out, tc.want)
			}
		})
	}
}

// spec: docs/design/release.md Build; Install/Homebrew
func TestCask(t *testing.T) {
	sums := filepath.Join(t.TempDir(), "checksums.txt")
	err := os.WriteFile(sums, []byte(
		"1111111111111111111111111111111111111111111111111111111111111111  winch-darwin-amd64.tar.gz\n"+
			"2222222222222222222222222222222222222222222222222222222222222222  winch-darwin-arm64.tar.gz\n"+
			"3333333333333333333333333333333333333333333333333333333333333333  winch-linux-amd64.tar.gz\n"+
			"4444444444444444444444444444444444444444444444444444444444444444  winch-linux-arm64.tar.gz\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "cask.sh", "v0.1.0", sums).Output()
	if err != nil {
		t.Fatalf("%v", err)
	}
	golden.Assert(t, "testdata/winch.rb", out)
}

// spec: docs/design/release.md Build; Install/Homebrew
func TestCaskMissingArchive(t *testing.T) {
	sums := filepath.Join(t.TempDir(), "checksums.txt")
	err := os.WriteFile(sums, []byte("1111111111111111111111111111111111111111111111111111111111111111  winch-darwin-amd64.tar.gz\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "cask.sh", "v0.1.0", sums).Output()
	var stderr []byte
	if ee, ok := err.(*exec.ExitError); ok {
		stderr = ee.Stderr
	}
	if want := "cask.sh: " + sums + " has no line for winch-darwin-arm64.tar.gz\n"; err == nil || string(stderr) != want || len(out) != 0 {
		t.Errorf("err %v, stdout %q, stderr %q, want stderr %q", err, out, stderr, want)
	}
}

// spec: docs/design/release.md Release notes
func TestChangelog(t *testing.T) {
	data, err := os.ReadFile("../CHANGELOG.md")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no CHANGELOG.md; the release workflow needs it when a tag is pushed")
	}
	if err != nil {
		t.Fatal(err)
	}
	groups := []string{"### Breaking changes", "### Added", "### Fixed"}
	var versions []string
	next, items := 0, 0
	end := func(line string) {
		if items == 0 && next > 0 {
			t.Errorf("CHANGELOG.md: %s: the group before %q is empty", versions[len(versions)-1], line)
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			end(line)
			v := strings.TrimPrefix(line, "## ")
			if !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(v) {
				t.Errorf("CHANGELOG.md: section %q, want ## vX.Y.Z", line)
			}
			versions = append(versions, v)
			next, items = 0, 0
		case strings.HasPrefix(line, "### "):
			end(line)
			i := slices.Index(groups, line)
			if i < next {
				t.Errorf("CHANGELOG.md: %s: group %q, want one of %v in this order", versions[len(versions)-1], line, groups[next:])
			}
			next, items = i+1, 0
		case strings.HasPrefix(line, "- "):
			items++
		}
	}
	end("the end")
	if len(versions) == 0 {
		t.Fatal("CHANGELOG.md has no section")
	}
	for _, v := range versions {
		if out, err := exec.Command("sh", "notes.sh", v, "../CHANGELOG.md").CombinedOutput(); err != nil {
			t.Errorf("notes.sh %s: %v\n%s", v, err, out)
		}
	}
}
