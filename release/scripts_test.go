package release

import (
	"errors"
	"fmt"
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

// spec: docs/design/release.md Install/Homebrew
func TestNotarized(t *testing.T) {
	sums := "testdata/notary/checksums.txt"
	data, err := os.ReadFile(sums)
	if err != nil {
		t.Fatal(err)
	}
	name := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		sha, archive, _ := strings.Cut(line, "  ")
		p := strings.TrimSuffix(strings.TrimPrefix(archive, "winch-"), ".tar.gz")
		name[p] = "winch-" + p + "-" + sha + ".zip"
	}
	type sub struct{ name, status, date string }
	arm := func(status, date string) sub { return sub{name["darwin-arm64"], status, date} }
	intel := func(status, date string) sub { return sub{name["darwin-amd64"], status, date} }
	cases := []struct {
		name    string
		history string // a file in testdata/notary, or empty for subs
		subs    []sub
		want    string
		wantErr string
	}{
		{name: "recorded in progress", history: "history.json", want: "in progress\n"},
		{name: "accepted", subs: []sub{arm("Accepted", "2026-11-02T10:00:00.000Z"), intel("Accepted", "2026-11-02T10:00:00.000Z")}, want: "accepted\n"},
		{name: "one in progress", subs: []sub{arm("Accepted", "2026-11-02T10:00:00.000Z"), intel("In Progress", "2026-11-02T10:00:00.000Z")}, want: "in progress\n"},
		{name: "newest submission counts", subs: []sub{
			arm("Accepted", "2026-11-03T10:00:00.000Z"), arm("Invalid", "2026-11-02T10:00:00.000Z"),
			intel("Invalid", "2026-11-02T10:00:00.000Z"), intel("Accepted", "2026-11-03T10:00:00.000Z"),
		}, want: "accepted\n"},
		{
			name:    "invalid",
			subs:    []sub{arm("Invalid", "2026-11-02T10:00:00.000Z"), intel("Accepted", "2026-11-02T10:00:00.000Z")},
			wantErr: "notarized.sh: Apple did not accept winch-darwin-arm64.tar.gz: status Invalid, submission id-0\n",
		},
		{
			name:    "rejected after in progress",
			subs:    []sub{arm("In Progress", "2026-11-02T10:00:00.000Z"), intel("Rejected", "2026-11-02T10:00:00.000Z")},
			wantErr: "notarized.sh: Apple did not accept winch-darwin-amd64.tar.gz: status Rejected, submission id-1\n",
		},
		{
			name:    "no submission",
			subs:    []sub{arm("Accepted", "2026-11-02T10:00:00.000Z"), {"winch-darwin-amd64-" + strings.Repeat("1", 64) + ".zip", "Accepted", "2026-11-02T10:00:00.000Z"}},
			wantErr: "notarized.sh: HISTORY has no submission " + name["darwin-amd64"] + "\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			history := filepath.Join("testdata/notary", tc.history)
			if tc.history == "" {
				var entries []string
				for i, s := range tc.subs {
					entries = append(entries, fmt.Sprintf(`{"createdDate":%q,"id":"id-%d","name":%q,"status":%q}`, s.date, i, s.name, s.status))
				}
				history = filepath.Join(t.TempDir(), "history.json")
				doc := `{"message":"Successfully received submission history.","history":[` + strings.Join(entries, ",") + `]}`
				if err := os.WriteFile(history, []byte(doc), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, err := exec.Command("sh", "notarized.sh", sums, history).Output()
			var stderr []byte
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = ee.Stderr
			}
			if tc.wantErr != "" {
				want := strings.ReplaceAll(tc.wantErr, "HISTORY", history)
				if err == nil || string(stderr) != want || len(out) != 0 {
					t.Fatalf("err %v, stdout %q, stderr %q, want stderr %q", err, out, stderr, want)
				}
				return
			}
			if err != nil || string(out) != tc.want {
				t.Errorf("err %v, stdout %q, stderr %q, want %q", err, out, stderr, tc.want)
			}
		})
	}
}

// spec: docs/design/release.md Install/Homebrew
func TestNotarizedMissingArchive(t *testing.T) {
	sums := filepath.Join(t.TempDir(), "checksums.txt")
	err := os.WriteFile(sums, []byte("1111111111111111111111111111111111111111111111111111111111111111  winch-darwin-amd64.tar.gz\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "notarized.sh", sums, "testdata/notary/history.json").Output()
	var stderr []byte
	if ee, ok := err.(*exec.ExitError); ok {
		stderr = ee.Stderr
	}
	if want := "notarized.sh: " + sums + " has no line for winch-darwin-arm64.tar.gz\n"; err == nil || string(stderr) != want || len(out) != 0 {
		t.Errorf("err %v, stdout %q, stderr %q, want stderr %q", err, out, stderr, want)
	}
}
