package module

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/davidklassen/winch/internal/yamlx"
)

// spec: Running a pipeline/Plan
func TestCheckReadsEarlierSteps(t *testing.T) {
	owner, group := yamlx.NameOrID(strconv.Itoa(os.Getuid())), yamlx.NameOrID(strconv.Itoa(os.Getgid()))
	file := func(p, content string) *File {
		return &File{Path: p, Data: []byte(content), Mode: "0644", Owner: owner, Group: group}
	}
	copyFrom := func(p, src string) *File {
		return &File{Path: p, CopyFrom: src, Mode: "0644", Owner: owner, Group: group}
	}
	target := func(s string) *string { return &s }
	tests := []struct {
		name string
		// before are the earlier steps, and step the step whose check the
		// test reads.
		before  func(dir string) []Module
		step    func(dir string) Module
		want    Status
		wantErr func(dir string) string
		changes func(dir string) []string
		// old and new are the texts of the diff; noDiff wants neither.
		old, new string
		noDiff   bool
		// sum is the SHA-256 of the new content; the controller has its text.
		sum string
	}{
		{
			name:    "copy_from a source that an earlier step writes",
			before:  func(dir string) []Module { return []Module{file(dir+"/src", "B\n")} },
			step:    func(dir string) Module { return copyFrom(dir+"/dst", dir+"/src") },
			want:    Change,
			changes: func(dir string) []string { return []string{"content from " + dir + "/src"} },
			old:     "A\n",
			sum:     sha([]byte("B\n")),
		},
		{
			name:    "copy_from a source that an earlier step removes",
			before:  func(dir string) []Module { return []Module{&File{Path: dir + "/src", Absent: true}} },
			step:    func(dir string) Module { return copyFrom(dir+"/dst", dir+"/src") },
			want:    Change,
			changes: func(dir string) []string { return []string{"content from " + dir + "/src (does not exist yet)"} },
			noDiff:  true,
		},
		{
			name: "copy_from a source whose content an earlier step does not know",
			before: func(dir string) []Module {
				return []Module{copyFrom(dir+"/mid", dir+"/missing")}
			},
			step:    func(dir string) Module { return copyFrom(dir+"/dst", dir+"/mid") },
			want:    Change,
			changes: func(dir string) []string { return []string{"content from " + dir + "/mid (does not exist yet)"} },
			noDiff:  true,
		},
		{
			name:    "copy_from a directory that an earlier step makes",
			before:  func(dir string) []Module { return []Module{&Dir{Path: dir + "/srcdir", Owner: owner, Group: group}} },
			step:    func(dir string) Module { return copyFrom(dir+"/dst", dir+"/srcdir") },
			wantErr: func(dir string) string { return dir + "/srcdir is a directory, not a file" },
		},
		{
			name: "copy_from takes the mode of a source that an earlier step writes",
			before: func(dir string) []Module {
				f := file(dir+"/src", "B\n")
				f.Mode = "0640"
				return []Module{f}
			},
			step: func(dir string) Module {
				return &File{Path: dir + "/new", CopyFrom: dir + "/src", Owner: owner, Group: group}
			},
			want: Change,
			changes: func(dir string) []string {
				return []string{"content from " + dir + "/src", attrLine(string(owner), string(group), 0o640)}
			},
			old: "",
		},
		{
			name:   "a file below a link that an earlier step moves",
			before: func(dir string) []Module { return []Module{&Link{Path: dir + "/cur", Target: target("v2")}} },
			step:   func(dir string) Module { return file(dir+"/cur/config", "new\n") },
			want:   OK,
		},
		{
			name:   "a line below a link that an earlier step moves",
			before: func(dir string) []Module { return []Module{&Link{Path: dir + "/cur", Target: target("v2")}} },
			step:   func(dir string) Module { return &Line{Path: dir + "/cur/config", Line: "new", Match: "^new$"} },
			want:   OK,
		},
		{
			name:    "copy_from through a link that an earlier step moves",
			before:  func(dir string) []Module { return []Module{&Link{Path: dir + "/cur", Target: target(dir + "/v2")}} },
			step:    func(dir string) Module { return copyFrom(dir+"/dst", dir+"/cur/config") },
			want:    Change,
			changes: func(dir string) []string { return []string{"content from " + dir + "/cur/config"} },
			old:     "A\n",
			new:     "new\n",
		},
		{
			name:    "copy_from a link that an earlier step makes",
			before:  func(dir string) []Module { return []Module{&Link{Path: dir + "/lnk", Target: target("v2/config")}} },
			step:    func(dir string) Module { return copyFrom(dir+"/dst", dir+"/lnk") },
			want:    Change,
			changes: func(dir string) []string { return []string{"content from " + dir + "/lnk"} },
			old:     "A\n",
			new:     "new\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for p, content := range map[string]string{"src": "A\n", "dst": "A\n", "v1/config": "A\n", "v2/config": "new\n"} {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, p), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			st := &State{}
			for _, m := range tt.before(dir) {
				if _, err := m.Check(t.Context(), st, Silent{}); err != nil {
					t.Fatal(err)
				}
			}
			res, err := tt.step(dir).Check(t.Context(), st, Silent{})
			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr(dir) {
					t.Fatalf("error = %v, want %s", err, tt.wantErr(dir))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != tt.want {
				t.Fatalf("status = %s, want %s; changes %q", res.Status, tt.want, res.Changes)
			}
			if tt.changes != nil && !slices.Equal(res.Changes, tt.changes(dir)) {
				t.Errorf("changes = %q, want %q", res.Changes, tt.changes(dir))
			}
			if tt.noDiff && (res.Old != nil || res.New != nil) {
				t.Errorf("old = %v, new = %v, want no diff", res.Old, res.New)
			}
			if tt.want == Change && !tt.noDiff && (res.Old == nil || *res.Old != tt.old) {
				t.Errorf("old = %v, want %q", res.Old, tt.old)
			}
			if tt.new != "" && (res.New == nil || *res.New != tt.new) {
				t.Errorf("new = %v, want %q", res.New, tt.new)
			}
			if tt.sum != "" && (res.SourceSHA256 != tt.sum || res.New != nil) {
				t.Errorf("source sum = %s, new = %v; want %s and no text, which the controller has", res.SourceSHA256, res.New, tt.sum)
			}
		})
	}
}

// spec: Running a pipeline/Plan
func TestPlannedPaths(t *testing.T) {
	st := &State{Paths: []Planned{
		{Path: "/srv/old"},
		{Path: "/srv/app", Kind: "dir"},
		{Path: "/srv/app/config", Kind: "file", SHA256: "a"},
		{Path: "/srv/file", Kind: "file", SHA256: "b"},
		{Path: "/srv/app/cur", Kind: "link", Target: "v2"},
		{Path: "/srv/app/v2", Kind: "link", Target: "/opt/v2"},
		{Path: "/srv/old/new", Kind: "file", SHA256: "c"},
	}}
	tests := []struct {
		path string
		want Planned
		ok   bool
	}{
		{"/srv/old/x", Planned{Path: "/srv/old/x"}, true},
		{"/srv/old/new", Planned{Path: "/srv/old/new", Kind: "file", SHA256: "c"}, true},
		{"/srv/app/other", Planned{}, false},
		{"/srv/app/config", Planned{Path: "/srv/app/config", Kind: "file", SHA256: "a"}, true},
		{"/srv/file/x", Planned{Path: "/srv/file/x"}, true},
		{"/etc/x", Planned{}, false},
	}
	for _, tt := range tests {
		if got, ok := st.planned(tt.path); got != tt.want || ok != tt.ok {
			t.Errorf("planned(%s) = %+v, %t; want %+v, %t", tt.path, got, ok, tt.want, tt.ok)
		}
	}
	for p, want := range map[string]string{
		"/srv/app/cur/x": "/opt/v2/x",
		"/srv/app/cur":   "/srv/app/cur",
		"/srv/app/x":     "/srv/app/x",
	} {
		if got := st.resolve(p); got != want {
			t.Errorf("resolve(%s) = %s, want %s", p, got, want)
		}
	}
}

// spec: Running a pipeline/Plan
func TestPlanRecordsReplaceTheTree(t *testing.T) {
	st := &State{}
	st.plan(Planned{Path: "/srv/app/config", Kind: "file", SHA256: "a"})
	st.plan(Planned{Path: "/srv/app"})
	st.plan(Planned{Path: "/srv/app", Kind: "dir"})
	if got, ok := st.planned("/srv/app/config"); ok {
		t.Errorf("planned(/srv/app/config) = %+v, want no record: the removal of /srv/app dropped it", got)
	}
	if len(st.Paths) != 1 {
		t.Errorf("paths = %+v, want the record of /srv/app alone", st.Paths)
	}
}

// spec: Running a pipeline/Plan
func TestPlanPkgs(t *testing.T) {
	out := "Inst winch-up [1] (2 test [all])\nInst libfoo:i386 (3 test [i386])\nConf winch-up (2 test [all])\nInst odd\nInst nginx (1.2 Debian:13/stable [arm64]) []\n"
	st := &State{}
	index := []string{"-o", "x"}
	planPkgs(st, out, index, []string{"nginx"})
	want := map[string]PlannedPkg{
		"winch-up": {Version: "2", Arch: "all", Index: index},
		"libfoo":   {Version: "3", Arch: "i386", Index: index},
		"nginx":    {Version: "1.2", Arch: "arm64", Index: index, Named: true},
	}
	if !reflect.DeepEqual(st.Packages, want) {
		t.Errorf("packages = %+v, want %+v", st.Packages, want)
	}
}
