package vmtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// spec: roadmap: Testing/VMs
func TestSnapshotName(t *testing.T) {
	base := snapshotInputs{Image: "aa", Seed: "seed", QEMU: "QEMU emulator version 10.2.0", Flags: "-smp 2 -m 1024"}
	name := snapshotName("arm64", base)
	if name != snapshotName("arm64", base) {
		t.Fatal("equal inputs give two names")
	}
	if !strings.HasPrefix(name, "snapshot-arm64-") {
		t.Errorf("name = %q, want the prefix snapshot-arm64-", name)
	}
	for _, c := range []struct {
		name string
		edit func(*snapshotInputs)
	}{
		{"image", func(in *snapshotInputs) { in.Image = "ab" }},
		{"seed", func(in *snapshotInputs) { in.Seed = "seed2" }},
		{"QEMU version", func(in *snapshotInputs) { in.QEMU = "QEMU emulator version 10.2.1" }},
		{"flags", func(in *snapshotInputs) { in.Flags = "-smp 2 -m 2048" }},
		// The inputs are separated, so text that moves from one to the next
		// changes the name.
		{"a boundary", func(in *snapshotInputs) { in.Image, in.Seed = "aas", "eed" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := base
			c.edit(&in)
			if got := snapshotName("arm64", in); got == name {
				t.Errorf("a changed %s keeps the name %s", c.name, name)
			}
		})
	}
	if snapshotName("amd64", base) == name {
		t.Error("another architecture keeps the name")
	}
}

// spec: roadmap: Testing/VMs
func TestRepoName(t *testing.T) {
	defs := func() fstest.MapFS {
		return fstest.MapFS{
			"winch-a/DEBIAN/control":  {Data: []byte("Package: winch-a\nVersion: 1\n")},
			"winch-a/DEBIAN/postinst": {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		}
	}
	name := func(t *testing.T, arch, snapshot string, list []byte, defs fstest.MapFS) string {
		t.Helper()
		input, err := repoInput(list, defs)
		if err != nil {
			t.Fatal(err)
		}
		return repoName(arch, snapshot, input)
	}
	list := []byte("hello\nnginx\n")
	base := name(t, "arm64", "snapshot-arm64-1", list, defs())
	if name(t, "arm64", "snapshot-arm64-1", list, defs()) != base {
		t.Fatal("equal inputs give two names")
	}
	if !strings.HasPrefix(base, "repo-arm64-") {
		t.Errorf("name = %q, want the prefix repo-arm64-", base)
	}
	for _, c := range []struct {
		name     string
		arch     string
		snapshot string
		list     string
		edit     func(fstest.MapFS)
	}{
		{name: "list", list: "hello\nnginx\ncurl\n"},
		{name: "snapshot", snapshot: "snapshot-arm64-2"},
		{name: "architecture", arch: "amd64"},
		{name: "definition content", edit: func(fs fstest.MapFS) {
			fs["winch-a/DEBIAN/control"] = &fstest.MapFile{Data: []byte("Package: winch-a\nVersion: 2\n")}
		}},
		{name: "new definition", edit: func(fs fstest.MapFS) {
			fs["winch-b/DEBIAN/control"] = &fstest.MapFile{Data: []byte("Package: winch-b\nVersion: 1\n")}
		}},
		{name: "file mode", edit: func(fs fstest.MapFS) {
			fs["winch-a/DEBIAN/postinst"] = &fstest.MapFile{Data: []byte("#!/bin/sh\n"), Mode: 0o644}
		}},
		{name: "file name", edit: func(fs fstest.MapFS) {
			fs["winch-a/DEBIAN/preinst"] = fs["winch-a/DEBIAN/postinst"]
			delete(fs, "winch-a/DEBIAN/postinst")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			arch, snapshot, l, fs := "arm64", "snapshot-arm64-1", list, defs()
			if c.arch != "" {
				arch = c.arch
			}
			if c.snapshot != "" {
				snapshot = c.snapshot
			}
			if c.list != "" {
				l = []byte(c.list)
			}
			if c.edit != nil {
				c.edit(fs)
			}
			if got := name(t, arch, snapshot, l, fs); got == base {
				t.Errorf("a changed %s keeps the name %s", c.name, base)
			}
		})
	}
}

// spec: roadmap: Testing/VMs
func TestWriteHost(t *testing.T) {
	dir := t.TempDir()
	l := &Lab{Dir: dir}
	if err := os.Mkdir(filepath.Join(dir, "hosts"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, port := range []string{"2201", "2202"} {
		if _, err := l.WriteHost("demo", "Host demo\n  Port "+port+"\n"); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "hosts", "demo.conf"))
		if err != nil || string(data) != "Host demo\n  Port "+port+"\n" {
			t.Fatalf("demo.conf = %q, %v", data, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "hosts"))
	if err != nil || len(entries) != 1 {
		t.Errorf("hosts holds %v, %v; want only demo.conf", entries, err)
	}
}

// spec: roadmap: Testing/VMs
func TestHint(t *testing.T) {
	list := "/src/test/repo/debian.list"
	for _, c := range []struct {
		name   string
		online bool
		out    string
		want   bool
	}{
		{name: "unknown package", out: "E: Unable to locate package cowsay\n", want: true},
		{name: "no candidate", out: "E: Package 'cowsay' has no installation candidate\n", want: true},
		{name: "online", online: true, out: "E: Unable to locate package cowsay\n"},
		{name: "other error", out: "E: Could not get lock /var/lib/dpkg/lock-frontend\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := &Lab{cfg: Config{Online: c.online}, list: list}
			got := l.hint(c.out)
			if c.want && !strings.Contains(got, list) {
				t.Errorf("hint = %q, want the list %s in it", got, list)
			}
			if !c.want && got != "" {
				t.Errorf("hint = %q, want none", got)
			}
		})
	}
}

// spec: roadmap: Testing/VMs
func TestWriteHostRenames(t *testing.T) {
	dir := t.TempDir()
	l := &Lab{Dir: dir}
	if err := os.Mkdir(filepath.Join(dir, "hosts"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, err := l.WriteHost("demo", "Host demo\n  Port 2201\n")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.WriteHost("demo", "Host demo\n  Port 2202\n"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// A rename puts a new file in place; a write in place keeps the old one,
	// which a parallel ssh can read half written.
	if os.SameFile(before, after) {
		t.Error("the second write changed the file in place")
	}
}

func TestRemoveOthers(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"snapshot-arm64-a", "snapshot-arm64-b", "snapshot-amd64-a", "repo-arm64-a", "tmp-snapshot-1"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeOthers(dir, "snapshot-arm64-", filepath.Join(dir, "snapshot-arm64-b")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if want := "repo-arm64-a snapshot-amd64-a snapshot-arm64-b tmp-snapshot-1"; strings.Join(got, " ") != want {
		t.Errorf("entries = %v, want %s", got, want)
	}
}

func TestFromEnvOnline(t *testing.T) {
	for _, c := range []struct {
		value   string
		online  bool
		wantErr bool
	}{
		{value: "", online: false},
		{value: "1", online: true},
		{value: "yes", wantErr: true},
		{value: "0", wantErr: true},
	} {
		t.Run(c.value, func(t *testing.T) {
			t.Setenv("WINCH_VM_IMAGE", "image")
			t.Setenv("WINCH_VM_ARCH", "arm64")
			t.Setenv("WINCH_VM_CACHE", "cache")
			t.Setenv("WINCH_VM_ONLINE", c.value)
			cfg, err := FromEnv("repo")
			if c.wantErr {
				if err == nil {
					t.Errorf("ONLINE=%s: no error", c.value)
				}
				return
			}
			if err != nil || cfg.Online != c.online {
				t.Errorf("ONLINE=%q: online %v, %v; want %v", c.value, cfg.Online, err, c.online)
			}
		})
	}
}
