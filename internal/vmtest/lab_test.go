package vmtest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"testing/synctest"
	"time"
)

// spec: roadmap: Testing/VMs
func TestSnapshotName(t *testing.T) {
	base := snapshotInputs{Image: "aa", Seed: "seed", QEMU: "QEMU emulator version 10.2.0", Flags: "-smp 2 -m 1024"}
	name := snapshotName("debian-13-arm64", base)
	if name != snapshotName("debian-13-arm64", base) {
		t.Fatal("equal inputs give two names")
	}
	if !strings.HasPrefix(name, "snapshot-debian-13-arm64-") {
		t.Errorf("name = %q, want the prefix snapshot-debian-13-arm64-", name)
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
			if got := snapshotName("debian-13-arm64", in); got == name {
				t.Errorf("a changed %s keeps the name %s", c.name, name)
			}
		})
	}
	if snapshotName("debian-13-amd64", base) == name {
		t.Error("another architecture keeps the name")
	}
}

// spec: roadmap: Testing/VMs
func TestRepoName(t *testing.T) {
	defs := func() fstest.MapFS {
		return fstest.MapFS{
			"packages/winch-a/DEBIAN/control":  {Data: []byte("Package: winch-a\nVersion: 1\n")},
			"packages/winch-a/DEBIAN/postinst": {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		}
	}
	name := func(t *testing.T, arch, snapshot string, list []byte, defs fstest.MapFS) string {
		t.Helper()
		defs["debian.list"] = &fstest.MapFile{Data: list}
		input, err := repoInput(defs)
		if err != nil {
			t.Fatal(err)
		}
		return repoName(arch, snapshot, input)
	}
	list := []byte("hello\nnginx\n")
	base := name(t, "debian-13-arm64", "snapshot-debian-13-arm64-1", list, defs())
	if name(t, "debian-13-arm64", "snapshot-debian-13-arm64-1", list, defs()) != base {
		t.Fatal("equal inputs give two names")
	}
	if !strings.HasPrefix(base, "repo-debian-13-arm64-") {
		t.Errorf("name = %q, want the prefix repo-debian-13-arm64-", base)
	}
	for _, c := range []struct {
		name     string
		arch     string
		snapshot string
		list     string
		edit     func(fstest.MapFS)
	}{
		{name: "list", list: "hello\nnginx\ncurl\n"},
		{name: "snapshot", snapshot: "snapshot-debian-13-arm64-2"},
		{name: "architecture", arch: "debian-13-amd64"},
		{name: "definition content", edit: func(fs fstest.MapFS) {
			fs["packages/winch-a/DEBIAN/control"] = &fstest.MapFile{Data: []byte("Package: winch-a\nVersion: 2\n")}
		}},
		{name: "signed list", edit: func(fs fstest.MapFS) {
			fs["signed.list"] = &fstest.MapFile{Data: []byte("rspamd\n")}
		}},
		{name: "new definition", edit: func(fs fstest.MapFS) {
			fs["packages/winch-b/DEBIAN/control"] = &fstest.MapFile{Data: []byte("Package: winch-b\nVersion: 1\n")}
		}},
		{name: "file mode", edit: func(fs fstest.MapFS) {
			fs["packages/winch-a/DEBIAN/postinst"] = &fstest.MapFile{Data: []byte("#!/bin/sh\n"), Mode: 0o644}
		}},
		{name: "file name", edit: func(fs fstest.MapFS) {
			fs["packages/winch-a/DEBIAN/preinst"] = fs["packages/winch-a/DEBIAN/postinst"]
			delete(fs, "packages/winch-a/DEBIAN/postinst")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			arch, snapshot, l, fs := "debian-13-arm64", "snapshot-debian-13-arm64-1", list, defs()
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
			t.Setenv("WINCH_VM_OS", "debian-13")
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

// spec: roadmap: Testing/VMs
func TestWarnings(t *testing.T) {
	for _, c := range []struct {
		name, stdout, stderr string
		want                 []string
	}{
		{name: "none", stdout: "web1\n  base\n", stderr: "web1: base: file /etc/motd: permission denied\n"},
		{name: "text", stderr: "connecting\ninventories/test.yaml:4:14: warning: this looks like a GitHub token; use !secret\n",
			want: []string{"inventories/test.yaml:4:14: warning: this looks like a GitHub token; use !secret"}},
		{name: "JSON", stdout: `{"type":"version","version":1}` + "\n" + `{"type":"diagnostic","severity":"warning","file":"pipelines/site.yml","line":1,"col":1,"message":"winch reads only .yaml"}` + "\n",
			want: []string{`{"type":"diagnostic","severity":"warning","file":"pipelines/site.yml","line":1,"col":1,"message":"winch reads only .yaml"}`}},
		{name: "file name with a space", stderr: "inventories/my hosts.yaml:4:14: warning: x\n", want: []string{"inventories/my hosts.yaml:4:14: warning: x"}},
		{name: "no file", stderr: ":0:0: warning: x\n", want: []string{":0:0: warning: x"}},
		{name: "JSON error", stdout: `{"type":"diagnostic","severity":"error","message":"x"}` + "\n"},
		{name: "host output", stdout: "        +warning: x\n", stderr: "web1: apt-get install: W: warning: y\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := warnings(c.stdout, c.stderr)
			if !slices.Equal(got, c.want) {
				t.Errorf("warnings = %q, want %q", got, c.want)
			}
		})
	}
}

type errLog []string

func (e *errLog) Errorf(format string, args ...any) { *e = append(*e, fmt.Sprintf(format, args...)) }

// spec: roadmap: Testing/VMs
func TestFailOnWarnings(t *testing.T) {
	var got errLog
	failOnWarnings(&got, []string{"plan", "site"}, Result{Stderr: "inventories/test.yaml:4:14: warning: x\n"})
	if want := (errLog{"winch plan site: unexpected warning: inventories/test.yaml:4:14: warning: x"}); !slices.Equal(got, want) {
		t.Errorf("errors = %q, want %q", got, want)
	}
}

func TestExpectedWarnings(t *testing.T) {
	const warning = "recipes/app/recipe.yaml:4:5: warning: purge may remove generated files"
	for _, tt := range []struct {
		name, stderr string
		want         []string
		fail         bool
	}{
		{"expected", warning + "\n", []string{warning}, false},
		{"missing", "", []string{warning}, true},
		{"extra", warning + "\nrecipes/app/recipe.yaml:6:5: warning: other\n", []string{warning}, true},
		{"different", "recipes/app/recipe.yaml:6:5: warning: other\n", []string{warning}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got errLog
			failOnWarnings(&got, []string{"plan", "site"}, Result{Stderr: tt.stderr}, tt.want...)
			if (len(got) > 0) != tt.fail {
				t.Errorf("failures = %v, want failed=%v", got, tt.fail)
			}
		})
	}
}

// spec: roadmap: Testing/VMs
func TestWaitBoot(t *testing.T) {
	// cloud-init gives its errors only with --long, and the output must not
	// go to /dev/null.
	report := `case "$*" in *">/dev/null"*) ;; *--long*) echo 'errors: boom' ;; esac; `
	for _, c := range []struct {
		name string
		ssh  string
		// want holds the parts of the error; none means success.
		want []string
		// wait is the time between ssh starts.
		wait time.Duration
		// The fake clock of a bubble stops while ssh runs, so the time
		// limit cannot end a running ssh.
		realClock bool
	}{
		{name: "done", ssh: "exit 0"},
		{name: "ssh fails first", ssh: `[ -e "$0.ran" ] && exit 0; touch "$0.ran"; exit 255`, wait: 2 * time.Second},
		{name: "error", ssh: report + "exit 1", want: []string{"cloud-init failed", "errors: boom"}},
		{name: "recoverable error", ssh: report + "exit 2", want: []string{"cloud-init failed", "errors: boom"}},
		{name: "time limit", ssh: "exec sleep 30", want: []string{"did not start", "deadline exceeded"}, realClock: true},
	} {
		test := func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "bin", "ssh"), []byte("#!/bin/sh\n"+c.ssh+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			vm := &VM{Name: "base", lab: &Lab{Dir: dir}, dir: dir}
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			start := time.Now()
			err := vm.waitBoot(ctx)
			if elapsed := time.Since(start); !c.realClock && elapsed != c.wait {
				t.Errorf("waitBoot took %s, want %s", elapsed, c.wait)
			}
			if len(c.want) == 0 {
				if err != nil {
					t.Fatalf("waitBoot = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("waitBoot = nil, want an error with %q", c.want)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("waitBoot = %v, want %q in it", err, w)
				}
			}
		}
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if c.realClock {
				test(t)
				return
			}
			synctest.Test(t, test)
		})
	}
}

// spec: roadmap: Testing/VMs
func TestRunRetriesDroppedLogin(t *testing.T) {
	for _, c := range []struct {
		name, first string
		// drops is the number of logins that sshd drops.
		drops, calls int
		ok           bool
	}{
		{"a reset before the handshake", "kex_exchange_identification: read: Connection reset by peer", 1, 2, true},
		{"a second reset", "kex_exchange_identification: read: Connection reset by peer", 2, 2, false},
		{"another failure", "admin@demo: Permission denied (publickey).", 1, 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "calls")
			ssh := fmt.Sprintf("#!/bin/sh\necho x >> %[1]s\nif [ $(wc -l < %[1]s) -le %[3]d ]; then echo %[2]s >&2; exit 255; fi\necho ok\n", calls, Quote(c.first), c.drops)
			if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "bin", "ssh"), []byte(ssh), 0o755); err != nil {
				t.Fatal(err)
			}
			vm := &VM{Name: "demo", lab: &Lab{Dir: dir}}
			out, err := vm.Run(t.Context(), "true")
			if c.ok && (err != nil || out != "ok\n") {
				t.Errorf("Run = %q, %v; want ok", out, err)
			} else if !c.ok && err == nil {
				t.Errorf("Run = %q, want an error", out)
			}
			if got, _ := os.ReadFile(calls); bytes.Count(got, []byte("\n")) != c.calls {
				t.Errorf("ssh ran %q, want %d times", got, c.calls)
			}
		})
	}
}
