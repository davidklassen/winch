package module

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// spec: Modules/file, dir, link (dir purge: the paths that each module writes)
func TestWrites(t *testing.T) {
	keys := &[]string{"ssh-ed25519 AAAA"}
	tests := []struct {
		name string
		m    Writer
		want []string
	}{
		{"file", &File{Path: "/etc/a"}, []string{"/etc/a"}},
		{"file absent", &File{Path: "/etc/a", Absent: true}, nil},
		{"dir", &Dir{Path: "/etc/d"}, []string{"/etc/d"}},
		{"dir absent", &Dir{Path: "/etc/d", Absent: true}, nil},
		{"link", &Link{Path: "/etc/l", Target: new("/x")}, []string{"/etc/l"}},
		{"link absent", &Link{Path: "/etc/l", Absent: true}, nil},
		{"line", &Line{Path: "/etc/x", Match: "^a", Line: "a"}, []string{"/etc/x"}},
		{"line absent", &Line{Path: "/etc/x", Match: "^a", Absent: true}, nil},
		{"repo", &Repo{Name: "rspamd"}, []string{"/etc/apt/sources.list.d/rspamd.sources"}},
		{"repo with key", &Repo{Name: "rspamd", Key: "rspamd.asc"}, []string{"/etc/apt/sources.list.d/rspamd.sources", "/etc/apt/keyrings/rspamd.asc"}},
		{"unit", &Unit{Name: "x.service"}, []string{"/etc/systemd/system/x.service"}},
		{"download", &Download{Path: "/opt/a.tgz"}, []string{"/opt/a.tgz"}},
		{"download unpack", &Download{Path: "/opt/a.tgz", Unpack: "/opt/a"}, []string{"/opt/a.tgz", "/opt/a"}},
		{"user", &User{Name: "deploy"}, []string{"/home/deploy"}},
		{"user with keys", &User{Name: "deploy", AuthorizedKeys: keys}, []string{"/home/deploy", "/home/deploy/.ssh", "/home/deploy/.ssh/authorized_keys"}},
		{"user with home", &User{Name: "vmail", System: true, Home: "/var/vmail"}, []string{"/var/vmail"}},
		{"system user", &User{Name: "vmail", System: true}, nil},
		{"user absent", &User{Name: "debian", Absent: true}, nil},
		{"cmd", &Cmd{Command: "x"}, nil},
		{"cmd creates", &Cmd{Command: "x", Creates: "/etc/x/done"}, []string{"/etc/x/done"}},
		{"hostname", &Hostname{Name: "mail"}, []string{"/etc/hostname"}},
		{"timezone", &Timezone{Name: "Etc/UTC"}, []string{"/etc/localtime", "/etc/timezone"}},
		{"certbot", &Certbot{Name: "example.com"}, []string{"/etc/letsencrypt/renewal/example.com.conf", "/etc/letsencrypt/live/example.com", "/etc/letsencrypt/archive/example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.Writes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Modules/file, dir, link (dir purge)
func TestPurgeKeeps(t *testing.T) {
	tests := []struct {
		name  string
		dir   string
		entry string
		link  bool
		keep  []string
		owned []string
		want  bool
	}{
		{"written", "/etc/x", "site", false, []string{"/etc/x/site"}, nil, true},
		{"common prefix with a dot", "/etc/x", "site.bak", false, []string{"/etc/x/site"}, nil, false},
		{"common prefix", "/etc/x", "site2", false, []string{"/etc/x/site"}, nil, false},
		{"parent of a written path", "/etc/x", "sub", false, []string{"/etc/x/sub/a/b"}, nil, true},
		{"a directory with a common prefix", "/etc", "conf.d", false, []string{"/etc/conf.d2/a"}, nil, false},
		{"unknown", "/etc/x", "a", false, nil, nil, false},
		{"owned by a package", "/etc/x", "README", false, nil, []string{"/etc/x/README"}, true},
		{"a link that a step writes", "/etc/x", "l", true, []string{"/etc/x/l"}, nil, true},
		{"an unknown link", "/etc/x", "l", true, nil, nil, false},
		{"a wants directory", "/etc/systemd/system", "multi-user.target.wants", false, nil, nil, true},
		{"a requires directory", "/etc/systemd/system", "x.target.requires", false, nil, nil, true},
		{"an upholds directory", "/etc/systemd/system", "x.target.upholds", false, nil, nil, true},
		{"an alias link", "/etc/systemd/system", "sshd.service", true, nil, nil, true},
		{"a unit file", "/etc/systemd/system", "x.service", false, nil, nil, false},
		{"a drop-in directory", "/etc/systemd/system", "x.service.d", false, nil, nil, false},
		{"an enable link", "/etc/systemd/system/multi-user.target.wants", "nginx.service", true, nil, nil, true},
		{"a file in a wants directory", "/etc/systemd/system/multi-user.target.wants", "junk", false, nil, nil, false},
		{"a link in a drop-in directory", "/etc/systemd/system/x.service.d", "l", true, nil, nil, false},
		{"a wants directory elsewhere", "/etc/x", "a.wants", false, nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owned := map[string]string{}
			for _, p := range tt.owned {
				owned[p] = "pkg"
			}
			if got := keeps(tt.dir, tt.entry, tt.link, tt.keep, owned); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// spec: Modules/file, dir, link (keep globs match entry names)
func TestPurgeKeepPatterns(t *testing.T) {
	for _, tt := range []struct {
		name     string
		patterns []string
		want     bool
	}{
		{"virtual.db", []string{"*.db"}, true},
		{"virtual.db.bak", []string{"*.db"}, false},
		{".hidden.db", []string{"*.db"}, true},
		{"virtual.db", []string{"*.log", "*.db"}, true},
		{"map1.db", []string{"map[0-9].?b"}, true},
		{"mapx.db", []string{"map[0-9].?b"}, false},
		{"map*.db", []string{`map\*.db`}, true},
		{"virtual.db", []string{"/etc/maps/*.db"}, false},
	} {
		t.Run(tt.name+strings.Join(tt.patterns, ","), func(t *testing.T) {
			d := &Dir{Path: "/etc/maps", KeepPatterns: tt.patterns}
			for _, link := range []bool{false, true} {
				if got := d.keeps(tt.name, link, nil); got != tt.want {
					t.Errorf("keeps(%q, link=%v) = %v, want %v", tt.name, link, got, tt.want)
				}
			}
		})
	}
}

// spec: Modules/file, dir, link (stock: the package archive)
func TestArchiveName(t *testing.T) {
	tests := []struct{ pkg, version, arch, want string }{
		{"nginx-common", "1.26.3-3+deb13u10", "all", "nginx-common_1.26.3-3+deb13u10_all.deb"},
		{"libc6", "2.41-12", "arm64", "libc6_2.41-12_arm64.deb"},
		{"dovecot-core", "1:2.4.1+dfsg1-6", "amd64", "dovecot-core_1%3a2.4.1+dfsg1-6_amd64.deb"},
	}
	for _, tt := range tests {
		if got := archiveName(tt.pkg, tt.version, tt.arch); got != tt.want {
			t.Errorf("archiveName(%s, %s, %s) = %s, want %s", tt.pkg, tt.version, tt.arch, got, tt.want)
		}
	}
}

// spec: Modules/file, dir, link (stock: the defaults come from the source)
func TestTarEntry(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range []*tar.Header{
		{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "./etc/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "./etc/x.conf", Mode: 0o640, Uname: "root", Gname: "adm", Gid: 4, Size: 6},
		{Name: "./etc/l", Typeflag: tar.TypeSymlink, Linkname: "x.conf", Mode: 0o777},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte("stock\n")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	data, hdr, err := tarEntry(bytes.NewReader(buf.Bytes()), "/etc/x.conf")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "stock\n" || hdr.Uname != "root" || hdr.Gname != "adm" || hdr.Mode&0o7777 != 0o640 {
		t.Errorf("got %q, %s %s %o", data, hdr.Uname, hdr.Gname, hdr.Mode)
	}
	for p, want := range map[string]string{
		"/etc/missing": "the archive has no /etc/missing",
		"/etc/l":       "the archive has /etc/l as a symbolic link, not a file",
		"/etc":         "the archive has /etc as a directory, not a file",
	} {
		if _, _, err := tarEntry(bytes.NewReader(buf.Bytes()), p); err == nil || err.Error() != want {
			t.Errorf("%s: error %v, want %q", p, err, want)
		}
	}
}

// spec: Modules/file, dir, link (an installed package owns a path)
func TestDpkgOwners(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.list":       "/.\n/etc\n/etc/a\n/etc/a.d\n",
		"b:arm64.list": "/etc/b\n",
		"a.md5sums":    "x  etc/c\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := dpkgOwners(os.DirFS(dir), map[string]bool{"/etc/a": true, "/etc/b": true, "/etc/c": true, "/etc/a.d": true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"/etc/a": "a", "/etc/a.d": "a", "/etc/b": "b:arm64"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// spec: Modules/file, dir, link (stock: the helper reads the package archive)
func TestDebEntryStopsEarly(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	big := bytes.Repeat([]byte("x"), 4<<20)
	for _, e := range []struct {
		name string
		data []byte
	}{{"./etc/x.conf", []byte("stock\n")}, {"./usr/share/big", big}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tarball := filepath.Join(dir, "data.tar")
	if err := os.WriteFile(tarball, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	// dpkg-deb writes the data archive from a child process.
	script := "#!/bin/sh\ncat " + tarball + " | cat\n"
	if err := os.WriteFile(filepath.Join(dir, "dpkg-deb"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	data, _, err := debEntry(ctx, "x.deb", "/etc/x.conf")
	if err != nil || string(data) != "stock\n" {
		t.Errorf("got %q, %v", data, err)
	}
	if ctx.Err() != nil {
		t.Error("debEntry waited for the end of the archive")
	}
}

// spec: Modules/file, dir, link (dir purge: each module writes known paths)
func TestEveryModuleDeclaresItsWrites(t *testing.T) {
	writesNothing := []string{"assert", "debconf", "group", "pkg", "reboot", "service", "upgrade"}
	for _, name := range Names() {
		m, _ := New(name)
		if _, ok := m.(Writer); ok == slices.Contains(writesNothing, name) {
			t.Errorf("module %s: Writer is %v; a module that writes paths implements Writer, and one that writes none is in the list", name, ok)
		}
	}
}

// spec: Running a pipeline/Plan (the hash covers the check results)
func TestCopyFromResultNamesTheSource(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	f := &File{Path: dst, CopyFrom: src}
	var sums []string
	for _, content := range []string{"a\n", "b\n"} {
		if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := f.Check(t.Context(), &State{}, func(string) {})
		if err != nil {
			t.Fatal(err)
		}
		sums = append(sums, res.SourceSHA256)
	}
	if sums[0] == "" || sums[0] == sums[1] {
		t.Errorf("source sums %q: want two different ones", sums)
	}
}
