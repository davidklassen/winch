package module

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// spec: Modules/download (unpack)
func FuzzUnpack(f *testing.F) {
	type entry struct {
		name, link string
		typ        byte
	}
	tarOf := func(entries ...entry) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for _, e := range entries {
			h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: 0o755}
			if e.typ == tar.TypeReg {
				h.Size = 2
			}
			if err := tw.WriteHeader(h); err != nil {
				f.Fatal(err)
			}
			if e.typ == tar.TypeReg {
				if _, err := tw.Write([]byte("x\n")); err != nil {
					f.Fatal(err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			f.Fatal(err)
		}
		return b.Bytes()
	}
	zipOf := func(entries ...entry) []byte {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		for _, e := range entries {
			h := &zip.FileHeader{Name: e.name}
			h.SetMode(0o644)
			content := "x\n"
			switch e.typ {
			case tar.TypeDir:
				h.SetMode(fs.ModeDir | 0o755)
				content = ""
			case tar.TypeSymlink:
				h.SetMode(fs.ModeSymlink | 0o777)
				content = e.link
			}
			w, err := zw.CreateHeader(h)
			if err != nil {
				f.Fatal(err)
			}
			if _, err := w.Write([]byte(content)); err != nil {
				f.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			f.Fatal(err)
		}
		return b.Bytes()
	}
	// An absolute symlink can point anywhere; seeds point one here.
	elsewhere := f.TempDir()
	for _, entries := range [][]entry{
		{{name: "app/", typ: tar.TypeDir}, {name: "app/bin/tool", typ: tar.TypeReg}, {name: "app/tool", link: "bin/tool", typ: tar.TypeSymlink}},
		{{name: "../outside", typ: tar.TypeReg}},
		{{name: "/abs", typ: tar.TypeReg}},
		{{name: "a/../../outside", typ: tar.TypeReg}},
		{{name: "up", link: "..", typ: tar.TypeSymlink}, {name: "up/outside", typ: tar.TypeReg}},
		{{name: "out", link: "../outside", typ: tar.TypeSymlink}, {name: "out", typ: tar.TypeReg}},
		{{name: "a", typ: tar.TypeReg}, {name: "b", link: "a", typ: tar.TypeLink}, {name: "c", link: "../outside", typ: tar.TypeLink}},
		{{name: "abs", link: elsewhere, typ: tar.TypeSymlink}, {name: "abs/f", typ: tar.TypeReg}},
	} {
		f.Add(tarOf(entries...), false)
		f.Add(zipOf(entries...), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, isZip bool) {
		var zr *zip.Reader
		var names []string
		if isZip {
			var err error
			if zr, err = zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
				return
			}
			for _, f := range zr.File {
				names = append(names, f.Name)
			}
		} else {
			tr := tar.NewReader(bytes.NewReader(data))
			for h, err := tr.Next(); err == nil; h, err = tr.Next() {
				names = append(names, h.Name)
				if h.Typeflag == tar.TypeLink {
					names = append(names, h.Linkname)
				}
			}
		}
		outsideName := slices.ContainsFunc(names, func(n string) bool { return !filepath.IsLocal(n) })
		unpack := func(u unpacker) error {
			if isZip {
				return u.zip(zr)
			}
			return u.tar(bytes.NewReader(data))
		}
		if err := unpack(unpacker{}); outsideName && err == nil {
			t.Errorf("the check of an archive with an entry outside the directory, %q, gives no error", names)
		}
		parent := t.TempDir()
		t.Cleanup(func() {
			// An archive can hold a directory without the owner's permissions.
			_ = filepath.WalkDir(parent, func(p string, d fs.DirEntry, err error) error {
				if d != nil && d.IsDir() {
					_ = os.Chmod(p, 0o700)
				}
				return nil
			})
		})
		outside := filepath.Join(parent, "outside")
		if err := os.WriteFile(outside, []byte("keep\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(parent, "target")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if err := unpack(unpacker{root: root, path: dir, uid: os.Getuid(), gid: os.Getgid()}); outsideName && err == nil {
			t.Errorf("the unpack of an archive with an entry outside the directory, %q, gives no error", names)
		}
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 {
			t.Errorf("the directory around the target holds %v, want only outside and target", entries)
		}
		if b, err := os.ReadFile(outside); err != nil || string(b) != "keep\n" {
			t.Errorf("the file outside the target = %q, %v; want it unchanged", b, err)
		}
		if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) > 0 {
			t.Errorf("the directory of an absolute symlink holds %v, %v; want it empty", entries, err)
		}
	})
}

// spec: Modules/pkg
func FuzzParseDpkg(f *testing.F) {
	f.Add("bash\tamd64\tii \t5.2\nexim4\tamd64\trc \t4.98\nheld\tamd64\thi \t1\npurged\tamd64\tun \t\nlibc6\ti386\trc \t2.40\nlibfoo\tall\tii \t1\nnginx\tamd64\tiF \t1.26.3-3\nheldnone\t\thn \t\n")
	f.Add("bash\tamd64\tii \t5.2\ndpkg-query: warning: something\n")
	f.Add("bash\tamd64\ti\t5.2\n")
	f.Fuzz(func(t *testing.T, out string) {
		pkgs, err := parseDpkg(out, "amd64")
		if err != nil {
			return
		}
		for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
			name, arch, _ := strings.Cut(line, "\t")
			arch, _, _ = strings.Cut(arch, "\t")
			if _, ok := pkgs[name]; !ok {
				if _, ok := pkgs[name+":"+arch]; !ok {
					t.Errorf("the line %q of %q gives no package", line, out)
				}
			}
		}
	})
}

// spec: Modules/service and unit
func FuzzParseShow(f *testing.F) {
	f.Add("Id=nginx.service\nLoadState=loaded\nActiveState=activating\nSubState=auto-restart\nUnitFileState=enabled\nNeedDaemonReload=yes\nDropInPaths=\nTriggeredBy=nginx.socket nginx.path\n")
	f.Add("Id=nginx.service\nLoadState=loaded\nActiveState=active\nFailed to get properties: Access denied\n")
	f.Add("a.service: ConditionPathExists=/x failed.\na.service: ConditionHost=|b failed.\n")
	f.Fuzz(func(t *testing.T, out string) {
		failedConditions("a.service", out)
		if _, err := parseShow(out); err != nil {
			return
		}
		keys := map[string]bool{}
		for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
			k, _, ok := strings.Cut(line, "=")
			if !ok {
				t.Errorf("the line %q of %q is not key=value, and parseShow gave no error", line, out)
			}
			keys[k] = true
		}
		if !keys["Id"] || !keys["LoadState"] || !keys["ActiveState"] {
			t.Errorf("%q has no Id, LoadState, or ActiveState line, and parseShow gave no error", out)
		}
	})
}

// spec: Modules/user and group
func FuzzParseAccounts(f *testing.F) {
	f.Add("# a comment\nroot:x:0:0:root:/root:/bin/bash\n\nalice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\nsvc:x:999:999:::\n")
	f.Add("bob:x:4294967296:0::/:/bin/sh\n")
	f.Add("# a comment\nroot:x:0:\nsudo:x:27:alice,bob\n")
	f.Add("root:x:z:\n")
	f.Fuzz(func(t *testing.T, data string) {
		var rows []string
		for line := range strings.Lines(data) {
			// bufio.ScanLines drops the \r of a \r\n line end.
			if line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"); line != "" && !strings.HasPrefix(line, "#") {
				rows = append(rows, line)
			}
		}
		fieldsOK := func(n int) bool {
			return !slices.ContainsFunc(rows, func(r string) bool { return strings.Count(r, ":") != n-1 })
		}
		if users, err := parsePasswd("/etc/passwd", []byte(data)); err == nil && (len(users) != len(rows) || !fieldsOK(7)) {
			t.Errorf("%q: %d users from the lines %q, and no error", data, len(users), rows)
		}
		if groups, err := parseGroup("/etc/group", []byte(data)); err == nil && (len(groups) != len(rows) || !fieldsOK(4)) {
			t.Errorf("%q: %d groups from the lines %q, and no error", data, len(groups), rows)
		}
	})
}

// spec: Modules/pkg; Modules/upgrade
func FuzzParseApt(f *testing.F) {
	f.Add("Reading package lists...\nInst winch-fragile [1] (2 10.0.2.100 [all])\nInst libbaz (1 10.0.2.100 [arm64])\nConf winch-fragile (2 10.0.2.100 [all])\nRemv winch-up-old [1]\nPurg old\n")
	f.Add("Package: winch-mta-c:armhf\nVersions: \n1 (/var/lib/dpkg/status)\n\nPackage: winch-mta\nVersions: \n\nReverse Provides: \nwinch-mta-a 1 (= )\n")
	f.Add("Inst libc6 [2.41-12] (2.41-12+deb13u1 Debian:13.2/stable [arm64]) []\n")
	f.Fuzz(func(t *testing.T, out string) {
		var inst, remv []string
		changes := 0
		for line := range strings.SplitSeq(out, "\n") {
			f := strings.Fields(line)
			switch {
			case len(f) >= 3 && f[0] == "Inst":
				inst = append(inst, f[1])
				changes++
			case len(f) >= 2 && f[0] == "Remv":
				remv = append(remv, f[1])
				changes++
			case len(f) >= 2 && f[0] == "Purg":
				remv = append(remv, f[1])
			}
		}
		installs, upgrades := parseSimulation(out, []string{"own"})
		for _, n := range slices.Concat(installs, upgrades) {
			if !slices.Contains(inst, n) || n == "own" {
				t.Errorf("parseSimulation: %q is not the package of an Inst line of %q, or is the step's own", n, out)
			}
		}
		for _, n := range parseRemovals(out, []string{"own"}) {
			if !slices.Contains(remv, n) || n == "own" {
				t.Errorf("parseRemovals: %q is not the package of a Remv or Purg line of %q, or is the step's own", n, out)
			}
		}
		if got := parseUpgrade(out); len(got) != changes {
			t.Errorf("parseUpgrade of %q gives %q, want one line for each Inst and Remv line", out, got)
		}
		providers, foreign, known := parseShowpkg(out)
		var names []string
		for n, ps := range providers {
			names = append(names, n)
			names = append(names, ps...)
		}
		for n := range known {
			names = append(names, n)
		}
		for _, n := range slices.Concat(names, slices.Collect(maps.Values(foreign))) {
			if !strings.Contains(out, n) {
				t.Errorf("parseShowpkg: %q is not in the output %q", n, out)
			}
		}
	})
}

// spec: Modules/line
func FuzzLineEdit(f *testing.F) {
	f.Add("bind 127.0.0.1\nmaxmemory 128mb\n", "maxmemory 256mb", "^maxmemory ", false)
	f.Add("a\nb", "c", "^c$", false)
	f.Add("", "x 1", "^x ", false)
	f.Add("session optional pam_motd.so\nauth x\npam_motd\n", "", "pam_motd", true)
	f.Add("a\r\nport 1\r\n", "port 2", "^port", false)
	f.Fuzz(func(t *testing.T, content, line, match string, absent bool) {
		l := &Line{Path: "/etc/a", Line: line, Match: match, Absent: absent}
		if l.Validate() != nil {
			return
		}
		once, _, err := l.edit([]byte(content))
		if err != nil {
			return
		}
		twice, old, err := l.edit(once)
		if err != nil || !bytes.Equal(twice, once) || old != "" {
			t.Errorf("%+v on %q: the first edit gives %q, the second %q with the old lines %q and %v", l, content, once, twice, old, err)
		}
	})
}
