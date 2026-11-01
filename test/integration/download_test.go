package integration

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/vmtest"
)

func sha(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

type entry struct {
	name, body, link string
	mode             int64
	typ              byte
}

func tarGz(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: e.typ, Linkname: e.link, Size: int64(len(e.body)), Uname: "nobody", Uid: 65534}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// spec: Modules/download
func TestDownloadModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "download")
	v1, v2 := []byte("version 1\n"), []byte("version 2\n")
	url1 := lab.Serve(t, "download/v1", v1)
	url2 := lab.Serve(t, "download/v2", v2)
	missing := strings.TrimSuffix(url1, "v1") + "missing"
	attrs := "owner root, group root, mode 0644"
	record := "/var/lib/winch/downloads/test"
	recordV1 := "mkdir -p /var/lib/winch/downloads && printf 'version 1\\n%s\\n' '" + sha(v1) + " /tmp/w/f' > " + record

	tgz := tarGz(t, []entry{
		{name: "./", typ: tar.TypeDir, mode: 0o700},
		{name: "app/", typ: tar.TypeDir, mode: 0o755},
		{name: "app/bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho tool\n"},
		{name: "app/README", typ: tar.TypeReg, mode: 0o664, body: "read me\n"},
		{name: "app/latest", typ: tar.TypeSymlink, link: "bin/tool"},
		{name: "app/hard", typ: tar.TypeLink, link: "app/README"},
	})
	urlTgz := lab.Serve(t, "download/app.tar.gz", tgz)
	tgz2 := tarGz(t, []entry{{name: "app/bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho tool2\n"}})
	urlTgz2 := lab.Serve(t, "download/app2.tar.gz", tgz2)
	urlShort := lab.Serve(t, "download/app.tgz", tgz2)
	late := tarGz(t, []entry{
		{name: "good", typ: tar.TypeReg, mode: 0o644, body: "x\n"},
		{name: "../evil", typ: tar.TypeReg, mode: 0o644, body: "x\n"},
	})
	urlLate := lab.Serve(t, "download/late.tar.gz", late)
	unpackRecord := sha(tgz) + ":root:root /tmp/w/opt"
	unpacked := "mkdir -p /var/lib/winch/downloads && printf 'version 1\\n%s\\n' '" + unpackRecord + "' > " + record
	extracted := unpacked + " && mkdir /tmp/w/opt && curl -sf " + urlTgz + " | tar -C /tmp/w/opt -xzf -"
	unpackLine := "unpack into /tmp/w/opt (owner root, group root)"
	evil := tarGz(t, []entry{{name: "../evil", typ: tar.TypeReg, mode: 0o644, body: "x\n"}})
	urlEvil := lab.Serve(t, "download/evil.tar.gz", evil)
	escape := tarGz(t, []entry{
		{name: "out", typ: tar.TypeSymlink, link: "/tmp/w"},
		{name: "out/escaped", typ: tar.TypeReg, mode: 0o644, body: "x\n"},
	})
	urlEscape := lab.Serve(t, "download/escape.tar.gz", escape)

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for _, f := range []struct {
		name string
		mode uint32
		body string
	}{{"z/a.txt", 0o644, "a\n"}, {"z/bin/run", 0o755, "#!/bin/sh\n"}, {"z/link", 0o777 | uint32(fs.ModeSymlink), "a.txt"}} {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		h.SetMode(fs.FileMode(f.mode&0o777) | fs.FileMode(f.mode)&fs.ModeSymlink)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	urlZip := lab.Serve(t, "download/z.zip", zbuf.Bytes())

	out := vm.MustRun(t, "rm -rf /tmp/x && mkdir -p /tmp/x/xd && echo xz > /tmp/x/xd/f && head -c 1000000 /dev/urandom > /tmp/x/xd/random && tar -C /tmp/x -cJf - xd | base64 -w0")
	txz, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatal(err)
	}
	urlTxz := lab.Serve(t, "download/x.tar.xz", txz)
	broken := txz[:len(txz)/2]
	urlBroken := lab.Serve(t, "download/broken.tar.xz", broken)

	reset := "[ ! -e /usr/bin/xz.off ] || mv /usr/bin/xz.off /usr/bin/xz\n[ -e /etc/ssl/certs ] || mv /etc/ssl/certs.off /etc/ssl/certs\n[ ! -d /tmp/w ] || find /tmp/w -depth -mindepth 1 -type d -exec mountpoint -q {} \\; -exec umount {} \\;\n[ ! -d /tmp/w ] || find /tmp/w \\( -type f -o -type d \\) -exec chattr -ia {} +\nrm -rf /tmp/w " + record + " && mkdir /tmp/w"
	t.Run("a failed unpack stays a change and keeps the old tree", func(t *testing.T) {
		ctx := t.Context()
		s := vm.Session(t)
		vm.MustRun(t, reset+"\n"+extracted)
		args := &module.Download{URL: urlEscape, SHA256: sha(escape), Unpack: "/tmp/w/opt", Owner: "admin"}
		if _, err := s.Apply(ctx, "download", args, &module.State{}, nil, nil, nil, protocol.Guard{}); err == nil || !strings.Contains(err.Error(), "unpack "+urlEscape+" into /tmp/w/opt") {
			t.Fatalf("apply of an archive with a link out of the directory = %v, want an unpack error", err)
		}
		want := []string{"download " + urlEscape + " (no record of an earlier download)", "unpack into /tmp/w/opt (owner admin, group root)", "remove its content: 4 files, 2 directories"}
		got, err := s.Check(ctx, "download", args, &module.State{})
		if err != nil || got.Status != module.Change || !slices.Equal(got.Changes, want) {
			t.Fatalf("check after the failed apply = %+v, %v; want the changes %q", got, err, want)
		}
		vm.MustRun(t, `[ "$(/tmp/w/opt/app/bin/tool)" = tool ] && [ ! -e /tmp/w/opt/out ] && [ "$(ls -A /tmp/w)" = opt ]`)
		args = &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt", Owner: "admin"}
		if _, err := s.Apply(ctx, "download", args, &module.State{}, nil, nil, nil, protocol.Guard{}); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if got, err := s.Check(ctx, "download", args, &module.State{}); err != nil || got.Status != module.OK {
			t.Fatalf("check after apply = %+v, %v; want ok", got, err)
		}
		vm.MustRun(t, `[ "$(/tmp/w/opt/app/bin/tool)" = tool ] && [ "$(stat -c '%U' /tmp/w/opt/app/bin/tool)" = admin ]`)
	})

	t.Run("a killed unpack keeps the old tree", func(t *testing.T) {
		ctx := t.Context()
		entries := []entry{{name: "app/bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho many\n"}}
		for i := range 20000 {
			entries = append(entries, entry{name: fmt.Sprintf("app/d%02d/f%04d", i/1000, i%1000), typ: tar.TypeReg, mode: 0o644, body: "x\n"})
		}
		many := tarGz(t, entries)
		args := &module.Download{URL: lab.Serve(t, "download/many.tar.gz", many), SHA256: sha(many), Unpack: "/tmp/w/opt"}
		vm.MustRun(t, reset+"\n"+extracted)
		s := vm.Session(t)
		done := make(chan error, 1)
		go func() {
			_, err := s.Apply(ctx, "download", args, &module.State{}, nil, nil, nil, protocol.Guard{})
			done <- err
		}()
		vm.MustRun(t, "timeout 60 sh -c 'until [ -d /tmp/w/.winch-unpack-opt/app/d02 ]; do sleep 0.05; done' && pkill -KILL -f '^/var/lib/winch/bin/'")
		if err := <-done; err == nil {
			t.Fatal("apply with a killed helper succeeded")
		}
		vm.MustRun(t, `[ "$(/tmp/w/opt/app/bin/tool)" = tool ] && [ -d /tmp/w/.winch-unpack-opt ]`)
		if _, err := vm.Session(t).Apply(ctx, "download", args, &module.State{}, nil, nil, nil, protocol.Guard{}); err != nil {
			t.Fatalf("apply after the killed unpack: %v", err)
		}
		vm.MustRun(t, `[ "$(/tmp/w/opt/app/bin/tool)" = many ] && [ ! -e /tmp/w/.winch-unpack-opt ] && [ "$(find /tmp/w/opt/app -type f | wc -l)" = 20001 ]`)
	})

	t.Run("temporary unpack warns", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: download-warning\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  download:\n    address: 127.0.0.1\n",
			"pipelines/site.yaml":   "stages:\n  - name: tools\n    hosts: all\n    steps:\n      - download:\n          url: " + urlTgz + "\n          sha256: " + sha(tgz) + "\n          unpack: /tmp/app\n",
		})
		warnings := []string{"pipelines/site.yaml:8:19: warning: unpack: the host removes files in /tmp, so the step downloads again; use a path such as /opt or /var/lib"}
		r := lab.WinchEnvWarnings(t, dir, nil, warnings, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "unpack into /tmp/app") {
			t.Fatalf("plan: exit %d\n%s", r.Code, r.Stdout)
		}
	})

	vmtest.RunCases(t, vm, "download", reset, []vmtest.Case{
		{
			Name:      "download",
			Args:      &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/sub/f"},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/sub (owner root, group root, mode 0755)", "download " + url1, attrs}},
			Unchanged: `[ ! -e /tmp/w/sub ] && [ ! -e ` + record + ` ]`,
			After:     `[ "$(cat /tmp/w/sub/f)" = "version 1" ] && [ "$(stat -c '%U %G %a' /tmp/w/sub/f)" = "root root 644" ] && [ ! -e ` + record + ` ]`,
		},
		{
			Name:  "ok with the record needs no network",
			Setup: "echo 'version 1' > /tmp/w/f && " + recordV1,
			Args:  &module.Download{URL: missing, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a right file ignores a different recorded checksum",
			Setup: "echo 'version 2' > /tmp/w/f && " + recordV1,
			Args:  &module.Download{URL: missing, SHA256: sha(v2), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "plain downloads do not read or write records",
			Setup: "echo 'version 1' > /tmp/w/f && mkdir -p " + record,
			Args:  &module.Download{URL: missing, SHA256: sha(v1), Path: "/tmp/w/f", Owner: "admin"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner root → admin"}},
			After: `[ "$(stat -c %U /tmp/w/f)" = admin ] && [ -d ` + record + ` ]`,
		},
		{
			Name:  "a right file without a record is ok",
			Setup: "echo 'version 1' > /tmp/w/f && touch -d 2000-01-01 /tmp/w/f",
			Args:  &module.Download{URL: missing, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.OK},
			After: `[ "$(stat -c %Y /tmp/w/f)" = "$(date -d 2000-01-01 +%s)" ] && [ ! -e ` + record + ` ]`,
		},
		{
			Name:  "a right file with a new owner changes only its owner",
			Setup: "echo 'version 1' > /tmp/w/f",
			Args:  &module.Download{URL: missing, SHA256: sha(v1), Path: "/tmp/w/f", Owner: "admin"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner root → admin"}},
			After: `[ "$(stat -c %U /tmp/w/f)" = admin ] && [ ! -e ` + record + ` ]`,
		},
		{
			Name:  "a wrong file without a record downloads again",
			Setup: "echo changed > /tmp/w/f",
			Args:  &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + url1 + " (the sha256 differs)"}},
			After: `[ "$(cat /tmp/w/f)" = "version 1" ] && [ ! -e ` + record + ` ]`,
		},
		{
			Name:  "an unpack directory without a record unpacks again and keeps its mode",
			Setup: "mkdir -m 0750 /tmp/w/opt && chown nobody:nogroup /tmp/w/opt",
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz + " (no record of an earlier download)", unpackLine, "remove its content: 0 files, 0 directories"}},
			After: `[ "$(/tmp/w/opt/app/latest)" = tool ] && [ "$(ls -A /tmp/w)" = opt ] && [ "$(stat -c '%U %G %a' /tmp/w/opt)" = "root root 750" ]`,
		},
		{
			Name:      "a new checksum downloads again",
			Setup:     "echo 'version 1' > /tmp/w/f && " + recordV1 + " && echo '" + sha(v1) + " /tmp/w/other' >> " + record,
			Args:      &module.Download{URL: url2, SHA256: sha(v2), Path: "/tmp/w/f"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + url2 + " (the sha256 differs)"}},
			Unchanged: `[ "$(cat /tmp/w/f)" = "version 1" ]`,
			After:     `[ "$(cat /tmp/w/f)" = "version 2" ] && [ "$(cat ` + record + `)" = "$(printf '%s\n' 'version 1' '` + sha(v1) + ` /tmp/w/f' '` + sha(v1) + ` /tmp/w/other')" ]`,
		},
		{
			Name:  "a file that changed on the host downloads again",
			Setup: "echo changed > /tmp/w/f && " + recordV1,
			Args:  &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + url1 + " (the sha256 differs)"}},
			After: `[ "$(cat /tmp/w/f)" = "version 1" ]`,
		},
		{
			Name:         "a wrong checksum fails and keeps the old file",
			Setup:        "echo 'version 1' > /tmp/w/f && " + recordV1,
			Args:         &module.Download{URL: url2, SHA256: sha([]byte("other")), Path: "/tmp/w/f"},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + url2 + " (the sha256 differs)"}},
			WantApplyErr: "download " + url2 + ": the sha256 is " + sha(v2) + ", not " + sha([]byte("other")) + "; check url, or take sha256 from the checksum file of the vendor",
			After:        `[ "$(cat /tmp/w/f)" = "version 1" ] && [ "$(ls -A /tmp/w)" = f ] && grep -qx '` + sha(v1) + ` /tmp/w/f' ` + record,
			FixArgs:      &module.Download{URL: url2, SHA256: sha(v2), Path: "/tmp/w/f"},
		},
		{
			Name:         "a missing URL fails",
			Args:         &module.Download{URL: missing, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + missing, attrs}},
			WantApplyErr: "download " + missing + ": 404 Not Found",
			After:        `[ "$(ls -A /tmp/w)" = "" ] && [ ! -e ` + record + ` ]`,
			FixArgs:      &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/f"},
		},
		{
			Name:  "owner and mode of a downloaded file",
			Setup: "echo 'version 1' > /tmp/w/f && " + recordV1,
			Args:  &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/f", Owner: "admin", Mode: "0755"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner root → admin", "mode 0644 → 0755"}},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "admin root 755" ]`,
		},
		{
			Name:    "a directory at the path fails",
			Setup:   "mkdir /tmp/w/f",
			Args:    &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/f"},
			WantErr: "/tmp/w/f is a directory, not a file",
		},
		{
			Name:    "a file at the unpack directory fails",
			Setup:   "touch /tmp/w/opt",
			Args:    &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			WantErr: "/tmp/w/opt is a file, not a directory",
		},
		{
			Name:    "a symbolic link at the unpack directory fails",
			Setup:   "mkdir /tmp/w/real && ln -s real /tmp/w/opt",
			Args:    &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			WantErr: "/tmp/w/opt is a symbolic link, not a directory",
		},
		{
			Name:      "unpack a tar.gz",
			Args:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/sub/opt", Owner: "admin"},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/sub (owner root, group root, mode 0755)", "download " + urlTgz, "unpack into /tmp/w/sub/opt (owner admin, group root)"}},
			Unchanged: `[ ! -e /tmp/w/sub ]`,
			After: `cd /tmp/w/sub/opt && [ "$(ls -A /tmp/w/sub)" = opt ]` +
				` && [ "$(stat -c '%U %G %a' . app app/bin app/bin/tool app/README)" = "$(printf '%s\n' 'admin root 755' 'admin root 755' 'admin root 755' 'admin root 755' 'admin root 644')" ]` +
				` && [ "$(app/latest)" = tool ] && [ "$(readlink app/latest)" = bin/tool ] && [ "$(stat -c '%U' app/latest)" = admin ]` +
				` && [ app/hard -ef app/README ] && grep -qx '` + sha(tgz) + `:admin:root /tmp/w/sub/opt' ` + record,
		},
		{
			Name:  "the archive replaces an older tree",
			Setup: "mkdir -p /tmp/w/opt/app && echo old > /tmp/w/opt/app/bin && echo old > /tmp/w/opt/old && ln -s nowhere /tmp/w/opt/app/latest && chown -R nobody:nogroup /tmp/w/opt",
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz + " (no record of an earlier download)", unpackLine, "remove its content: 3 files, 1 directory"}},
			After: `[ "$(/tmp/w/opt/app/latest)" = tool ] && [ "$(stat -c '%U %G' /tmp/w/opt /tmp/w/opt/app)" = "$(printf '%s\n' 'root root' 'root root')" ] && [ "$(ls -A /tmp/w)" = opt ]` +
				` && [ "$(cd /tmp/w/opt && find . | LC_ALL=C sort | tr '\n' ' ')" = ". ./app ./app/README ./app/bin ./app/bin/tool ./app/hard ./app/latest " ]`,
		},
		{
			Name:  "a file of the archive replaces a directory",
			Setup: "mkdir -p /tmp/w/opt/app/README/sub",
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz + " (no record of an earlier download)", unpackLine, "remove its content: 0 files, 3 directories"}},
			After: `[ "$(cat /tmp/w/opt/app/README)" = "read me" ]`,
		},
		{
			Name:         "a tree of a stopped unpack that cannot be removed fails",
			Setup:        "mkdir /tmp/w/.winch-unpack-opt && touch /tmp/w/.winch-unpack-opt/f && chattr +i /tmp/w/.winch-unpack-opt/f",
			Args:         &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTgz, unpackLine}},
			WantApplyErr: "remove the tree of a stopped unpack into /tmp/w/opt: ",
			After:        `[ ! -e /tmp/w/opt ] && [ ! -e ` + record + ` ]`,
			Fix:          "chattr -i /tmp/w/.winch-unpack-opt/f",
		},
		{
			Name:    "an unpack directory that is a mount point fails",
			Setup:   "mkdir /tmp/w/opt && mount -t tmpfs tmpfs /tmp/w/opt",
			Args:    &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			WantErr: "/tmp/w/opt is a mount point, and winch does not remove a mounted file system; unmount it first",
		},
		{
			Name:    "a mount point in the old tree fails",
			Setup:   extracted + " && mkdir /tmp/w/opt/app/m && mount -t tmpfs tmpfs /tmp/w/opt/app/m",
			Args:    &module.Download{URL: urlTgz2, SHA256: sha(tgz2), Unpack: "/tmp/w/opt"},
			WantErr: "/tmp/w/opt/app/m is a mount point, and winch does not remove a mounted file system; unmount it first",
		},
		{
			Name:    "an immutable file in the old tree fails",
			Setup:   extracted + " && chattr +i /tmp/w/opt/app/README",
			Args:    &module.Download{URL: urlTgz2, SHA256: sha(tgz2), Unpack: "/tmp/w/opt"},
			WantErr: "/tmp/w/opt/app/README is immutable; chattr -i removes the flag",
		},
		{
			Name:  "unpack a tar.xz",
			Args:  &module.Download{URL: urlTxz, SHA256: sha(txz), Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTxz, unpackLine}},
			After: `[ "$(cat /tmp/w/opt/xd/f)" = xz ]`,
		},
		{
			Name:  "an http tar.xz to a path needs neither xz nor CA certificates",
			Setup: "mv /usr/bin/xz /usr/bin/xz.off && mv /etc/ssl/certs /etc/ssl/certs.off",
			Args:  &module.Download{URL: urlTxz, SHA256: sha(txz), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTxz, attrs}},
		},
		{
			Name:         "a tar.xz without xz names xz-utils",
			Setup:        "mv /usr/bin/xz /usr/bin/xz.off",
			Args:         &module.Download{URL: urlTxz, SHA256: sha(txz), Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTxz, unpackLine}, MissingTools: []module.Tool{{Name: "xz", Package: "xz-utils"}}},
			WantApplyErr: "xz is missing; install the package xz-utils in an earlier pkg step",
			Fix:          "mv /usr/bin/xz.off /usr/bin/xz",
		},
		{
			Name:  "unpack a tgz",
			Args:  &module.Download{URL: urlShort, SHA256: sha(tgz2), Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlShort, unpackLine}},
			After: `[ "$(/tmp/w/opt/app/bin/tool)" = tool2 ]`,
		},
		{
			Name:  "unpack a zip",
			Args:  &module.Download{URL: urlZip, SHA256: sha(zbuf.Bytes()), Unpack: "/tmp/w/opt", Group: "adm"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlZip, "unpack into /tmp/w/opt (owner root, group adm)"}},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/opt/z /tmp/w/opt/z/a.txt /tmp/w/opt/z/bin/run)" = "$(printf '%s\n' 'root adm 755' 'root adm 644' 'root adm 755')" ] && [ "$(readlink /tmp/w/opt/z/link)" = a.txt ]`,
		},
		{
			Name:         "an entry outside the directory fails",
			Args:         &module.Download{URL: urlEvil, SHA256: sha(evil), Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlEvil, unpackLine}},
			WantApplyErr: `the entry "../evil" is outside the directory`,
			After:        `[ "$(ls -A /tmp/w)" = "" ] && [ ! -e ` + record + ` ]`,
			FixArgs:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
		},
		{
			Name:  "a record without the file downloads again",
			Setup: recordV1,
			Args:  &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + url1, attrs}},
		},
		{
			Name:  "a missing unpack directory unpacks again",
			Setup: unpacked,
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTgz, unpackLine}},
			After: `[ "$(/tmp/w/opt/app/latest)" = tool ]`,
		},
		{
			Name:      "a new owner unpacks again",
			Setup:     extracted,
			Args:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt", Owner: "admin"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz + " (new owner)", "unpack into /tmp/w/opt (owner admin, group root)"}},
			Unchanged: `[ "$(stat -c %U /tmp/w/opt/app/bin/tool)" != admin ]`,
			After:     `[ "$(stat -c %U /tmp/w/opt /tmp/w/opt/app/bin/tool)" = "$(printf '%s\n' admin admin)" ] && grep -qx '` + sha(tgz) + `:admin:root /tmp/w/opt' ` + record,
		},
		{
			Name:  "a new group unpacks again",
			Setup: extracted,
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt", Group: "adm"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz + " (new group)", "unpack into /tmp/w/opt (owner root, group adm)"}},
			After: `[ "$(stat -c %G /tmp/w/opt /tmp/w/opt/app/bin/tool)" = "$(printf '%s\n' adm adm)" ] && grep -qx '` + sha(tgz) + `:root:adm /tmp/w/opt' ` + record,
		},
		{
			Name:  "the check reads no tree",
			Setup: extracted + " && echo changed > /tmp/w/opt/app/README && rm /tmp/w/opt/app/bin/tool",
			Args:  &module.Download{URL: missing, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a new unpack directory that exists unpacks again",
			Setup: extracted + " && mkdir /tmp/w/opt2 && echo '" + sha(v1) + " /tmp/w/other' >> " + record,
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt2"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz + " (no record of an earlier download)", "unpack into /tmp/w/opt2 (owner root, group root)", "remove its content: 0 files, 0 directories"}},
			After: `[ "$(/tmp/w/opt2/app/latest)" = tool ] && [ "$(cat ` + record + `)" = "$(printf '%s\n' 'version 1' '` + unpackRecord + `' '` + sha(v1) + ` /tmp/w/other' '` + sha(tgz) + `:root:root /tmp/w/opt2')" ]`,
		},
		{
			Name:      "a new checksum unpacks the new archive",
			Setup:     extracted,
			Args:      &module.Download{URL: urlTgz2, SHA256: sha(tgz2), Unpack: "/tmp/w/opt"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz2 + " (new sha256)", unpackLine}},
			Unchanged: `[ "$(/tmp/w/opt/app/bin/tool)" = tool ]`,
			After:     `[ "$(/tmp/w/opt/app/bin/tool)" = tool2 ] && grep -qx '` + sha(tgz2) + `:root:root /tmp/w/opt' ` + record + ` && [ "$(ls -A /tmp/w)" = opt ]`,
		},
		{
			Name:         "a wrong checksum unpacks nothing",
			Args:         &module.Download{URL: urlTgz, SHA256: sha(v1), Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTgz, unpackLine}},
			WantApplyErr: "the sha256 is " + sha(tgz),
			After:        `[ "$(ls -A /tmp/w)" = "" ]`,
			FixArgs:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
		},
		{
			Name:         "a bad entry after a good one unpacks nothing",
			Args:         &module.Download{URL: urlLate, SHA256: sha(late), Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlLate, unpackLine}},
			WantApplyErr: `the entry "../evil" is outside the directory`,
			After:        `[ "$(ls -A /tmp/w)" = "" ]`,
			FixArgs:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
		},
		{
			Name:         "a broken tar.xz shows the error of xz",
			Args:         &module.Download{URL: urlBroken, SHA256: sha(broken), Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlBroken, unpackLine}},
			WantApplyErr: "xz: exit status 1: xz: (stdin): Unexpected end of input",
			After:        `[ "$(ls -A /tmp/w)" = "" ]`,
			FixArgs:      &module.Download{URL: urlTxz, SHA256: sha(txz), Unpack: "/tmp/w/opt"},
		},
		{
			Name:         "a link out of the directory is not followed",
			Args:         &module.Download{URL: urlEscape, SHA256: sha(escape), Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlEscape, unpackLine}},
			WantApplyErr: "/tmp/w/opt/out is a symbolic link, not a directory",
			After:        `[ ! -e /tmp/w/escaped ] && [ "$(ls -A /tmp/w)" = "" ] && [ ! -e ` + record + ` ]`,
			FixArgs:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Unpack: "/tmp/w/opt"},
		},
	})
}

// spec: Modules/download; Modules/file, dir, link
func TestDownloadRun(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "download-run")
	tool := []byte("#!/bin/sh\necho tool\n")
	url := lab.Serve(t, "download-run/tool", tool)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  " + vm.Name + ": {}\n",
		"pipelines/site.yaml": `stages:
  - name: tools
    hosts: all
    steps:
      - dir:
          path: /opt/tools
      - download:
          url: ` + url + `
          sha256: ` + sha(tool) + `
          path: /opt/tools/tool
          mode: "0755"
`,
	})
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 {
		t.Fatalf("plan: exit %d", r.Code)
	}
	if !strings.Contains(r.Stdout, "download "+url) {
		t.Errorf("the plan does not download:\n%s", r.Stdout)
	}
	if strings.Contains(r.Stdout, "create directory /opt/tools") {
		t.Errorf("the plan creates /opt/tools for the download, after the dir step:\n%s", r.Stdout)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "/opt/tools/tool && test ! -e /var/lib/winch/downloads/acme"); out != "tool\n" {
		t.Errorf("tool output = %q", out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}

// spec: Modules/download
func TestDownloadUnpackRun(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "download-unpack-run")
	v1 := tarGz(t, []entry{
		{name: "bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho v1\n"},
		{name: "bin/old", typ: tar.TypeReg, mode: 0o755, body: "old\n"},
		{name: "lib", typ: tar.TypeReg, mode: 0o644, body: "lib\n"},
	})
	v2 := tarGz(t, []entry{
		{name: "bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho v2\n"},
		{name: "lib/so", typ: tar.TypeReg, mode: 0o644, body: "so\n"},
	})
	url1 := lab.Serve(t, "download-unpack-run/v1.tar.gz", v1)
	url2 := lab.Serve(t, "download-unpack-run/v2.tar.gz", v2)
	project := func(url string, sum string) string {
		return vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: acme\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  " + vm.Name + ": {}\n",
			"pipelines/site.yaml": `stages:
  - name: tools
    hosts: all
    steps:
      - download:
          url: ` + url + `
          sha256: ` + sum + `
          unpack: /opt/winch-test/app
`,
		})
	}
	dir := project(url1, sha(v1))
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "/opt/winch-test/app/bin/tool && ls -A /opt/winch-test"); out != "v1\napp\n" {
		t.Errorf("tool output and /opt/winch-test = %q, want v1 and only the unpack directory", out)
	}
	vm.MustRun(t, "echo changed > /opt/winch-test/app/bin/tool")
	if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
	dir = project(url2, sha(v2))
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "download "+url2+" (new sha256)") {
		t.Errorf("plan with a new sha256: exit %d, stdout %q", r.Code, r.Stdout)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply with a new sha256: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "/opt/winch-test/app/bin/tool && ls -A /opt/winch-test && cd /opt/winch-test/app && find . | LC_ALL=C sort"); out != "v2\napp\n.\n./bin\n./bin/tool\n./lib\n./lib/so\n" {
		t.Errorf("tool output, /opt/winch-test, and the tree after the new sha256 = %q, want v2, only the unpack directory, and the tree of the archive", out)
	}
}

// spec: Modules/download; Modules/file, dir, link
func TestDownloadUnpackDirStep(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "download-unpack-dir")
	v1 := tarGz(t, []entry{{name: "bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho v1\n"}})
	v2 := tarGz(t, []entry{{name: "bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho v2\n"}})
	url1 := lab.Serve(t, "download-unpack-dir/v1.tar.gz", v1)
	url2 := lab.Serve(t, "download-unpack-dir/v2.tar.gz", v2)
	project := func(url string, sum string) string {
		return vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: acme\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  " + vm.Name + ": {}\n",
			"pipelines/site.yaml": `stages:
  - name: tools
    hosts: all
    steps:
      - dir:
          path: /opt/winch-test/app
          mode: "0750"
      - download:
          url: ` + url + `
          sha256: ` + sum + `
          unpack: /opt/winch-test/app
`,
		})
	}
	for _, dir := range []string{project(url1, sha(v1)), project(url2, sha(v2))} {
		if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
			t.Fatalf("apply: exit %d", r.Code)
		}
		if r := lab.Winch(t, dir, "plan", "site", "--exit-code"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("plan after apply: exit %d, stdout %q", r.Code, r.Stdout)
		}
	}
	if out := vm.MustRun(t, "/opt/winch-test/app/bin/tool && stat -c '%U %a' /opt/winch-test/app"); out != "v2\nroot 750\n" {
		t.Errorf("tool output and the unpack directory = %q, want v2 and root 750", out)
	}
}

// selfSigned returns a PEM file with a self-signed certificate for localhost
// and its key.
func selfSigned(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
}

// spec: Modules/download
func TestDownloadNetwork(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "download-network")
	vm.MustRun(t, "cat > /root/tls.pem <<'EOF'\n"+selfSigned(t)+"EOF")
	sum := sha([]byte("tool"))
	// server starts a Python server on port that runs body after listen.
	// It writes its PID to /root/listening when it accepts connections.
	server := func(port, body string) string {
		return `(python3 -c 'import os, socket, ssl, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", ` + port + `))
s.listen()
open("/root/listening", "w").write(str(os.getpid()))
` + body + `' >/dev/null 2>&1 &) && timeout 10 sh -c 'until [ -e /root/listening ]; do sleep 0.1; done'`
	}
	stall := server("8099", `c, _ = s.accept()
c.recv(65536)
c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial")
time.sleep(600)`)
	// serve answers each request with "tool".
	const serve = `c.recv(65536)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntool")`
	tls := server("8443", `ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/root/tls.pem")
while True:
    c, _ = s.accept()
    try:
        c = ctx.wrap_socket(c, server_side=True)
        `+serve+`
    except Exception:
        pass
    c.close()`)
	good := "pid=$(cat /root/listening) && kill $pid && while kill -0 $pid 2>/dev/null; do sleep 0.1; done && rm /root/listening && " + server("8099", `while True:
    c, _ = s.accept()
    try:
        `+serve+`
    except Exception:
        pass
    c.close()`)
	trust := "sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' /root/tls.pem > /usr/local/share/ca-certificates/winch-test.crt && update-ca-certificates >/dev/null 2>&1"
	attrs := "owner root, group root, mode 0644"
	reset := "! pid=$(cat /root/listening 2>/dev/null) || ! kill $pid || while kill -0 $pid 2>/dev/null; do sleep 0.1; done\n[ -e /etc/ssl/certs ] || mv /etc/ssl/certs.off /etc/ssl/certs\n[ ! -e /usr/local/share/ca-certificates/winch-test.crt ] || { rm /usr/local/share/ca-certificates/winch-test.crt && update-ca-certificates >/dev/null 2>&1; }\nrm -rf /tmp/w /root/listening /var/lib/winch/downloads/test && mkdir /tmp/w"
	stalled, untrusted := "http://127.0.0.1:8099/tool", "https://localhost:8443/tool"
	// redirects serves a chain of redirects from http to https and back to
	// http on both ports. The chain of /r1 ends in "tool", the chain of /b1 in
	// other content.
	redirects := trust + ` && (python3 -c 'import os, socket, ssl, threading
routes = {"/r1": "https://localhost:8443/r2", "/r2": "http://127.0.0.1:8099/tool", "/tool": "tool",
    "/b1": "https://localhost:8443/b2", "/b2": "http://127.0.0.1:8099/evil", "/evil": "evil"}
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/root/tls.pem")
def serve(s, tls):
    while True:
        c, _ = s.accept()
        try:
            if tls:
                c = ctx.wrap_socket(c, server_side=True)
            r = routes[c.recv(65536).split(b" ")[1].decode()]
            if r.startswith("http"):
                c.sendall(("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % r).encode())
            else:
                c.sendall(("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(r), r)).encode())
        except Exception:
            pass
        c.close()
socks = []
for port in (8099, 8443):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen()
    socks.append(s)
threading.Thread(target=serve, args=(socks[1], True), daemon=True).start()
open("/root/listening", "w").write(str(os.getpid()))
serve(socks[0], False)' >/dev/null 2>&1 &) && timeout 10 sh -c 'until [ -e /root/listening ]; do sleep 0.1; done'`
	chain, otherChain := "http://127.0.0.1:8099/r1", "http://127.0.0.1:8099/b1"
	vmtest.RunCases(t, vm, "download", reset, []vmtest.Case{
		{
			Name:         "a server that stops sending fails after the stall limit",
			Setup:        stall,
			Args:         &module.Download{URL: stalled, SHA256: sum, Path: "/tmp/w/f"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + stalled, attrs}},
			WantApplyErr: "download " + stalled + ": no data for 120s",
			After:        `[ "$(ls -A /tmp/w)" = "" ]`,
			Fix:          good,
		},
		{
			Name:         "an untrusted certificate fails",
			Setup:        tls,
			Args:         &module.Download{URL: untrusted, SHA256: sum, Path: "/tmp/w/f"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + untrusted, attrs}},
			WantApplyErr: "certificate signed by unknown authority",
			Fix:          trust,
		},
		{
			Name:  "a redirect chain from http to https and back to http",
			Setup: redirects,
			Args:  &module.Download{URL: chain, SHA256: sum, Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + chain, attrs}},
			After: `[ "$(cat /tmp/w/f)" = tool ]`,
		},
		{
			Name:         "a redirect chain to other content fails on the sha256",
			Setup:        redirects,
			Args:         &module.Download{URL: otherChain, SHA256: sum, Path: "/tmp/w/f"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + otherChain, attrs}},
			WantApplyErr: "download " + otherChain + ": the sha256 is " + sha([]byte("evil")) + ", not " + sum,
			After:        `[ "$(ls -A /tmp/w)" = "" ]`,
			FixArgs:      &module.Download{URL: chain, SHA256: sum, Path: "/tmp/w/f"},
		},
		{
			Name:  "a file with its sha256 needs no CA certificates",
			Setup: "mv /etc/ssl/certs /etc/ssl/certs.off && printf tool > /tmp/w/f && chmod 0644 /tmp/w/f",
			Args:  &module.Download{URL: untrusted, SHA256: sum, Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "https without CA certificates names ca-certificates",
			Setup: "mv /etc/ssl/certs /etc/ssl/certs.off && " + tls,
			Args:  &module.Download{URL: untrusted, SHA256: sum, Path: "/tmp/w/f"},
			Want: module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + untrusted, attrs},
				MissingTools: []module.Tool{{Name: "/etc/ssl/certs/ca-certificates.crt", Package: "ca-certificates"}}},
			WantApplyErr: "download " + untrusted + ": the host has no CA certificates; install the package ca-certificates in an earlier pkg step",
			Fix:          "mv /etc/ssl/certs.off /etc/ssl/certs && " + trust,
		},
	})
}
