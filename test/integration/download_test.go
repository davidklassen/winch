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
	recordV1 := "mkdir -p /var/lib/winch/downloads && echo '" + sha(v1) + " /tmp/w/f' > " + record

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
	unpacked := "curl -sfo /tmp/w/app.tar.gz " + urlTgz + " && mkdir -p /var/lib/winch/downloads && echo '" + sha(tgz) + " /tmp/w/app.tar.gz' > " + record
	extracted := unpacked + " && mkdir /tmp/w/opt && tar -C /tmp/w/opt -xzf /tmp/w/app.tar.gz"
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

	reset := "[ ! -d /tmp/w ] || find /tmp/w \\( -type f -o -type d \\) -exec chattr -ia {} +\nrm -rf /tmp/w " + record + " && mkdir /tmp/w"
	t.Run("a failed unpack stays a change", func(t *testing.T) {
		ctx := t.Context()
		s := vm.Session(t)
		vm.MustRun(t, reset+"\n"+extracted+" && rm /tmp/w/opt/app/bin/tool && mkdir /tmp/w/opt/app/bin/tool")
		args := &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt", Owner: "admin"}
		if _, err := s.Apply(ctx, "download", args, &module.State{}, nil, nil, protocol.Guard{}); err == nil || !strings.Contains(err.Error(), "unpack /tmp/w/app.tar.gz into /tmp/w/opt") {
			t.Fatalf("apply over a directory at a file entry = %v, want an unpack error", err)
		}
		want := []string{"download " + urlTgz + " (no record of an earlier download)", "unpack into /tmp/w/opt"}
		got, err := s.Check(ctx, "download", args, &module.State{})
		if err != nil || got.Status != module.Change || !slices.Equal(got.Changes, want) {
			t.Fatalf("check after the failed apply = %+v, %v; want the changes %q", got, err, want)
		}
		vm.MustRun(t, "rmdir /tmp/w/opt/app/bin/tool")
		if _, err := s.Apply(ctx, "download", args, &module.State{}, nil, nil, protocol.Guard{}); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if got, err := s.Check(ctx, "download", args, &module.State{}); err != nil || got.Status != module.OK {
			t.Fatalf("check after apply = %+v, %v; want ok", got, err)
		}
		vm.MustRun(t, `[ "$(/tmp/w/opt/app/bin/tool)" = tool ] && [ "$(stat -c '%U' /tmp/w/opt/app/bin/tool)" = admin ]`)
	})

	vmtest.RunCases(t, vm, "download", reset, []vmtest.Case{
		{
			Name:      "download",
			Args:      &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/sub/f"},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/sub (owner root, group root, mode 0755)", "download " + url1, attrs}},
			Unchanged: `[ ! -e /tmp/w/sub ] && [ ! -e ` + record + ` ]`,
			After:     `[ "$(cat /tmp/w/sub/f)" = "version 1" ] && [ "$(stat -c '%U %G %a' /tmp/w/sub/f)" = "root root 644" ] && grep -qx '` + sha(v1) + ` /tmp/w/sub/f' ` + record,
		},
		{
			Name:  "ok with the record needs no network",
			Setup: "echo 'version 1' > /tmp/w/f && " + recordV1,
			Args:  &module.Download{URL: missing, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a file without a record downloads again",
			Setup: "echo 'version 1' > /tmp/w/f",
			Args:  &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + url1 + " (no record of an earlier download)"}},
			After: "grep -qx '" + sha(v1) + " /tmp/w/f' " + record,
		},
		{
			Name:      "a new checksum downloads again",
			Setup:     "echo 'version 1' > /tmp/w/f && " + recordV1 + " && echo '" + sha(v1) + " /tmp/w/other' >> " + record,
			Args:      &module.Download{URL: url2, SHA256: sha(v2), Path: "/tmp/w/f"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + url2 + " (new sha256)"}},
			Unchanged: `[ "$(cat /tmp/w/f)" = "version 1" ]`,
			After:     `[ "$(cat /tmp/w/f)" = "version 2" ] && [ "$(cat ` + record + `)" = "$(printf '%s\n' '` + sha(v1) + ` /tmp/w/other' '` + sha(v2) + ` /tmp/w/f')" ]`,
		},
		{
			Name:  "a file that changed on the host downloads again",
			Setup: "echo changed > /tmp/w/f && " + recordV1,
			Args:  &module.Download{URL: url1, SHA256: sha(v1), Path: "/tmp/w/f"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + url1 + " (the file changed on the host)"}},
			After: `[ "$(cat /tmp/w/f)" = "version 1" ]`,
		},
		{
			Name:         "a wrong checksum fails and keeps the old file",
			Setup:        "echo 'version 1' > /tmp/w/f && " + recordV1,
			Args:         &module.Download{URL: url2, SHA256: sha([]byte("other")), Path: "/tmp/w/f"},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + url2 + " (new sha256)"}},
			WantApplyErr: "download " + url2 + ": the SHA-256 is " + sha(v2) + ", not " + sha([]byte("other")),
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
			Args:    &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt"},
			WantErr: "/tmp/w/opt is a file, not a directory",
		},
		{
			Name:      "unpack a tar.gz",
			Args:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt", Owner: "admin"},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTgz, "owner admin, group root, mode 0644", "unpack into /tmp/w/opt"}},
			Unchanged: `[ ! -e /tmp/w/opt ]`,
			After: `[ "$(stat -c '%U %G %a' /tmp/w/app.tar.gz /tmp/w/opt /tmp/w/opt/app /tmp/w/opt/app/bin /tmp/w/opt/app/bin/tool /tmp/w/opt/app/README)" = "$(printf '%s\n' 'admin root 644' 'admin root 755' 'admin root 755' 'admin root 755' 'admin root 755' 'admin root 644')" ]` +
				` && [ "$(/tmp/w/opt/app/latest)" = tool ] && [ "$(readlink /tmp/w/opt/app/latest)" = bin/tool ] && [ "$(stat -c '%U' /tmp/w/opt/app/latest)" = admin ]` +
				` && [ /tmp/w/opt/app/hard -ef /tmp/w/opt/app/README ] && grep -qx '` + sha(tgz) + ` /tmp/w/app.tar.gz' ` + record,
		},
		{
			Name:  "unpack over an older tree",
			Setup: "mkdir -p /tmp/w/opt/app/bin && echo old > /tmp/w/opt/app/bin/tool && echo keep > /tmp/w/opt/keep && ln -s nowhere /tmp/w/opt/app/latest",
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTgz, attrs, "unpack into /tmp/w/opt"}},
			After: `[ "$(/tmp/w/opt/app/latest)" = tool ] && [ "$(cat /tmp/w/opt/keep)" = keep ]`,
		},
		{
			Name:  "unpack a tar.xz",
			Args:  &module.Download{URL: urlTxz, SHA256: sha(txz), Path: "/tmp/w/x.tar.xz", Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTxz, attrs, "unpack into /tmp/w/opt"}},
			After: `[ "$(cat /tmp/w/opt/xd/f)" = xz ]`,
		},
		{
			Name:  "unpack a tgz",
			Args:  &module.Download{URL: urlShort, SHA256: sha(tgz2), Path: "/tmp/w/app.tgz", Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlShort, attrs, "unpack into /tmp/w/opt"}},
			After: `[ "$(/tmp/w/opt/app/bin/tool)" = tool2 ]`,
		},
		{
			Name:  "unpack a zip",
			Args:  &module.Download{URL: urlZip, SHA256: sha(zbuf.Bytes()), Path: "/tmp/w/z.zip", Unpack: "/tmp/w/opt", Group: "adm"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlZip, "owner root, group adm, mode 0644", "unpack into /tmp/w/opt"}},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/opt/z /tmp/w/opt/z/a.txt /tmp/w/opt/z/bin/run)" = "$(printf '%s\n' 'root adm 755' 'root adm 644' 'root adm 755')" ] && [ "$(readlink /tmp/w/opt/z/link)" = a.txt ]`,
		},
		{
			Name:         "an entry outside the directory fails",
			Args:         &module.Download{URL: urlEvil, SHA256: sha(evil), Path: "/tmp/w/evil.tar.gz", Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlEvil, attrs, "unpack into /tmp/w/opt"}},
			WantApplyErr: `the entry "../evil" is outside the directory`,
			After:        `[ ! -e /tmp/w/evil ] && [ ! -e /tmp/w/evil.tar.gz ] && [ ! -e ` + record + ` ]`,
			FixArgs:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/evil.tar.gz", Unpack: "/tmp/w/opt"},
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
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz + " (/tmp/w/opt does not exist)", "unpack into /tmp/w/opt"}},
			After: `[ "$(/tmp/w/opt/app/latest)" = tool ]`,
		},
		{
			Name:  "an owner change unpacks again",
			Setup: extracted,
			Args:  &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt", Owner: "admin"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner root → admin", "unpack into /tmp/w/opt"}},
			After: `[ "$(stat -c '%U' /tmp/w/app.tar.gz /tmp/w/opt/app/bin/tool)" = "$(printf '%s\n' admin admin)" ]`,
		},
		{
			Name:      "a new checksum unpacks the new archive",
			Setup:     extracted,
			Args:      &module.Download{URL: urlTgz2, SHA256: sha(tgz2), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"download " + urlTgz2 + " (new sha256)", "unpack into /tmp/w/opt"}},
			Unchanged: `[ "$(/tmp/w/opt/app/bin/tool)" = tool ]`,
			After:     `[ "$(/tmp/w/opt/app/bin/tool)" = tool2 ] && grep -qx '` + sha(tgz2) + ` /tmp/w/app.tar.gz' ` + record,
		},
		{
			Name:         "a wrong checksum unpacks nothing",
			Args:         &module.Download{URL: urlTgz, SHA256: sha(v1), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlTgz, attrs, "unpack into /tmp/w/opt"}},
			WantApplyErr: "the SHA-256 is " + sha(tgz),
			After:        `[ ! -e /tmp/w/opt ] && [ ! -e /tmp/w/app.tar.gz ]`,
			FixArgs:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/app.tar.gz", Unpack: "/tmp/w/opt"},
		},
		{
			Name:         "a bad entry after a good one unpacks nothing",
			Args:         &module.Download{URL: urlLate, SHA256: sha(late), Path: "/tmp/w/late.tar.gz", Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlLate, attrs, "unpack into /tmp/w/opt"}},
			WantApplyErr: `the entry "../evil" is outside the directory`,
			After:        `[ ! -e /tmp/w/opt ] && [ ! -e /tmp/w/evil ]`,
			FixArgs:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/late.tar.gz", Unpack: "/tmp/w/opt"},
		},
		{
			Name:         "a broken tar.xz shows the error of xz",
			Args:         &module.Download{URL: urlBroken, SHA256: sha(broken), Path: "/tmp/w/broken.tar.xz", Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlBroken, attrs, "unpack into /tmp/w/opt"}},
			WantApplyErr: "xz: exit status 1: xz: (stdin): Unexpected end of input",
			After:        `[ ! -e /tmp/w/broken.tar.xz ]`,
			FixArgs:      &module.Download{URL: urlTxz, SHA256: sha(txz), Path: "/tmp/w/broken.tar.xz", Unpack: "/tmp/w/opt"},
		},
		{
			Name:         "a link out of the directory is not followed",
			Args:         &module.Download{URL: urlEscape, SHA256: sha(escape), Path: "/tmp/w/escape.tar.gz", Unpack: "/tmp/w/opt"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + urlEscape, attrs, "unpack into /tmp/w/opt"}},
			WantApplyErr: "/tmp/w/opt/out is a symbolic link, not a directory",
			After:        `[ ! -e /tmp/w/escaped ] && [ ! -e ` + record + ` ]`,
			FixArgs:      &module.Download{URL: urlTgz, SHA256: sha(tgz), Path: "/tmp/w/escape.tar.gz", Unpack: "/tmp/w/opt"},
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
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
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
	if out := vm.MustRun(t, "/opt/tools/tool && cat /var/lib/winch/downloads/acme"); out != "tool\n"+sha(tool)+" /opt/tools/tool\n" {
		t.Errorf("tool output and record = %q", out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
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
	vmtest.RunCases(t, vm, "download", reset, []vmtest.Case{
		{
			Name:         "a server that stops sending fails after the stall limit",
			Setup:        stall,
			Args:         &module.Download{URL: stalled, SHA256: sum, Path: "/tmp/w/f"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + stalled, attrs}},
			WantApplyErr: "download " + stalled + ": no data for 2m0s",
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
			Name:         "https without CA certificates names ca-certificates",
			Setup:        "mv /etc/ssl/certs /etc/ssl/certs.off && " + tls,
			Args:         &module.Download{URL: untrusted, SHA256: sum, Path: "/tmp/w/f"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + untrusted, attrs}},
			WantApplyErr: "download " + untrusted + ": the host has no CA certificates; install the package ca-certificates with an earlier pkg step",
			Fix:          "mv /etc/ssl/certs.off /etc/ssl/certs && " + trust,
		},
	})
}
