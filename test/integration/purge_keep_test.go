package integration

import (
	"archive/tar"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/file, dir, link (dir purge keeps generated files)
func TestPurgePostmap(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "postmap")
	vm.MustRun(t, "mkdir /etc/winch-maps && touch /etc/winch-maps/stale")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: purge\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  postmap: {}\n",
		"pipelines/site.yaml": `stages:
  - name: maps
    hosts: all
    steps:
      - pkg:
          name: postfix
      - dir:
          path: /etc/winch-maps
          purge: true
          keep: ["*.db"]
      - file:
          path: /etc/winch-maps/virtual
          content: "alice@example.org bob@example.org\n"
        then: postmap /etc/winch-maps/virtual
      - recipe: app
`,
		"recipes/app/recipe.yaml": `steps:
  - file:
      path: /etc/winch-maps/aliases
      content: "carol@example.org dave@example.org\n"
    notify: rebuild
handlers:
  rebuild:
    - cmd:
        command: postmap /etc/winch-maps/aliases
`,
	})
	for run := 1; run <= 4; run++ {
		if run == 4 {
			vm.MustRun(t, "touch /etc/winch-maps/stale")
		}
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply %d: exit %d, stdout %q, stderr %q", run, r.Code, r.Stdout, r.Stderr)
		}
		if got := vm.MustRun(t, "postmap -q alice@example.org /etc/winch-maps/virtual"); got != "bob@example.org\n" {
			t.Fatalf("apply %d: map lookup = %q", run, got)
		}
		if got := vm.MustRun(t, "postmap -q carol@example.org /etc/winch-maps/aliases"); got != "dave@example.org\n" {
			t.Fatalf("apply %d: handler map lookup = %q", run, got)
		}
		vm.MustRun(t, "test ! -e /etc/winch-maps/stale")
		if (run == 2 || run == 3) && !strings.Contains(r.Stdout, "1 host: 0 to change, 1 unchanged") {
			t.Errorf("apply %d did not converge: %s", run, r.Stdout)
		}
		if run == 4 && !strings.Contains(r.Stdout, "remove file /etc/winch-maps/stale") {
			t.Errorf("drift apply did not purge stale file: %s", r.Stdout)
		}
	}
}

// spec: Modules/file, dir, link (dir purge keeps a download unpack tree)
func TestPurgeUnpack(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "purge-unpack")
	tgz := tarGz(t, []entry{
		{name: "bin/", typ: tar.TypeDir, mode: 0o755},
		{name: "bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho tool\n"},
		{name: "README", typ: tar.TypeReg, mode: 0o644, body: "read me\n"},
	})
	url := lab.Serve(t, "purge-unpack/app.tar.gz", tgz)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: purge\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  purge-unpack: {}\n",
		"pipelines/site.yaml": `stages:
  - name: app
    hosts: all
    steps:
      - dir:
          path: /opt/app
          purge: true
      - dir:
          path: /opt/app/bin
          purge: true
      - download:
          url: ` + url + `
          sha256: ` + sha(tgz) + `
          unpack: /opt/app
`,
	})
	for run := 1; run <= 2; run++ {
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply %d: exit %d, stdout %q, stderr %q", run, r.Code, r.Stdout, r.Stderr)
		}
		if got := vm.MustRun(t, "{ /opt/app/bin/tool; cat /opt/app/README; } 2>&1 || true"); got != "tool\nread me\n" {
			t.Errorf("apply %d: the unpacked files = %q, stdout %q", run, got, r.Stdout)
		}
	}
	r := lab.Winch(t, dir, "plan", "site", "--exit-code")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("third plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}

// spec: Modules/file, dir, link (dir purge keeps the conffiles of a removed package)
func TestPurgeRemovedPackageConffile(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "purge-rc")
	// winch-rc ships the conffile /etc/winch-rc/rc.conf. After dpkg -r its
	// state is rc: the package is gone, and the conffile stays.
	vm.MustRun(t, `set -e
mkdir -p /root/winch-rc/DEBIAN /root/winch-rc/etc/winch-rc
printf 'Package: winch-rc\nVersion: 1\nArchitecture: all\nMaintainer: winch\nDescription: test\n' > /root/winch-rc/DEBIAN/control
echo /etc/winch-rc/rc.conf > /root/winch-rc/DEBIAN/conffiles
echo rc > /root/winch-rc/etc/winch-rc/rc.conf
dpkg-deb -b /root/winch-rc /root/winch-rc.deb >/dev/null
dpkg -i /root/winch-rc.deb >/dev/null
dpkg -r winch-rc >/dev/null
dpkg-query -W -f='${db:Status-Abbrev}' winch-rc | grep -q '^rc'
touch /etc/winch-rc/stale`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: purge\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  purge-rc: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - dir:\n          path: /etc/winch-rc\n          purge: true\n",
	})
	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "remove file /etc/winch-rc/stale") || strings.Contains(r.Stdout, "rc.conf") {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if got := vm.MustRun(t, "cat /etc/winch-rc/rc.conf; test ! -e /etc/winch-rc/stale"); got != "rc\n" {
		t.Errorf("conffile = %q", got)
	}
	r = lab.Winch(t, dir, "plan", "site", "--exit-code")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
