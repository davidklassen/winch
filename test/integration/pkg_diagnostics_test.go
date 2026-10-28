package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// installNeedsHello installs winch-needs-hello, which depends on hello.
const installNeedsHello = `mkdir -p /root/needs-hello/DEBIAN && printf 'Package: winch-needs-hello\nVersion: 1\nArchitecture: all\nDepends: hello\nMaintainer: winch\nDescription: test\n' > /root/needs-hello/DEBIAN/control && dpkg-deb -b /root/needs-hello /root/needs-hello.deb >/dev/null && dpkg -i /root/needs-hello.deb >/dev/null`

// spec: Modules/pkg
func TestPkgDiagnostics(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pkgdiagnostics")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":              "name: pkgdiagnostics\ninventory: test\n",
		"inventories/test.yaml":   "hosts:\n  pkgdiagnostics: {}\n",
		"pipelines/typo.yaml":     "stages:\n  - name: packages\n    hosts: all\n    steps:\n      - pkg: {name: apache, absent: true}\n",
		"pipelines/conflict.yaml": "stages:\n  - name: packages\n    hosts: all\n    steps:\n      - pkg: {name: winch-conflict}\n",
		"pipelines/remove.yaml":   "stages:\n  - name: packages\n    hosts: all\n    steps:\n      - pkg: {name: hello, absent: true}\n",
		"pipelines/known.yaml":    "stages:\n  - name: packages\n    hosts: all\n    steps:\n      - pkg: {name: [sl, winch-mta], absent: true}\n",
		"pipelines/unknown.yaml":  "stages:\n  - name: packages\n    hosts: all\n    steps:\n      - pkg: {name: [apache, winch-no-such-package]}\n",
	})
	t.Run("an empty index gives no unknown name note", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "typo")
		if r.Code != 0 || !unchanged(r.Stdout, 1) || strings.Contains(r.Stdout+r.Stderr, "apt does not know") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	vm.MustRun(t, "apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q hello >/dev/null")
	t.Run("an unknown absent name is noted", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "typo")
		if r.Code != 0 || !unchanged(r.Stdout, 1) || !strings.Contains(r.Stdout+r.Stderr, "apt does not know apache") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	t.Run("a known name or provider gives no unknown name note", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "known")
		if r.Code != 0 || !unchanged(r.Stdout, 1) || strings.Contains(r.Stdout+r.Stderr, "apt does not know") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	t.Run("an unknown install name gives no note", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "unknown")
		if r.Code != 0 || !strings.Contains(r.Stdout, "other packages: known after the refresh") || strings.Contains(r.Stdout+r.Stderr, "apt does not know") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	t.Run("a needed removal names the package and fix", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "conflict")
		want := "apt must remove hello; add a pkg step with name: hello and absent: true before this step"
		if r.Code == 0 || !strings.Contains(r.Stdout+r.Stderr, want) {
			t.Errorf("plan: exit %d, want %q, stdout %q, stderr %q", r.Code, want, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, "dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii' && ! dpkg -s winch-conflict >/dev/null 2>&1")
	})
	t.Run("each needed removal names the package and fix", func(t *testing.T) {
		vm.MustRun(t, installNeedsHello)
		r := lab.Winch(t, dir, "plan", "conflict")
		for _, n := range []string{"hello", "winch-needs-hello"} {
			want := "apt must remove " + n + "; add a pkg step with name: " + n + " and absent: true before this step"
			if r.Code == 0 || !strings.Contains(r.Stdout+r.Stderr, want) {
				t.Errorf("plan: exit %d, want %q, stdout %q, stderr %q", r.Code, want, r.Stdout, r.Stderr)
			}
		}
		vm.MustRun(t, "dpkg --purge winch-needs-hello >/dev/null")
	})
	t.Run("a needed removal after the refresh names the package and fix", func(t *testing.T) {
		vm.MustRun(t, "rm /var/lib/apt/lists/10.0.2.100_test_*")
		r := lab.Winch(t, dir, "apply", "conflict", "--yes")
		want := "apt must remove hello; add a pkg step with name: hello and absent: true before this step"
		if r.Code == 0 || !strings.Contains(r.Stdout+r.Stderr, want) {
			t.Errorf("apply: exit %d, want %q, stdout %q, stderr %q", r.Code, want, r.Stdout, r.Stderr)
		}
		if !strings.Contains(r.Stdout, "other packages: known after the refresh") || !strings.Contains(r.Stderr, "packages: failed: pkg winch-conflict:") {
			t.Errorf("want a plan with unknown dependencies and a failure during apply, stdout %q, stderr %q", r.Stdout, r.Stderr)
		}
		vm.MustRun(t, "dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii' && ! dpkg -s winch-conflict >/dev/null 2>&1")
	})
	t.Run("a separate removal run allows the install", func(t *testing.T) {
		for _, pipeline := range []string{"remove", "conflict"} {
			r := lab.Winch(t, dir, "apply", pipeline, "--yes")
			if r.Code != 0 {
				t.Fatalf("%s apply: exit %d, stdout %q, stderr %q", pipeline, r.Code, r.Stdout, r.Stderr)
			}
		}
		vm.MustRun(t, "dpkg-query -W -f='${db:Status-Abbrev}' winch-conflict | grep -q '^ii' && ! dpkg -s hello >/dev/null 2>&1")
		r := lab.Winch(t, dir, "plan", "conflict")
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
}

// spec: Modules/pkg
func TestPkgForeignRemovalHint(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pkgforeign")
	vm.MustRun(t, `dpkg --add-architecture armhf && mkdir -p /root/foreign/DEBIAN && printf 'Package: hello\nVersion: 1\nArchitecture: armhf\nMulti-Arch: foreign\nMaintainer: winch\nDescription: test\n' > /root/foreign/DEBIAN/control && dpkg-deb -b /root/foreign /root/hello.deb >/dev/null && dpkg -i /root/hello.deb >/dev/null && apt-get update -q >/dev/null`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":              "name: pkgforeign\ninventory: test\n",
		"inventories/test.yaml":   "hosts:\n  pkgforeign: {}\n",
		"pipelines/conflict.yaml": "stages:\n  - name: packages\n    hosts: all\n    steps:\n      - pkg: {name: winch-conflict}\n",
	})
	r := lab.Winch(t, dir, "plan", "conflict")
	want := "apt must remove hello:armhf; first run apt-get remove hello:armhf"
	if r.Code == 0 || !strings.Contains(r.Stdout+r.Stderr, want) {
		t.Fatalf("plan: exit %d, want %q, stdout %q, stderr %q", r.Code, want, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "apt-get remove -y -q hello:armhf >/dev/null")
	r = lab.Winch(t, dir, "apply", "conflict", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "dpkg-query -W -f='${db:Status-Abbrev}' winch-conflict | grep -q '^ii' && ! dpkg -s hello:armhf >/dev/null 2>&1")
}
