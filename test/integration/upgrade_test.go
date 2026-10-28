package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// upgradeDebs builds version 1 of the upgrade test packages in /root/debs.
// The lab's test source has version 2 of winch-up, winch-up-deps, and
// winch-up-conflict, and version 1 of winch-up-new. Version 2 of winch-up
// changes its conffile; version 2 of winch-up-deps depends on winch-up-new;
// version 2 of winch-up-conflict conflicts with winch-up-old. Both versions
// of winch-up install /etc/winch-up-ucf.conf through ucf.
const upgradeDebs = `set -e
deb() {
	mkdir -p /root/debs/$1/DEBIAN
	printf 'Package: %s\nVersion: 1\nArchitecture: all\nMaintainer: winch\nDescription: test\n' $1 > /root/debs/$1/DEBIAN/control
}
deb winch-up
mkdir -p /root/debs/winch-up/etc
echo 'version 1' > /root/debs/winch-up/etc/winch-up.conf
echo /etc/winch-up.conf > /root/debs/winch-up/DEBIAN/conffiles
mkdir -p /root/debs/winch-up/usr/share/winch-up
echo 'version 1' > /root/debs/winch-up/usr/share/winch-up/ucf.conf
printf '#!/bin/sh\nset -e\nif [ "$1" = configure ]; then ucf /usr/share/winch-up/ucf.conf /etc/winch-up-ucf.conf; fi\n' > /root/debs/winch-up/DEBIAN/postinst
chmod 755 /root/debs/winch-up/DEBIAN/postinst
deb winch-up-deps
deb winch-up-conflict
deb winch-up-old
for d in /root/debs/*/; do dpkg-deb -b "$d" "${d%/}.deb" >/dev/null; done`

// installV1 installs version 1 of the named test packages.
func installV1(names ...string) string {
	cmd := "dpkg -i"
	for _, n := range names {
		cmd += " /root/debs/" + n + ".deb"
	}
	return cmd + " >/dev/null"
}

// version is a shell test that the package has the version.
func version(name, v string) string {
	return "[ \"$(dpkg-query -W -f='${db:Status-Abbrev}${Version}' " + name + ")\" = 'ii " + v + "' ]"
}

// upgradeVM starts a VM whose only apt source is the lab's test source, so
// an upgrade sees only the test packages.
func upgradeVM(t *testing.T, name string) *vmtest.VM {
	vm := lab.StartVM(t, name)
	vm.MustRun(t, "rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list.d/winch-debian.sources && "+upgradeDebs+" && "+fragileDeb)
	return vm
}

const upgradeReset = "pkill -f 'fcntl[.]lockf'; rm -f /root/locked /etc/winch-fragile.ok /etc/apt/sources.list.d/winch-down.sources; " +
	"while pgrep -x dpkg >/dev/null; do sleep 0.1; done; apt-mark showhold | xargs -r apt-mark unhold >/dev/null; dpkg --configure -a >/dev/null 2>&1; " +
	"dpkg --purge winch-up winch-up-deps winch-up-new winch-up-conflict winch-up-old winch-fragile >/dev/null 2>&1; ucf --purge /etc/winch-up-ucf.conf 2>/dev/null; rm -f /etc/winch-up.conf* /etc/winch-up-ucf.conf*; true"

// spec: Modules/upgrade; Modules
func TestUpgradeModule(t *testing.T) {
	t.Parallel()
	vm := upgradeVM(t, "upgrade")
	fresh := module.State{IndexFresh: true}
	safe := &module.Upgrade{Mode: "safe"}
	full := &module.Upgrade{Mode: "full"}
	vmtest.RunCases(t, vm, "upgrade", upgradeReset, []vmtest.Case{
		{
			Name:      "nothing to upgrade",
			Args:      safe,
			Want:      module.Result{Status: module.OK},
			WantState: fresh,
		},
		{
			Name: "the check refreshes the index and safe upgrades a package",
			// Without the index of the test source, only a refresh finds
			// version 2.
			Setup:     installV1("winch-up") + " && rm -f /var/lib/apt/lists/10.0.2.100_test_*",
			Args:      safe,
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"upgrade winch-up 1 → 2"}},
			WantState: fresh,
			Unchanged: version("winch-up", "1"),
			After:     version("winch-up", "2"),
		},
		{
			Name:      "changed conffile and ucf files stay, without a question",
			Setup:     installV1("winch-up") + " && echo local > /etc/winch-up.conf && echo local > /etc/winch-up-ucf.conf",
			Args:      full,
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"upgrade winch-up 1 → 2"}},
			WantState: fresh,
			Unchanged: version("winch-up", "1"),
			After:     version("winch-up", "2") + " && [ \"$(echo $(cat /etc/winch-up.conf /etc/winch-up-ucf.conf))\" = \"local local\" ]",
		},
		{
			Name:      "safe installs a new dependency",
			Setup:     installV1("winch-up-deps"),
			Args:      safe,
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"install winch-up-new 1", "upgrade winch-up-deps 1 → 2"}},
			WantState: fresh,
			Unchanged: version("winch-up-deps", "1") + " && ! dpkg -s winch-up-new >/dev/null 2>&1",
			After:     version("winch-up-deps", "2") + " && " + version("winch-up-new", "1"),
		},
		{
			Name:      "safe keeps back an upgrade that removes a package",
			Setup:     installV1("winch-up-old", "winch-up-conflict"),
			Args:      safe,
			Want:      module.Result{Status: module.OK},
			WantState: fresh,
			After:     version("winch-up-conflict", "1") + " && " + version("winch-up-old", "1"),
		},
		{
			Name:      "full upgrades it and removes the package",
			Setup:     installV1("winch-up-old", "winch-up-conflict"),
			Args:      full,
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove winch-up-old", "upgrade winch-up-conflict 1 → 2"}},
			WantState: fresh,
			Unchanged: version("winch-up-old", "1"),
			After:     version("winch-up-conflict", "2") + " && ! dpkg -s winch-up-old >/dev/null 2>&1",
		},
		{
			Name:      "a held package stays",
			Setup:     installV1("winch-up") + " && apt-mark hold winch-up >/dev/null",
			Args:      full,
			Want:      module.Result{Status: module.OK},
			WantState: fresh,
			After:     "dpkg-query -W -f='${db:Status-Abbrev}${Version}' winch-up | grep -qx 'hi 1'",
		},
		{
			Name:  "apply waits for the package locks",
			Setup: installV1("winch-up"),
			Args:  safe,
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"upgrade winch-up 1 → 2"}},
			// The fcntl lock of apt; flock(1) takes a lock that apt does not see.
			BeforeApply: `(python3 -c '` + lockHolder("/var/lib/dpkg/lock-frontend", 3) + `' >/dev/null 2>&1 &) && while [ ! -e /root/locked ]; do sleep 0.1; done`,
			WantState:   fresh,
			Unchanged:   version("winch-up", "1"),
			After:       "! pgrep -f 'fcntl[.]lockf' && " + version("winch-up", "2"),
		},
		{
			Name:    "a half-configured package fails the check",
			Setup:   halfConfigure,
			Args:    safe,
			WantErr: "winch-fragile is half configured: its configuration failed; fix the cause, then run dpkg --configure -a",
		},
		{
			Name: "a source that apt cannot fetch fails the check",
			// Nothing listens on port 9.
			Setup:   installV1("winch-up") + " && printf 'Types: deb\\nURIs: http://127.0.0.1:9/winch-down\\nSuites: trixie\\nComponents: main\\nTrusted: yes\\n' > /etc/apt/sources.list.d/winch-down.sources",
			Args:    safe,
			WantErr: "Failed to fetch http://127.0.0.1:9/winch-down",
		},
	})
}

// spec: CLI (winch run); CLI/Prompts; Modules/service and unit
func TestRunCommand(t *testing.T) {
	t.Parallel()
	vm := upgradeVM(t, "run")
	vm.MustRun(t, `cat > /etc/systemd/system/winch-run.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
ExecReload=/bin/touch /root/reloaded
U
systemctl daemon-reload && systemctl start winch-run`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  run: {}\n",
	})

	t.Run("upgrade asks, --check applies, and a second run has no change", func(t *testing.T) {
		vm.MustRun(t, upgradeReset+"\n"+installV1("winch-up"))
		r := lab.Winch(t, dir, "run", "run", "upgrade", "mode=full")
		if r.Code != 5 || !strings.HasPrefix(r.Stdout, "run\n  run\n    ~ upgrade full\n        upgrade winch-up 1 → 2\n") {
			t.Fatalf("run without a terminal: exit %d", r.Code)
		}
		hash := hashOf(t, r.Stdout)
		if !strings.HasSuffix(r.Stdout, "To apply, run: winch run run upgrade mode=full --check "+hash+"\n") {
			t.Errorf("run without a terminal does not name the command")
		}
		vm.MustRun(t, version("winch-up", "1"))
		r = lab.Winch(t, dir, "run", "run", "upgrade", "mode=full", "--check", hash)
		if r.Code != 0 || !strings.Contains(r.Stdout, "run: run: ~ upgrade full\n") {
			t.Errorf("run --check: exit %d", r.Code)
		}
		vm.MustRun(t, version("winch-up", "2"))
		if r := lab.Winch(t, dir, "run", "run", "upgrade", "mode=full"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second run: exit %d", r.Code)
		}
	})

	t.Run("restarted and reloaded", func(t *testing.T) {
		pid := vm.MustRun(t, "systemctl show -p MainPID --value winch-run")
		r := lab.Winch(t, dir, "run", "run", "service", "name=winch-run", "restarted=true", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "    ~ service winch-run\n        restart\n") {
			t.Errorf("restarted: exit %d", r.Code)
		}
		if after := vm.MustRun(t, "systemctl show -p MainPID --value winch-run"); after == pid {
			t.Errorf("the main PID %s did not change", strings.TrimSpace(pid))
		}
		r = lab.Winch(t, dir, "run", "run", "service", "name=winch-run", "reloaded=true", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "        reload\n") {
			t.Errorf("reloaded: exit %d", r.Code)
		}
		vm.MustRun(t, "test -e /root/reloaded")
	})

	t.Run("restarted in a stage is a load error", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  run: {}\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - service:\n          name: winch-run\n          restarted: true\n",
		})
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 3 || !strings.Contains(r.Stderr, "restarted: only handler steps and winch run can use restarted") {
			t.Errorf("plan: exit %d", r.Code)
		}
	})

	t.Run("pkg installs a package", func(t *testing.T) {
		r := lab.Winch(t, dir, "run", "run", "pkg", "name=winch-up-new", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "run: run: + pkg winch-up-new\n") {
			t.Errorf("run pkg: exit %d", r.Code)
		}
		vm.MustRun(t, version("winch-up-new", "1"))
	})
}
