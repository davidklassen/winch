package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// upgradeDebs builds version 1 of the upgrade test packages in /root/debs.
// The lab's test source has version 2 of winch-up, winch-up-deps,
// winch-up-conflict, and winch-up-nossh, and version 1 of winch-up-new.
// Version 2 of winch-up changes its conffile; version 2 of winch-up-deps
// depends on winch-up-new; version 2 of winch-up-conflict conflicts with
// winch-up-old; version 2 of winch-up-nossh conflicts with openssh-server. Both versions
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
deb winch-up-nossh
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

// testIndex is the file of the lab's test source in apt's index.
const testIndex = "/var/lib/apt/lists/10.0.2.100_test_*Packages"

// hookConf is an apt config with update hooks.
const hookConf = "/etc/apt/apt.conf.d/99winch-hook"

const upgradeReset = "pkill -f 'fcntl[.]lockf'; rm -f " + hookConf + " /root/hook /root/locked /etc/winch-fragile.ok /etc/apt/sources.list.d/winch-down.sources; " +
	"while pgrep -x dpkg >/dev/null; do sleep 0.1; done; apt-mark showhold | xargs -r apt-mark unhold >/dev/null; dpkg --configure -a >/dev/null 2>&1; " +
	"dpkg --purge winch-up winch-up-deps winch-up-new winch-up-conflict winch-up-old winch-fragile >/dev/null 2>&1; ucf --purge /etc/winch-up-ucf.conf 2>/dev/null; rm -f /etc/winch-up.conf* /etc/winch-up-ucf.conf*; true"

// aptFiles lists apt's index and caches with the size and modification time
// of each file.
const aptFiles = "find /var/lib/apt/lists /var/cache/apt -printf '%p %s %T@\\n' | sort"

// downSource adds a source that apt cannot fetch: nothing listens on port 9.
const downSource = "printf 'Types: deb\\nURIs: http://127.0.0.1:9/winch-down\\nSuites: trixie\\nComponents: main\\nTrusted: yes\\n' > /etc/apt/sources.list.d/winch-down.sources"

// spec: Modules/upgrade; Modules
func TestUpgradeModule(t *testing.T) {
	t.Parallel()
	vm := upgradeVM(t, "upgrade")
	fresh := module.State{Refreshed: true, Upgraded: true}
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
			Setup:     installV1("winch-up") + " && rm -f /var/lib/apt/lists/10.0.2.100_test_* /var/lib/winch/apt/lists/10.0.2.100_test_* && " + aptFiles + " > /root/apt-files",
			Args:      safe,
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"upgrade winch-up 1 → 2"}},
			WantState: fresh,
			Unchanged: version("winch-up", "1") + " && " + aptFiles + " | cmp - /root/apt-files",
			After:     version("winch-up", "2"),
		},
		{
			Name:      "the refresh runs no update hook",
			Setup:     `echo 'APT::Update::Pre-Invoke {"touch /root/hook";}; APT::Update::Post-Invoke-Success {"touch /root/hook";};' > ` + hookConf,
			Args:      safe,
			Want:      module.Result{Status: module.OK},
			WantState: fresh,
			Unchanged: "[ ! -e /root/hook ]",
		},
		{
			Name: "the check skips the refresh after a refresh of the run",
			// A refresh fails on this source, so an ok check did not refresh.
			Setup:     downSource,
			State:     module.State{Refreshed: true},
			Args:      safe,
			Want:      module.Result{Status: module.OK},
			WantState: fresh,
			After:     "rm /etc/apt/sources.list.d/winch-down.sources",
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
			Name:    "a source that apt cannot fetch fails the check",
			Setup:   installV1("winch-up") + " && " + downSource,
			Args:    safe,
			WantErr: "Failed to fetch http://127.0.0.1:9/winch-down",
		},
	})
}

// oldVersion replaces winch-signed in the file: source of oldSigned with
// version v.
func oldVersion(v string) string {
	return `set -e
cd /srv/old
rm -f winch-signed_*.deb
sed -i 's/^Version: .*/Version: ` + v + `/' winch-signed/DEBIAN/control
dpkg-deb -b winch-signed winch-signed_` + v + `_all.deb >/dev/null
{ dpkg-deb -f winch-signed_` + v + `_all.deb; echo "Filename: ./winch-signed_` + v + `_all.deb"; echo "Size: $(stat -c %s winch-signed_` + v + `_all.deb)"; echo "SHA256: $(sha256sum winch-signed_` + v + `_all.deb | cut -d' ' -f1)"; } > Packages`
}

// spec: Modules/upgrade; Remote execution/State on the host
func TestUpgradeFileSource(t *testing.T) {
	t.Parallel()
	vm := upgradeVM(t, "upgrade-file")
	vm.MustRun(t, oldSigned+" && DEBIAN_FRONTEND=noninteractive apt-get install -y -q winch-signed=0 >/dev/null")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  upgrade-file: {}\n",
	})
	upgrade := func() vmtest.Result {
		return lab.Winch(t, dir, "run", "upgrade-file", "upgrade", "mode=safe")
	}
	if r := upgrade(); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Fatalf("first run: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, oldVersion("2"))
	if r := upgrade(); r.Code != 5 || !strings.Contains(r.Stdout, "upgrade winch-signed 0 → 2") {
		t.Fatalf("run after version 2: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, oldVersion("3")+" && "+downSource)
	if r := upgrade(); r.Code == 0 || !strings.Contains(r.Stderr, "Failed to fetch http://127.0.0.1:9/winch-down") {
		t.Fatalf("run with a source that apt cannot fetch: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "rm /etc/apt/sources.list.d/winch-down.sources")
	if r := upgrade(); r.Code != 5 || !strings.Contains(r.Stdout, "upgrade winch-signed 0 → 3") {
		t.Fatalf("run after the failed refresh: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "ls /var/lib/winch/apt/lists/_srv_old_* >/dev/null")
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
		if r.Code != 3 || !strings.Contains(r.Stderr, "restarted: a step with restarted needs on_change; add on_change with the paths whose change it reacts to") {
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

// spec: Running a pipeline/Plan; Modules/file, dir, link (stock, copy_from); Modules/pkg
func TestPlanAfterUpgrade(t *testing.T) {
	t.Parallel()
	vm := upgradeVM(t, "upgrade-plan")
	project := func(steps string) string {
		return vmtest.WriteProject(t, map[string]string{
			"winch.yaml":              "name: demo\ninventory: test\n",
			"inventories/test.yaml":   "hosts:\n  upgrade-plan: {}\n",
			"pipelines/site.yaml":     "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: app\n",
			"recipes/app/recipe.yaml": "steps:\n" + steps,
		})
	}
	reset := upgradeReset + "; rm -f /root/reloaded /etc/winch-up-copy.conf /etc/winch-example.conf; dpkg --purge winch-stock winch-mta >/dev/null 2>&1; rm -rf /etc/winch-stock.conf /var/cache/apt/archives/winch-stock_0_all.deb /root/virt /etc/apt/sources.list.d/winch-virt.sources; true"
	// plan plans the project, applies it, and plans it again. The first plan
	// must hold each of want.
	plan := func(t *testing.T, dir string, want ...string) {
		t.Helper()
		r := lab.Winch(t, dir, "plan", "site")
		for _, w := range want {
			if r.Code != 0 || !strings.Contains(r.Stdout, w) {
				t.Errorf("plan: exit %d, stdout %q, stderr %q, want %q", r.Code, r.Stdout, r.Stderr, w)
			}
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		r = lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	}

	t.Run("copy_from of a file that the upgrade changes", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && cp /usr/share/winch-up/ucf.conf /etc/winch-up-copy.conf")
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up-copy.conf\n      copy_from: /usr/share/winch-up/ucf.conf\n  - cmd:\n      command: touch /root/reloaded\n    on_change: [/etc/winch-up-copy.conf]\n")
		plan(t, dir, "~ file /etc/winch-up-copy.conf\n          content from /usr/share/winch-up/ucf.conf\n          @@ -1,1 +1,1 @@\n          -version 1\n          +version 2\n", "? cmd touch /root/reloaded (/etc/winch-up-copy.conf changes)")
		vm.MustRun(t, "[ \"$(cat /etc/winch-up-copy.conf)\" = 'version 2' ] && [ -e /root/reloaded ]")
	})

	t.Run("stock of a changed conffile that the upgrade keeps", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && echo local > /etc/winch-up.conf")
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up.conf\n      stock: true\n")
		plan(t, dir, "~ file /etc/winch-up.conf\n          content of winch-up 2\n          @@ -1,1 +1,1 @@\n          -local\n          +version 2\n")
		vm.MustRun(t, version("winch-up", "2")+" && [ \"$(cat /etc/winch-up.conf)\" = 'version 2' ]")
	})

	t.Run("stock of a package that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - file:\n      path: /etc/winch-stock.conf\n      stock: true\n")
		plan(t, dir, "file /etc/winch-stock.conf\n          content of winch-stock 1\n")
		vm.MustRun(t, "[ \"$(cat /etc/winch-stock.conf)\" = stock ]")
	})

	t.Run("copy_from of a file of a package that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - file:\n      path: /etc/winch-example.conf\n      copy_from: /usr/share/winch-stock/example.conf\n")
		plan(t, dir, "+ file /etc/winch-example.conf\n          content from /usr/share/winch-stock/example.conf\n          owner root, group root, mode 0644\n          @@ -0,0 +1,1 @@\n          +example\n")
		vm.MustRun(t, "[ \"$(cat /etc/winch-example.conf)\" = example ]")
	})

	// stale makes apt's index an old one, in which the test source has version
	// 0 of winch-stock. The source has only version 1. The old date makes the
	// refresh fetch the index again.
	stale := " && apt-get update -q >/dev/null && sed -i '/^Package: winch-stock$/,/^$/{s/^Version: 1$/Version: 0/;s/winch-stock_1_all/winch-stock_0_all/}' " + testIndex + " && touch -d 2000-01-01 " + testIndex
	staleUp := "sed -i -e '/^Package: winch-up$/,/^$/{s/^Version: 2$/Version: 3/;s/winch-up_2_all/winch-up_3_all/}' -e '/^Package: winch-up-new$/a Depends: winch-up (>= 3)' " + testIndex + " && touch -d 2000-01-01 " + testIndex
	stockSteps := "  - pkg:\n      name: winch-stock\n  - file:\n      path: /etc/winch-stock.conf\n      stock: true\n"

	t.Run("stock of a version that the source no longer has", func(t *testing.T) {
		vm.MustRun(t, reset+stale+" && echo local > /etc/winch-stock.conf")
		plan(t, project(stockSteps), "~ file /etc/winch-stock.conf\n          content of the package that ships /etc/winch-stock.conf (known after the refresh)\n          owner, group, and mode from the package\n")
		vm.MustRun(t, version("winch-stock", "1")+" && [ \"$(cat /etc/winch-stock.conf)\" = stock ]")
	})

	t.Run("copy_from of a version that the source no longer has", func(t *testing.T) {
		vm.MustRun(t, reset+stale)
		dir := project("  - pkg:\n      name: winch-stock\n  - file:\n      path: /etc/winch-example.conf\n      copy_from: /usr/share/winch-stock/example.conf\n")
		plan(t, dir, "+ file /etc/winch-example.conf\n          content from /usr/share/winch-stock/example.conf (known after the refresh)\n          owner root, group root, mode from /usr/share/winch-stock/example.conf\n")
		vm.MustRun(t, "[ \"$(cat /etc/winch-example.conf)\" = example ]")
	})

	t.Run("copy_from of an upgrade to a version that the source no longer has", func(t *testing.T) {
		// In the old index, winch-up-new needs version 3 of the installed winch-up.
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && apt-get update -q >/dev/null && "+staleUp)
		dir := project("  - pkg:\n      name: winch-up-new\n  - file:\n      path: /etc/winch-up-copy.conf\n      copy_from: /usr/share/winch-up/ucf.conf\n")
		plan(t, dir, "also upgrade winch-up\n", "+ file /etc/winch-up-copy.conf\n          content from /usr/share/winch-up/ucf.conf (known after the refresh)\n")
		vm.MustRun(t, version("winch-up", "1")+" && [ \"$(cat /etc/winch-up-copy.conf)\" = 'version 1' ]")
	})

	t.Run("stock reads the installed version after an install from an old index", func(t *testing.T) {
		// apt's cache has the archive of version 0, so the plan reads it, and
		// the file holds its content. apt deletes a cached archive whose size
		// differs from the index.
		vm.MustRun(t, reset+stale+` && mkdir -p /var/cache/apt/archives /root/stock0/DEBIAN /root/stock0/etc && echo old > /root/stock0/etc/winch-stock.conf &&
printf 'Package: winch-stock\nVersion: 0\nArchitecture: all\nMaintainer: winch\nDescription: test\n' > /root/stock0/DEBIAN/control &&
dpkg-deb -b /root/stock0 /var/cache/apt/archives/winch-stock_0_all.deb >/dev/null && echo old > /etc/winch-stock.conf &&
size=$(stat -c %s /var/cache/apt/archives/winch-stock_0_all.deb) && sum=$(sha256sum /var/cache/apt/archives/winch-stock_0_all.deb | cut -d' ' -f1) &&
sed -i "/^Package: winch-stock$/,/^$/{/^MD5sum:\|^SHA1:\|^SHA512:/d;s/^Size: .*/Size: $size/;s/^SHA256: .*/SHA256: $sum/}" `+testIndex+` && touch -d 2000-01-01 `+testIndex)
		dir := project(stockSteps)
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || strings.Contains(r.Stdout, "known after the refresh") || strings.Contains(r.Stdout, "file /etc/winch-stock.conf") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want the file ok with version 0", r.Code, r.Stdout, r.Stderr)
		}
		plan(t, dir)
		vm.MustRun(t, version("winch-stock", "1")+" && [ \"$(cat /etc/winch-stock.conf)\" = stock ]")
	})

	t.Run("stock of an upgrade to a version that the source no longer has", func(t *testing.T) {
		// In the old index, winch-up-new needs version 3 of the installed
		// winch-up. The refresh removes that need, so apply reads version 1.
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && mkdir -p /var/cache/apt/archives && cp /root/debs/winch-up.deb /var/cache/apt/archives/winch-up_1_all.deb && apt-get update -q >/dev/null && "+staleUp)
		dir := project("  - pkg:\n      name: winch-up-new\n  - file:\n      path: /etc/winch-up.conf\n      stock: true\n")
		plan(t, dir, "also upgrade winch-up\n", "~ file /etc/winch-up.conf\n          content of the package that ships /etc/winch-up.conf (known after the refresh)\n")
		vm.MustRun(t, "rm /var/cache/apt/archives/winch-up_1_all.deb; "+version("winch-up", "1")+" && [ \"$(cat /etc/winch-up.conf)\" = 'version 1' ]")
	})

	t.Run("stock of a named package beside one whose version the source no longer has", func(t *testing.T) {
		// winch-conflict sorts before winch-stock, and its archive is gone.
		vm.MustRun(t, reset+" && dpkg --purge winch-conflict >/dev/null 2>&1; apt-get update -q >/dev/null && sed -i '/^Package: winch-conflict$/,/^$/{s/^Version: .*/Version: 0/;s/winch-conflict_[^_]*_all/winch-conflict_0_all/}' "+testIndex+" && touch -d 2000-01-01 "+testIndex)
		dir := project("  - pkg:\n      name: [winch-conflict, winch-stock]\n  - file:\n      path: /etc/winch-stock.conf\n      stock: true\n")
		plan(t, dir, "file /etc/winch-stock.conf\n          content of winch-stock 1\n")
		vm.MustRun(t, "dpkg --purge winch-conflict >/dev/null")
	})

	copyConf := "  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up-copy.conf\n      copy_from: /etc/winch-up.conf\n"
	t.Run("copy_from of a conffile that the host changed", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && echo local > /etc/winch-up.conf && cp /etc/winch-up.conf /etc/winch-up-copy.conf")
		plan(t, project(copyConf), "upgrade winch-up 1 → 2\n\n1 host")
		vm.MustRun(t, version("winch-up", "2")+" && [ \"$(cat /etc/winch-up-copy.conf)\" = local ]")
	})

	t.Run("copy_from of a conffile that the host removed", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && rm /etc/winch-up.conf")
		r := lab.Winch(t, project(copyConf), "plan", "site")
		if want := "content from /etc/winch-up.conf (does not exist yet)"; r.Code != 0 || !strings.Contains(r.Stdout, want) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want %q: dpkg keeps a removed conffile removed", r.Code, r.Stdout, r.Stderr, want)
		}
	})

	t.Run("a name that only other packages provide after an upgrade step", func(t *testing.T) {
		// Without apt's index of the test source, as on a new host, only
		// winch's index knows winch-mta.
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && rm -f /var/lib/apt/lists/10.0.2.100_test_*")
		r := lab.Winch(t, project("  - upgrade:\n      mode: full\n  - pkg:\n      name: winch-mta\n"), "apply", "site", "--yes")
		if want := "winch-mta is provided by winch-mta-a, winch-mta-b; name one of them"; r.Code == 0 || !strings.Contains(r.Stderr, want) {
			t.Errorf("apply: exit %d, stdout %q, stderr %q, want an error with %q", r.Code, r.Stdout, r.Stderr, want)
		}
		vm.MustRun(t, version("winch-up", "1"))
	})

	t.Run("a name that winch's index does not know after an upgrade step", func(t *testing.T) {
		vm.MustRun(t, reset)
		r := lab.Winch(t, project("  - upgrade:\n      mode: safe\n  - pkg:\n      name: winch-no-such-package\n"), "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, module.OthersUnknown) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want %q", r.Code, r.Stdout, r.Stderr, module.OthersUnknown)
		}
	})

	t.Run("a real package of a source that a file step adds before an upgrade step", func(t *testing.T) {
		// Only winch-mta-a and winch-mta-b of the test source provide
		// winch-mta. The file step adds a source with a real winch-mta, which
		// winch's index of the plan does not have.
		vm.MustRun(t, reset+" && mkdir -p /root/virt/pkg/DEBIAN && "+
			`printf 'Package: winch-mta\nVersion: 1\nArchitecture: all\nMaintainer: winch\nDescription: test\n' > /root/virt/pkg/DEBIAN/control && `+
			"dpkg-deb -b /root/virt/pkg /root/virt/winch-mta.deb >/dev/null && cd /root/virt && "+
			`{ cat pkg/DEBIAN/control && printf 'Filename: winch-mta.deb\nSize: %s\nSHA256: %s\n' "$(stat -c %s winch-mta.deb)" "$(sha256sum winch-mta.deb | cut -d' ' -f1)"; } > Packages`)
		dir := project("  - file:\n      path: /etc/apt/sources.list.d/winch-virt.sources\n      content: |\n        Types: deb\n        URIs: file:/root/virt\n        Suites: ./\n        Trusted: yes\n" +
			"  - pkg:\n      name: winch-mta\n  - upgrade:\n      mode: safe\n")
		if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
			t.Errorf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, version("winch-mta", "1"))
	})

	t.Run("a name that only other packages provide without an upgrade step", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		r := lab.Winch(t, project("  - pkg:\n      name: winch-mta\n"), "plan", "site")
		if want := "note: winch-mta may be provided by winch-mta-a, winch-mta-b; apply checks it after the refresh\n"; r.Code != 0 || !strings.Contains(r.Stderr, want) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want %q", r.Code, r.Stdout, r.Stderr, want)
		}
	})

	// upgraded upgrades winch-up to version 2 while apt's index names version
	// 1, so only winch's index has version 2, and cleans apt's cache.
	upgraded := func(t *testing.T) {
		t.Helper()
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && apt-get update -q >/dev/null && sed -i '/^Package: winch-up$/,/^$/{s/^Version: 2$/Version: 1/;s/winch-up_2_all/winch-up_1_all/}' "+testIndex)
		if r := lab.Winch(t, project("  - upgrade:\n      mode: safe\n"), "apply", "site", "--yes"); r.Code != 0 {
			t.Fatalf("apply the upgrade: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, version("winch-up", "2")+" && apt-get clean && echo local > /etc/winch-up.conf && "+aptFiles+" > /root/apt-files")
	}
	stockUp := "  - file:\n      path: /etc/winch-up.conf\n      stock: true\n"

	t.Run("stock after an upgrade and a clean of apt's cache", func(t *testing.T) {
		upgraded(t)
		plan(t, project(stockUp), "~ file /etc/winch-up.conf\n          content of winch-up 2\n          @@ -1,1 +1,1 @@\n          -local\n          +version 2\n")
		vm.MustRun(t, "[ \"$(cat /etc/winch-up.conf)\" = 'version 2' ] && "+sameCache)
	})

	t.Run("stock beside an upgrade step after a clean of apt's cache", func(t *testing.T) {
		upgraded(t)
		plan(t, project("  - upgrade:\n      mode: safe\n"+stockUp), "~ file /etc/winch-up.conf\n          content of winch-up 2\n")
		vm.MustRun(t, sameCache)
	})

	for _, c := range []struct {
		name, setup string
		both        bool
	}{
		{"stock of a version that no index has", "rm -f /var/lib/winch/apt/lists/10.0.2.100_test_*", true},
		{"stock of a version that apt's index lacks, without winch's index", "rm -rf /var/lib/winch/apt/lists", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			upgraded(t)
			vm.MustRun(t, c.setup)
			r := lab.Winch(t, project(stockUp), "plan", "site")
			if r.Code == 0 || !strings.Contains(r.Stderr, "get the archive of winch-up 2: apt-get download") || strings.Contains(r.Stderr, "through winch's index") != c.both {
				t.Errorf("plan: exit %d, stdout %q, stderr %q, want a failed fetch, through winch's index: %v", r.Code, r.Stdout, r.Stderr, c.both)
			}
			vm.MustRun(t, sameCache)
		})
	}
}

// spec: Running a pipeline/Plan
func TestPlanThroughMovedLink(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "moved-link")
	// v2/data is a link to a directory, which v1 does not have.
	vm.MustRun(t, "mkdir -p /srv/app/v1 /srv/app/v2/real && echo old > /srv/app/v1/config && echo new > /srv/app/v2/config && ln -s real /srv/app/v2/data && ln -s v1 /srv/app/current")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  moved-link: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - link:
          path: /srv/app/current
          target: v2
      - file:
          path: /srv/app/current/config
          content: "new\n"
      - file:
          path: /srv/app/copy
          copy_from: /srv/app/current/config
      - dir:
          path: /srv/app/current/data
`,
	})
	r := lab.Winch(t, dir, "plan", "site")
	if want := "~ link /srv/app/current\n        target v1 → v2\n    + file /srv/app/copy\n        content from /srv/app/current/config\n        owner root, group root, mode 0644\n        @@ -0,0 +1,1 @@\n        +new\n\n"; r.Code != 0 || !strings.Contains(r.Stdout, want) {
		t.Errorf("plan: exit %d, stdout %q, stderr %q, want %q", r.Code, r.Stdout, r.Stderr, want)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "[ \"$(cat /srv/app/v1/config)\" = old ] && [ \"$(cat /srv/app/copy)\" = new ]")
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}
