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
	fresh := module.State{Refreshed: true}
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
	vm.MustRun(t, "ls /var/lib/winch/apt/lists/_srv_old_* >/dev/null && [ -z \"$(find /var/lib/winch/apt/lists ! -type f ! -type d)\" ]")
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

// spec: Running a pipeline/Plan; Modules/file, dir, link (stock, copy_from)
func TestPlanAfterUpgrade(t *testing.T) {
	t.Parallel()
	vm := upgradeVM(t, "upgrade-plan")
	project := func(steps string) string {
		return vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  upgrade-plan: {}\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: app\n",
			"recipes/app/recipe.yaml": "steps:\n" + steps + `handlers:
  reload:
    - cmd:
        command: touch /root/reloaded
`,
		})
	}
	reset := "rm -f /usr/local/bin/apt-get /root/apt-called /etc/winch-new.conf; " + upgradeReset + "; rm -f /root/reloaded /etc/winch-up-copy.conf /etc/winch-example.conf; dpkg --purge winch-stock >/dev/null 2>&1; rm -f /etc/winch-stock.conf; true"
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
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up-copy.conf\n      copy_from: /usr/share/winch-up/ucf.conf\n    notify: reload\n")
		plan(t, dir, "~ file /etc/winch-up-copy.conf\n          content from /usr/share/winch-up/ucf.conf\n          @@ -1,1 +1,1 @@\n          -version 1\n          +version 2\n", "! handler app.reload")
		vm.MustRun(t, "[ \"$(cat /etc/winch-up-copy.conf)\" = 'version 2' ] && [ -e /root/reloaded ]")
	})

	t.Run("stock of a changed conffile that the upgrade keeps", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && echo local > /etc/winch-up.conf")
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up.conf\n      stock: true\n")
		plan(t, dir, "~ file /etc/winch-up.conf\n          content of winch-up 2\n          @@ -1,1 +1,1 @@\n          -local\n          +version 2\n")
		vm.MustRun(t, version("winch-up", "2")+" && [ \"$(cat /etc/winch-up.conf)\" = 'version 2' ]")
	})

	const (
		upgradeOne = "~ upgrade safe\n          upgrade winch-up 1 → 2\n"
		pkgStock   = "+ pkg winch-stock\n          refresh the package index\n          install winch-stock\n"
	)
	// planFirst plans the project, applies it, and plans it again. The first
	// plan must show only the first step, which shows as first.
	planFirst := func(t *testing.T, dir, first string) {
		t.Helper()
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.HasPrefix(r.Stdout, "upgrade-plan\n  base\n    app\n      "+first+"\n1 host: 1 to change") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want only %q", r.Code, r.Stdout, r.Stderr, first)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, "[ ! -e /root/reloaded ]")
		r = lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	}

	t.Run("stock of an unmodified conffile that the upgrade replaces", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up"))
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up.conf\n      stock: true\n    notify: reload\n")
		planFirst(t, dir, upgradeOne)
		vm.MustRun(t, version("winch-up", "2")+" && [ \"$(cat /etc/winch-up.conf)\" = 'version 2' ]")
	})

	t.Run("stock of a package that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - file:\n      path: /etc/winch-stock.conf\n      stock: true\n    notify: reload\n")
		planFirst(t, dir, pkgStock)
		vm.MustRun(t, "[ \"$(cat /etc/winch-stock.conf)\" = stock ]")
	})

	t.Run("steps on paths of a package that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project(`  - pkg:
      name: winch-stock
  - dir:
      path: /etc/winch-stock.d
    notify: reload
  - file:
      path: /etc/winch-stock.d/README
      mode: "0644"
    notify: reload
  - line:
      path: /etc/winch-stock.conf
      line: stock
      match: ^stock$
    notify: reload
`)
		planFirst(t, dir, pkgStock)
	})

	t.Run("copy_from of a file of a package that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - file:\n      path: /etc/winch-example.conf\n      copy_from: /usr/share/winch-stock/example.conf\n")
		plan(t, dir, "+ file /etc/winch-example.conf\n          content from /usr/share/winch-stock/example.conf\n          owner root, group root, mode 0644\n          @@ -0,0 +1,1 @@\n          +example\n")
		vm.MustRun(t, "[ \"$(cat /etc/winch-example.conf)\" = example ]")
	})

	t.Run("apply reads the host after an earlier step installed the package", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project(`  - pkg:
      name: winch-stock
  - cmd:
      command: rm -f /var/cache/apt/archives/winch-stock_* /var/lib/winch/apt/fetched/winch-stock_*; printf '#!/bin/sh\ntouch /root/apt-called\nexit 1\n' > /usr/local/bin/apt-get; chmod 755 /usr/local/bin/apt-get
  - file:
      path: /etc/winch-new.conf
      content: "new\n"
`)
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Errorf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, "[ ! -e /root/apt-called ] && [ \"$(cat /etc/winch-new.conf)\" = new ]")
	})

	t.Run("an archive that apt cannot fetch leaves other paths to the plan", func(t *testing.T) {
		vm.MustRun(t, reset+` && apt-get update -q >/dev/null && rm -f /var/cache/apt/archives/winch-stock_* && printf '#!/bin/sh\ncase " $* " in *" download "*) exit 1 ;; esac\nexec /usr/bin/apt-get "$@"\n' > /usr/local/bin/apt-get && chmod 755 /usr/local/bin/apt-get`)
		dir := project("  - pkg:\n      name: winch-stock\n  - file:\n      path: /etc/winch-new.conf\n      content: \"new\\n\"\n")
		r := lab.Winch(t, dir, "plan", "site")
		if want := "+ file /etc/winch-new.conf\n"; r.Code != 0 || !strings.Contains(r.Stdout, want) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want %q", r.Code, r.Stdout, r.Stderr, want)
		}
	})

	t.Run("an archive that apt cannot fetch fails a step on a path of its package", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up")+` && rm -f /var/cache/apt/archives/winch-up_* && printf '#!/bin/sh\ncase " $* " in *" download "*) exit 1 ;; esac\nexec /usr/bin/apt-get "$@"\n' > /usr/local/bin/apt-get && chmod 755 /usr/local/bin/apt-get`)
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up.conf\n      content: \"mine\\n\"\n")
		r := lab.Winch(t, dir, "plan", "site")
		if want := "get the archive of winch-up 2"; r.Code == 0 || !strings.Contains(r.Stderr, want) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want %q", r.Code, r.Stdout, r.Stderr, want)
		}
	})

	t.Run("a cmd in a directory that a dir step keeps", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - dir:\n      path: /etc/winch-stock.d\n  - cmd:\n      command: \"true\"\n      dir: /etc/winch-stock.d\n")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || strings.Contains(r.Stdout+r.Stderr, "does not exist yet") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})

	t.Run("a link step on a link that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - link:\n      path: /etc/winch-stock.link\n      target: winch-stock.conf\n    notify: reload\n")
		planFirst(t, dir, pkgStock)
	})

	t.Run("a link step that moves a link of an earlier install", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - link:\n      path: /etc/winch-stock.link\n      target: /etc/hostname\n")
		plan(t, dir, "~ link /etc/winch-stock.link\n          target winch-stock.conf → /etc/hostname\n")
	})

	t.Run("steps that change paths of a package that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project(`  - pkg:
      name: winch-stock
  - dir:
      path: /etc/winch-stock.d
      mode: "0700"
  - file:
      path: /etc/winch-stock.d/README
      mode: "0600"
  - file:
      path: /usr/share/winch-stock/example.conf
      content: "mine\n"
    notify: reload
  - line:
      path: /etc/winch-stock.conf
      line: added
      match: ^added$
`)
		plan(t, dir,
			"~ dir /etc/winch-stock.d\n          mode 0755 → 0700\n",
			"~ file /etc/winch-stock.d/README\n          mode 0644 → 0600\n",
			"~ file /usr/share/winch-stock/example.conf\n          @@ -1,1 +1,1 @@\n          -example\n          +mine\n",
			"~ line /etc/winch-stock.conf\n          +added\n",
			"! handler app.reload",
		)
		vm.MustRun(t, "[ -e /root/reloaded ]")
	})

	t.Run("absent steps on paths of a package that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - file:\n      path: /etc/winch-stock.conf\n      absent: true\n  - dir:\n      path: /etc/winch-stock.d\n      absent: true\n    notify: reload\n")
		plan(t, dir, "- file /etc/winch-stock.conf\n", "- dir /etc/winch-stock.d\n", "! handler app.reload")
		vm.MustRun(t, "[ -e /root/reloaded ] && [ ! -e /etc/winch-stock.conf ] && [ ! -e /etc/winch-stock.d ]")
	})

	t.Run("dir recurse on a directory that an earlier step installs", func(t *testing.T) {
		vm.MustRun(t, reset+" && apt-get update -q >/dev/null")
		dir := project("  - pkg:\n      name: winch-stock\n  - dir:\n      path: /etc/winch-stock.d\n      owner: root\n      group: root\n      recurse: true\n")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})

	t.Run("a conffile that the upgrade leaves keeps its mode", func(t *testing.T) {
		vm.MustRun(t, reset+" && rm -rf /root/up-same && cp -r /root/debs/winch-up /root/up-same && echo 'version 2' > /root/up-same/etc/winch-up.conf && dpkg-deb -b /root/up-same /root/up-same.deb >/dev/null && dpkg -i /root/up-same.deb >/dev/null && chmod 600 /etc/winch-up.conf")
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up.conf\n      mode: \"0600\"\n    notify: reload\n")
		planFirst(t, dir, upgradeOne)
		vm.MustRun(t, "[ \"$(stat -c %a /etc/winch-up.conf)\" = 600 ]")
	})

	t.Run("a conffile that the host removed stays removed for its own step", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && rm /etc/winch-up.conf")
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up.conf\n      content: \"mine\\n\"\n")
		plan(t, dir, "+ file /etc/winch-up.conf\n")
	})

	t.Run("a conffile that is no file fails the plan", func(t *testing.T) {
		vm.MustRun(t, reset+" && "+installV1("winch-up")+" && rm /etc/winch-up.conf && mkfifo /etc/winch-up.conf")
		dir := project("  - upgrade:\n      mode: safe\n  - file:\n      path: /etc/winch-up.conf\n      mode: \"0640\"\n")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code == 0 || !strings.Contains(r.Stderr, "not a file") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
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
