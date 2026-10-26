package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// quietApt stops the apt timers, so no other apt run holds the lock or
// refreshes the index during a test.
const quietApt = "systemctl stop apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service"

// fragileDeb builds winch-fragile, a local package whose postinst fails
// until /etc/winch-fragile.ok exists.
const fragileDeb = `mkdir -p /root/fragile/DEBIAN && printf 'Package: winch-fragile\nVersion: 1\nArchitecture: all\nMaintainer: winch\nDescription: test\n' > /root/fragile/DEBIAN/control && ` +
	`printf '#!/bin/sh\n[ -e /etc/winch-fragile.ok ]\n' > /root/fragile/DEBIAN/postinst && chmod 755 /root/fragile/DEBIAN/postinst && dpkg-deb -b /root/fragile /root/winch-fragile.deb >/dev/null`

// halfConfigure installs winch-fragile without the marker, so dpkg keeps it
// half configured.
const halfConfigure = "! dpkg -i /root/winch-fragile.deb >/dev/null 2>&1 && dpkg-query -W -f='${db:Status-Abbrev}' winch-fragile | grep -q '^iF'"

// spec: Modules/pkg
func TestPkgModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pkg")
	// Every apt-get update adds a line to /root/updates.
	vm.MustRun(t, quietApt+` && echo 'APT::Update::Pre-Invoke {"echo x >> /root/updates";};' > /etc/apt/apt.conf.d/99count && touch /root/updates`)
	const (
		install = "DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends"
		// count keeps the number of refreshes; same checks it after apply.
		count = "wc -l < /root/updates > /root/before"
		same  = `[ "$(wc -l < /root/updates)" = "$(cat /root/before)" ]`
	)
	refresh := "refresh the package index"
	// startSlow returns while the postinst of winch-slow runs. The [w] keeps
	// pgrep from matching this shell.
	startSlow := "touch /root/slow && (dpkg -i /root/winch-slow.deb >/dev/null 2>&1 &) && " +
		"for i in $(seq 100); do pgrep -f winch-slo[w].postinst >/dev/null && break; sleep 0.1; done"
	interrupted := startSlow + " && pkill -9 -x dpkg; rm /root/slow && dpkg-query -W -f='${db:Status-Abbrev}' winch-slow | grep -q '^iF'"
	// winch-slow is a local package whose postinst sleeps while /root/slow
	// exists, so a test can kill its install.
	vm.MustRun(t, `mkdir -p /root/slow-pkg/DEBIAN && printf 'Package: winch-slow\nVersion: 1\nArchitecture: all\nMaintainer: winch\nDescription: test\n' > /root/slow-pkg/DEBIAN/control && `+
		`printf '#!/bin/sh\nwhile [ -e /root/slow ]; do sleep 1; done\n' > /root/slow-pkg/DEBIAN/postinst && chmod 755 /root/slow-pkg/DEBIAN/postinst && dpkg-deb -b /root/slow-pkg /root/winch-slow.deb >/dev/null`)
	vm.MustRun(t, fragileDeb)
	// The lab's test source has version 2 of winch-fragile, and winch-mta-a,
	// winch-mta-b, and winch-mta-c for armhf, which provide winch-mta. The
	// provides of a foreign package with Multi-Arch: foreign count for the
	// native architecture too.
	// winch-mta-a also provides winch-fragile. winch-conflict conflicts with
	// hello. The reset removes the index of the test source, so a case sees
	// these packages only after a refresh.
	const localRepo = "apt-get update -q >/dev/null"
	// localOnly refreshes only the index of the test source.
	const localOnly = "apt-get update -q -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winch-test.sources -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 >/dev/null"
	const localArmhf = "dpkg --add-architecture armhf && " + localOnly
	reset := "pkill -f 'fcntl[.]lockf'; rm -f /root/slow /root/locked /etc/winch-fragile.ok; while pgrep -x dpkg >/dev/null || pgrep -f winch-slo[w].postinst >/dev/null; do sleep 0.1; done; rm -f /etc/apt/apt.conf.d/99norecommends /etc/apt/sources.list.d/winch-down.sources /var/lib/apt/lists/10.0.2.100_test_*; apt-mark showhold | xargs -r apt-mark unhold >/dev/null; dpkg --purge winch-mta-c:armhf >/dev/null 2>&1; dpkg --remove-architecture armhf 2>/dev/null; " +
		"dpkg --configure -a >/dev/null 2>&1; dpkg --purge winch-slow winch-fragile winch-conflict hello sl figlet tree fortune-mod fortunes-min librecode3 at >/dev/null 2>&1; true"
	vmtest.RunCases(t, vm, "pkg", reset, []vmtest.Case{
		{
			Name:      "the first install of a run refreshes the index",
			Setup:     count,
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello"}},
			WantState: module.State{IndexFresh: true},
			Unchanged: same + " && ! dpkg -s hello >/dev/null 2>&1",
			After:     `[ "$(wc -l < /root/updates)" = $(( $(cat /root/before) + 1 )) ] && dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii'`,
		},
		{
			Name:      "the refresh creates a missing index directory",
			Setup:     "rm -rf /var/lib/apt/lists",
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello"}},
			WantState: module.State{IndexFresh: true},
			Unchanged: "[ ! -e /var/lib/apt/lists ]",
			After:     "[ -d /var/lib/apt/lists/partial ] && dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii'",
		},
		{
			Name: "a refresh fails when apt cannot fetch a source",
			// Nothing listens on port 9.
			Setup:        "printf 'Types: deb\\nURIs: http://127.0.0.1:9/winch-down\\nSuites: trixie\\nComponents: main\\nTrusted: yes\\n' > /etc/apt/sources.list.d/winch-down.sources",
			Args:         &module.Pkg{Name: []string{"hello"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello"}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "Failed to fetch http://127.0.0.1:9/winch-down",
		},
		{
			Name:  "ok when installed",
			Setup: install + " hello",
			Args:  &module.Pkg{Name: []string{"hello"}},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "no refresh after the first install of the run",
			Setup:     count,
			State:     module.State{IndexFresh: true},
			Args:      &module.Pkg{Name: []string{"figlet"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install figlet"}},
			WantState: module.State{IndexFresh: true},
			After:     same,
		},
		{
			Name:      "a package that came in as a dependency is marked as manually installed",
			Setup:     install + " fortune-mod && apt-mark showauto librecode3 | grep -q librecode3",
			Args:      &module.Pkg{Name: []string{"librecode3"}},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mark librecode3 as manually installed"}},
			Unchanged: "apt-mark showauto librecode3 | grep -q librecode3",
			// A dry run of autoremove keeps the other automatic packages of the VM.
			After: "DEBIAN_FRONTEND=noninteractive apt-get purge -y -q fortune-mod && ! apt-get -s autoremove | grep -q '^Remv librecode3 '",
		},
		{
			Name:      "a list installs a missing package and marks a dependency",
			State:     module.State{IndexFresh: true},
			Setup:     install + " fortune-mod",
			Args:      &module.Pkg{Name: []string{"hello", "librecode3"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install hello", "mark librecode3 as manually installed"}},
			WantState: module.State{IndexFresh: true},
			Unchanged: "apt-mark showauto librecode3 | grep -q librecode3",
			After:     "apt-mark showmanual hello librecode3 | grep -c . | grep -qx 2",
		},
		{
			Name:      "a list installs the missing packages in one apt call",
			State:     module.State{IndexFresh: true},
			Setup:     install + " hello && grep -c ^Commandline /var/log/apt/history.log > /root/hist",
			Args:      &module.Pkg{Name: []string{"tree", "hello", "figlet"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install tree, figlet"}},
			WantState: module.State{IndexFresh: true},
			After: `[ "$(grep -c ^Commandline /var/log/apt/history.log)" = $(( $(cat /root/hist) + 1 )) ] && ` +
				`grep ^Commandline /var/log/apt/history.log | tail -1 | grep -q 'tree figlet'`,
		},
		{
			Name:      "recommends false",
			State:     module.State{IndexFresh: true},
			Args:      &module.Pkg{Name: []string{"fortune-mod"}, Recommends: new(false)},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install fortune-mod (without recommended packages)"}},
			WantState: module.State{IndexFresh: true},
			After:     `dpkg -s fortune-mod >/dev/null && ! dpkg -s fortunes-min >/dev/null 2>&1`,
		},
		{
			Name:      "recommended packages by default",
			State:     module.State{IndexFresh: true},
			Args:      &module.Pkg{Name: []string{"fortune-mod"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install fortune-mod"}},
			WantState: module.State{IndexFresh: true},
			After:     `dpkg-query -W -f='${db:Status-Abbrev}' fortunes-min | grep -q '^ii'`,
		},
		{
			Name:      "absent removes and keeps the configuration files",
			Setup:     install + " at",
			Args:      &module.Pkg{Name: []string{"at"}, Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove at"}},
			Unchanged: `dpkg-query -W -f='${db:Status-Abbrev}' at | grep -q '^ii'`,
			After:     `[ "$(dpkg-query -W -f='${db:Status-Abbrev}' at)" = "rc " ] && [ -e /etc/at.deny ]`,
		},
		{
			Name:      "recommends true overrides the apt config",
			State:     module.State{IndexFresh: true},
			Setup:     `echo 'APT::Install-Recommends "false";' > /etc/apt/apt.conf.d/99norecommends`,
			Args:      &module.Pkg{Name: []string{"fortune-mod"}, Recommends: new(true)},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install fortune-mod"}},
			WantState: module.State{IndexFresh: true},
			After:     `dpkg-query -W -f='${db:Status-Abbrev}' fortunes-min | grep -q '^ii'`,
		},
		{
			Name:      "absent lists the packages that depend on it",
			Setup:     install + " fortune-mod",
			Args:      &module.Pkg{Name: []string{"librecode3"}, Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove librecode3", "also remove fortune-mod"}},
			Unchanged: `dpkg-query -W -f='${db:Status-Abbrev}' fortune-mod | grep -q '^ii'`,
			After:     `! dpkg-query -W -f='${db:Status-Abbrev}' fortune-mod | grep -q '^ii'`,
		},
		{
			Name:    "absent on a held package fails",
			Setup:   install + " at && apt-mark hold at",
			Args:    &module.Pkg{Name: []string{"at"}, Absent: true},
			WantErr: "at is held; apt-mark unhold at changes it",
		},
		{
			Name:    "purge of a held removed package fails",
			Setup:   install + " at && apt-get remove -y -q at && apt-mark hold at",
			Args:    &module.Pkg{Name: []string{"at"}, Absent: true, Purge: true},
			WantErr: "at is held; apt-mark unhold at changes it",
		},
		{
			Name:    "install of a held package fails",
			State:   module.State{IndexFresh: true},
			Setup:   "apt-mark hold hello",
			Args:    &module.Pkg{Name: []string{"hello"}},
			WantErr: "hello is held; apt-mark unhold hello changes it",
		},
		{
			Name:  "a held package that is installed is ok",
			Setup: install + " at && apt-mark hold at",
			Args:  &module.Pkg{Name: []string{"at"}},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "an interrupted dpkg fails every check",
			Setup:   interrupted,
			Args:    &module.Pkg{Name: []string{"hello"}},
			WantErr: "dpkg was interrupted; run dpkg --configure -a",
		},
		{
			Name:    "an interrupted dpkg fails a check that is ok",
			Setup:   interrupted,
			Args:    &module.Pkg{Name: []string{"sl"}, Absent: true},
			WantErr: "dpkg was interrupted; run dpkg --configure -a",
		},
		{
			Name:  "a half-configured package that the step names plans configure",
			Setup: halfConfigure,
			Args:  &module.Pkg{Name: []string{"winch-fragile"}},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"configure winch-fragile"}},
			// The postinst passes once the marker exists.
			BeforeApply: "touch /etc/winch-fragile.ok",
			After:       "dpkg-query -W -f='${db:Status-Abbrev}' winch-fragile | grep -q '^ii'",
		},
		{
			Name:         "configure fails while the cause stays",
			Setup:        halfConfigure,
			Args:         &module.Pkg{Name: []string{"winch-fragile"}},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"configure winch-fragile"}},
			WantApplyErr: "post-installation script subprocess returned error exit status 1",
		},
		{
			Name:        "configure keeps the installed version",
			State:       module.State{IndexFresh: true},
			Setup:       localRepo + " && " + halfConfigure,
			Args:        &module.Pkg{Name: []string{"winch-fragile"}},
			Want:        module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"configure winch-fragile"}},
			WantState:   module.State{IndexFresh: true},
			BeforeApply: "touch /etc/winch-fragile.ok",
			After:       "[ \"$(dpkg-query -W -f='${db:Status-Abbrev}${Version}' winch-fragile)\" = 'ii 1' ]",
		},
		{
			Name:         "an install that would remove a conflicting package fails",
			State:        module.State{IndexFresh: true},
			Setup:        localOnly + " && " + install + " hello",
			Args:         &module.Pkg{Name: []string{"winch-conflict"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install winch-conflict"}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "Packages need to be removed but remove is disabled",
			After:        "dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii' && ! dpkg -s winch-conflict >/dev/null 2>&1",
		},
		{
			Name:    "a step that names a package of an interrupted dpkg fails",
			Setup:   interrupted,
			Args:    &module.Pkg{Name: []string{"winch-slow"}},
			WantErr: "dpkg was interrupted; run dpkg --configure -a",
		},
		{
			Name:      "a list installs a package and configures a half-configured one",
			State:     module.State{IndexFresh: true},
			Setup:     halfConfigure + " && touch /etc/winch-fragile.ok",
			Args:      &module.Pkg{Name: []string{"hello", "winch-fragile"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install hello", "configure winch-fragile"}},
			WantState: module.State{IndexFresh: true},
			After:     "dpkg-query -W -f='${db:Status-Abbrev}\\n' hello winch-fragile | grep -c '^ii' | grep -qx 2",
		},
		{
			Name:  "absent removes a half-configured package",
			Setup: halfConfigure,
			Args:  &module.Pkg{Name: []string{"winch-fragile"}, Absent: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove winch-fragile"}},
			After: "! dpkg -s winch-fragile >/dev/null 2>&1",
		},
		{
			Name:    "another half-configured package fails the check",
			Setup:   halfConfigure,
			Args:    &module.Pkg{Name: []string{"sl"}, Absent: true},
			WantErr: "winch-fragile is half configured: its configuration failed; fix the cause, then run dpkg --configure -a",
		},
		{
			Name: "a check waits for a running dpkg",
			// dpkg holds its lock while the postinst runs, and ends 3 s later.
			Setup:     startSlow + " && (sleep 3; rm /root/slow) >/dev/null 2>&1 &",
			State:     module.State{IndexFresh: true},
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install hello"}},
			WantState: module.State{IndexFresh: true},
			Unchanged: "dpkg-query -W -f='${db:Status-Abbrev}' winch-slow | grep -q '^ii'",
		},
		{
			Name:      "apply waits for another apt",
			State:     module.State{IndexFresh: true},
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install hello"}},
			WantState: module.State{IndexFresh: true},
			// The fcntl lock of apt; flock(1) takes a lock that apt does not see.
			BeforeApply: `(python3 -c 'import fcntl, time; f = open("/var/lib/dpkg/lock-frontend", "w"); fcntl.lockf(f, fcntl.LOCK_EX); open("/root/locked", "w"); time.sleep(5)' >/dev/null 2>&1 &) && ` +
				"timeout 10 sh -c 'until [ -e /root/locked ]; do sleep 0.1; done'",
			After: "! pgrep -f 'fcntl[.]lockf' && dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii'",
		},
		{
			Name:    "absent fails when apt must remove a held package with it",
			Setup:   install + " fortune-mod && apt-mark hold fortune-mod",
			Args:    &module.Pkg{Name: []string{"librecode3"}, Absent: true},
			WantErr: "held packages",
		},
		{
			Name:  "purge a list with an installed and a removed package",
			Setup: install + " at hello && apt-get remove -y -q at",
			Args:  &module.Pkg{Name: []string{"at", "hello", "sl"}, Absent: true, Purge: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"purge at, hello"}},
			After: `[ ! -e /etc/at.deny ] && ! dpkg -s hello >/dev/null 2>&1`,
		},
		{
			Name:  "absent with purge removes the configuration files",
			Setup: install + " at",
			Args:  &module.Pkg{Name: []string{"at"}, Absent: true, Purge: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"purge at"}},
			After: `[ ! -e /etc/at.deny ]`,
		},
		{
			Name:  "purge a removed package",
			Setup: install + " at && apt-get remove -y -q at",
			Args:  &module.Pkg{Name: []string{"at"}, Absent: true, Purge: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"purge at"}},
			After: `[ ! -e /etc/at.deny ]`,
		},
		{
			Name:  "absent on a removed package is ok",
			Setup: install + " at && apt-get remove -y -q at",
			Args:  &module.Pkg{Name: []string{"at"}, Absent: true},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name: "absent when not installed is ok",
			Args: &module.Pkg{Name: []string{"sl", "winch-no-such-package"}, Absent: true, Purge: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:    "a name that only another package provides fails the check",
			Args:    &module.Pkg{Name: []string{"libssl3"}},
			WantErr: "libssl3 is provided by libssl3t64; name that package",
		},
		{
			Name:    "a name with several providers fails the check",
			Setup:   "apt-get update -q >/dev/null",
			Args:    &module.Pkg{Name: []string{"mail-transport-agent"}},
			WantErr: "mail-transport-agent is provided by ",
		},
		{
			Name:    "a name with several providers names the native ones",
			Setup:   localArmhf,
			Args:    &module.Pkg{Name: []string{"winch-mta"}},
			WantErr: "winch-mta is provided by winch-mta-a, winch-mta-b; name one of them",
		},
		{
			Name:        "a package that others also provide installs",
			State:       module.State{IndexFresh: true},
			Setup:       localArmhf,
			Args:        &module.Pkg{Name: []string{"winch-fragile"}},
			Want:        module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install winch-fragile"}},
			WantState:   module.State{IndexFresh: true},
			BeforeApply: "touch /etc/winch-fragile.ok",
			After:       "[ \"$(dpkg-query -W -f='${db:Status-Abbrev}${Version}' winch-fragile)\" = 'ii 2' ]",
		},
		{
			Name:      "a name with only a foreign package installs that package",
			State:     module.State{IndexFresh: true},
			Setup:     localArmhf,
			Args:      &module.Pkg{Name: []string{"winch-mta-c"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install winch-mta-c:armhf"}},
			WantState: module.State{IndexFresh: true},
			After:     "dpkg-query -W -f='${db:Status-Abbrev}' winch-mta-c:armhf | grep -q '^ii'",
		},
		{
			Name:  "absent removes the foreign package of a name",
			Setup: localArmhf + " && " + install + " winch-mta-c",
			Args:  &module.Pkg{Name: []string{"winch-mta-c"}, Absent: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove winch-mta-c:armhf"}},
			After: "! dpkg-query -W -f='${db:Status-Abbrev}' winch-mta-c:armhf | grep -q '^ii'",
		},
		{
			Name:    "a list names the provided name after a real package",
			Args:    &module.Pkg{Name: []string{"hello", "libssl3"}},
			WantErr: "libssl3 is provided by libssl3t64; name that package",
		},
		{
			Name:    "absent of a name that only another package provides fails the check",
			Args:    &module.Pkg{Name: []string{"libssl3"}, Absent: true},
			WantErr: "libssl3 is provided by libssl3t64; name that package",
		},
		{
			Name: "the providing package converges",
			Args: &module.Pkg{Name: []string{"libssl3t64"}},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:         "an unknown package checks as a change and fails at apply",
			State:        module.State{IndexFresh: true},
			Args:         &module.Pkg{Name: []string{"winch-no-such-package"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install winch-no-such-package"}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "Unable to locate package winch-no-such-package",
		},
	})
}

// spec: Modules/pkg; Running a pipeline/Apply
func TestPkgConfiguresAfterAFix(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "fragile")
	vm.MustRun(t, quietApt+" && "+fragileDeb+" && "+halfConfigure)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  fragile: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/winch-fragile.ok
          content: "ok\n"
      - pkg:
          name: winch-fragile
`,
	})

	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ pkg winch-fragile") || !strings.Contains(r.Stdout, "configure winch-fragile") {
		t.Fatalf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || r.Stdout != "1 host: 0 to change, 1 unchanged, 0 unknown\n" {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
