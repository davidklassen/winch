package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

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
	vm.MustRun(t, `echo 'APT::Update::Pre-Invoke {"echo x >> /root/updates";};' > /etc/apt/apt.conf.d/99count && touch /root/updates`)
	const (
		install = "DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends"
		// count keeps the number of refreshes; same checks it after apply.
		count = "wc -l < /root/updates > /root/before"
		same  = `[ "$(wc -l < /root/updates)" = "$(cat /root/before)" ]`
	)
	refresh := "refresh the package index"
	later := "other packages: known after the refresh"
	librecode := osRelease().librecode
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
	// fragileV1 installs version 1 of winch-fragile while the index has version 2.
	const fragileV1 = "touch /etc/winch-fragile.ok && dpkg -i /root/winch-fragile.deb >/dev/null && " + localOnly + " && apt-cache policy winch-fragile | grep -q 'Candidate: 2'"
	reset := "[ ! -e /root/virt ] || { rm -r /root/virt /etc/apt/sources.list.d/winch-virt.sources && apt-get update -q >/dev/null; }; pkill -f 'fcntl[.]lockf'; rm -f /root/slow /root/locked /etc/winch-fragile.ok; while pgrep -x dpkg >/dev/null || pgrep -f winch-slo[w].postinst >/dev/null; do sleep 0.1; done; rm -f /etc/apt/apt.conf.d/99norecommends /etc/apt/sources.list.d/winch-down.sources /var/lib/apt/lists/10.0.2.100_test_*; apt-mark showhold | xargs -r apt-mark unhold >/dev/null; dpkg --purge winch-mta-c:armhf >/dev/null 2>&1; dpkg --remove-architecture armhf 2>/dev/null; " +
		"dpkg --configure -a >/dev/null 2>&1; dpkg --purge winch-virt winch-slow winch-uses-fragile winch-fragile winch-conflict hello sl figlet tree fortune-mod fortunes-min " + librecode + " at >/dev/null 2>&1; true"
	// The cases with a fresh index need the index of the system's sources,
	// also when RUN selects one of them alone.
	vm.MustRun(t, localRepo)
	vmtest.RunCases(t, vm, "pkg", reset, []vmtest.Case{
		{
			Name:      "the first install of a run refreshes the index",
			Setup:     "rm -f /var/lib/apt/lists/*_* && " + count,
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello", later}},
			WantState: module.State{IndexFresh: true},
			Unchanged: same + " && ! dpkg -s hello >/dev/null 2>&1",
			After:     `[ "$(wc -l < /root/updates)" = $(( $(cat /root/before) + 1 )) ] && dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii'`,
		},
		{
			Name:      "the refresh creates a missing index directory",
			Setup:     "rm -rf /var/lib/apt/lists",
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello", later}},
			WantState: module.State{IndexFresh: true},
			Unchanged: "[ ! -e /var/lib/apt/lists ]",
			After:     "[ -d /var/lib/apt/lists/partial ] && dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii'",
		},
		{
			Name:      "an empty index plans the other packages after the refresh",
			Setup:     "rm -rf /var/lib/apt/lists/*",
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello", later}},
			WantState: module.State{IndexFresh: true},
			After:     "dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii'",
		},
		{
			Name:        "an install lists the other packages that apt installs",
			State:       module.State{IndexFresh: true},
			Setup:       localOnly,
			Args:        &module.Pkg{Name: []string{"winch-uses-fragile"}},
			Want:        module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install winch-uses-fragile", "also install winch-fragile"}},
			WantState:   module.State{IndexFresh: true},
			BeforeApply: "touch /etc/winch-fragile.ok",
			After:       "dpkg-query -W -f='${db:Status-Abbrev}\\n' winch-uses-fragile winch-fragile | grep -c '^ii' | grep -qx 2",
		},
		{
			Name:      "an install lists the other packages that apt upgrades",
			State:     module.State{IndexFresh: true},
			Setup:     fragileV1,
			Args:      &module.Pkg{Name: []string{"winch-uses-fragile"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install winch-uses-fragile", "also upgrade winch-fragile"}},
			WantState: module.State{IndexFresh: true},
			After:     "[ \"$(dpkg-query -W -f='${db:Status-Abbrev}${Version}' winch-fragile)\" = 'ii 2' ]",
		},
		{
			Name:    "an install that must upgrade a held package fails the check",
			State:   module.State{IndexFresh: true},
			Setup:   fragileV1 + " && apt-mark hold winch-fragile",
			Args:    &module.Pkg{Name: []string{"winch-uses-fragile"}},
			WantErr: "winch-fragile is held; apt-mark unhold winch-fragile removes the hold",
		},
		{
			Name: "an install that must upgrade a held package fails after the refresh",
			// The reset removed the index of the test source.
			Setup:        "touch /etc/winch-fragile.ok && dpkg -i /root/winch-fragile.deb >/dev/null && apt-mark hold winch-fragile",
			Args:         &module.Pkg{Name: []string{"winch-uses-fragile"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install winch-uses-fragile", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "winch-fragile is held; apt-mark unhold winch-fragile removes the hold",
			After:        "! dpkg -s winch-uses-fragile >/dev/null 2>&1",
			Fix:          "apt-mark unhold winch-fragile >/dev/null",
		},
		{
			Name: "an install checks the other packages again after the refresh",
			// The old index of the test source has winch-uses-fragile without
			// its dependency. The old date makes the refresh fetch it again.
			Setup: "touch /etc/winch-fragile.ok && dpkg -i /root/winch-fragile.deb >/dev/null && apt-mark hold winch-fragile >/dev/null && " + localOnly +
				" && sed -i '/^Depends: winch-fragile/d' /var/lib/apt/lists/10.0.2.100_test_*Packages && touch -d 2000-01-01 /var/lib/apt/lists/10.0.2.100_test_*Packages" +
				" && ! apt-cache show winch-uses-fragile | grep -q ^Depends",
			Args:         &module.Pkg{Name: []string{"winch-uses-fragile"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install winch-uses-fragile"}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "winch-fragile is held; apt-mark unhold winch-fragile removes the hold",
			After:        "! dpkg -s winch-uses-fragile >/dev/null 2>&1",
			Fix:          "apt-mark unhold winch-fragile >/dev/null",
		},
		{
			Name:      "a removed package with an empty index plans the other packages after the refresh",
			Setup:     install + " at && apt-get remove -y -q at >/dev/null && rm -rf /var/lib/apt/lists/*",
			Args:      &module.Pkg{Name: []string{"at"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install at", later}},
			WantState: module.State{IndexFresh: true},
			After:     "dpkg-query -W -f='${db:Status-Abbrev}' at | grep -q '^ii'",
		},
		{
			Name:        "a list with a name that the index does not know plans the other packages after the refresh",
			Setup:       localRepo + " && rm /var/lib/apt/lists/10.0.2.100_test_* && apt-cache show hello >/dev/null",
			Args:        &module.Pkg{Name: []string{"hello", "winch-uses-fragile"}},
			Want:        module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello, winch-uses-fragile", later}},
			WantState:   module.State{IndexFresh: true},
			BeforeApply: "touch /etc/winch-fragile.ok",
			After:       "dpkg-query -W -f='${db:Status-Abbrev}\\n' hello winch-uses-fragile winch-fragile | grep -c '^ii' | grep -qx 3",
		},
		{
			Name: "a refresh fails when apt cannot fetch a source",
			// Nothing listens on port 9.
			Setup:        "printf 'Types: deb\\nURIs: http://127.0.0.1:9/winch-down\\nSuites: trixie\\nComponents: main\\nTrusted: yes\\n' > /etc/apt/sources.list.d/winch-down.sources",
			Args:         &module.Pkg{Name: []string{"hello"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello"}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "Failed to fetch http://127.0.0.1:9/winch-down",
			Fix:          "rm /etc/apt/sources.list.d/winch-down.sources",
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
			Setup:     install + " fortune-mod && apt-mark showauto " + librecode + " | grep -q " + librecode,
			Args:      &module.Pkg{Name: []string{librecode}},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mark " + librecode + " as manually installed"}},
			Unchanged: "apt-mark showauto " + librecode + " | grep -q " + librecode,
			// A dry run of autoremove keeps the other automatic packages of the VM.
			After: "DEBIAN_FRONTEND=noninteractive apt-get purge -y -q fortune-mod && ! apt-get -s autoremove | grep -q '^Remv " + librecode + " '",
		},
		{
			Name:      "a list installs a missing package and marks a dependency",
			State:     module.State{IndexFresh: true},
			Setup:     install + " fortune-mod",
			Args:      &module.Pkg{Name: []string{"hello", librecode}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install hello", "mark " + librecode + " as manually installed"}},
			WantState: module.State{IndexFresh: true},
			Unchanged: "apt-mark showauto " + librecode + " | grep -q " + librecode,
			After:     "apt-mark showmanual hello " + librecode + " | grep -c . | grep -qx 2",
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
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install fortune-mod (without recommended packages)", "also install " + librecode}},
			WantState: module.State{IndexFresh: true},
			After:     `dpkg -s fortune-mod >/dev/null && ! dpkg -s fortunes-min >/dev/null 2>&1`,
		},
		{
			Name:      "recommended packages by default",
			State:     module.State{IndexFresh: true},
			Args:      &module.Pkg{Name: []string{"fortune-mod"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install fortune-mod", "also install " + librecode + ", fortunes-min"}},
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
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install fortune-mod", "also install " + librecode + ", fortunes-min"}},
			WantState: module.State{IndexFresh: true},
			After:     `dpkg-query -W -f='${db:Status-Abbrev}' fortunes-min | grep -q '^ii'`,
		},
		{
			Name:      "the default overrides the apt config",
			State:     module.State{IndexFresh: true},
			Setup:     `echo 'APT::Install-Recommends "false";' > /etc/apt/apt.conf.d/99norecommends`,
			Args:      &module.Pkg{Name: []string{"fortune-mod"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install fortune-mod", "also install " + librecode + ", fortunes-min"}},
			WantState: module.State{IndexFresh: true},
			After:     `dpkg-query -W -f='${db:Status-Abbrev}' fortunes-min | grep -q '^ii'`,
		},
		{
			Name:      "absent lists the packages that depend on it",
			Setup:     install + " fortune-mod",
			Args:      &module.Pkg{Name: []string{librecode}, Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove " + librecode, "also remove fortune-mod"}},
			Unchanged: `dpkg-query -W -f='${db:Status-Abbrev}' fortune-mod | grep -q '^ii'`,
			After:     `! dpkg-query -W -f='${db:Status-Abbrev}' fortune-mod | grep -q '^ii'`,
		},
		{
			Name:    "absent on a held package fails",
			Setup:   install + " at && apt-mark hold at",
			Args:    &module.Pkg{Name: []string{"at"}, Absent: true},
			WantErr: "at is held; apt-mark unhold at removes the hold",
		},
		{
			Name:    "purge of a held removed package fails",
			Setup:   install + " at && apt-get remove -y -q at && apt-mark hold at",
			Args:    &module.Pkg{Name: []string{"at"}, Absent: true, Purge: true},
			WantErr: "at is held; apt-mark unhold at removes the hold",
		},
		{
			Name:    "install of a held package fails",
			State:   module.State{IndexFresh: true},
			Setup:   "apt-mark hold hello",
			Args:    &module.Pkg{Name: []string{"hello"}},
			WantErr: "hello is held; apt-mark unhold hello removes the hold",
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
			WantApplyErr: osRelease().postinstFailed,
			Fix:          "touch /etc/winch-fragile.ok",
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
			Name:  "an installed package is ok while the index has a newer version",
			Setup: fragileV1,
			Args:  &module.Pkg{Name: []string{"winch-fragile"}},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "a list with a missing package keeps the installed version of the others",
			Setup:     fragileV1,
			Args:      &module.Pkg{Name: []string{"winch-fragile", "hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello"}},
			WantState: module.State{IndexFresh: true},
			After:     "[ \"$(dpkg-query -W -f='${db:Status-Abbrev}${Version}' winch-fragile)\" = 'ii 1' ] && dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii'",
		},
		{
			Name:    "an install that would remove a conflicting package fails the check",
			State:   module.State{IndexFresh: true},
			Setup:   localOnly + " && " + install + " hello",
			Args:    &module.Pkg{Name: []string{"winch-conflict"}},
			WantErr: "apt must remove hello; add a pkg step with name: hello and absent: true before this step",
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
			Args:    &module.Pkg{Name: []string{librecode}, Absent: true},
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
			Name: "an install restarts no service",
			// The file of the running program of winch-old is gone, so
			// needrestart, which Ubuntu installs, would restart winch-old
			// after an apt run.
			State: module.State{IndexFresh: true},
			Setup: "if grep -qx ID=ubuntu /etc/os-release; then command -v needrestart >/dev/null; fi && " + localRepo + ` && cp /usr/bin/sleep /usr/local/bin/winch-old && printf '[Service]\nExecStart=/usr/local/bin/winch-old infinity\n' > /etc/systemd/system/winch-old.service && systemctl daemon-reload && systemctl restart winch-old && ` +
				`systemctl show -P InvocationID winch-old > /root/inv && rm /usr/local/bin/winch-old && cp /usr/bin/sleep /usr/local/bin/winch-old`,
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install hello"}},
			WantState: module.State{IndexFresh: true},
			After:     `[ "$(systemctl show -P InvocationID winch-old)" = "$(cat /root/inv)" ] && systemctl stop winch-old`,
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
			Name:         "a name that only another package provides fails after the refresh",
			Args:         &module.Pkg{Name: []string{"libssl3"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install libssl3", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "libssl3 is provided by libssl3t64; name that package",
			FixArgs:      &module.Pkg{Name: []string{"hello"}},
		},
		{
			Name:         "a name that only another package provides fails after an earlier refresh",
			State:        module.State{IndexFresh: true},
			Args:         &module.Pkg{Name: []string{"libssl3"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install libssl3", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "libssl3 is provided by libssl3t64; name that package",
			FixArgs:      &module.Pkg{Name: []string{"hello"}},
		},
		{
			Name:         "a name with several providers fails after the refresh",
			Setup:        "apt-get update -q >/dev/null",
			Args:         &module.Pkg{Name: []string{"mail-transport-agent"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install mail-transport-agent", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "mail-transport-agent is provided by ",
			FixArgs:      &module.Pkg{Name: []string{"hello"}},
		},
		{
			Name:         "a name with several providers names the native ones",
			Setup:        localArmhf,
			Args:         &module.Pkg{Name: []string{"winch-mta"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install winch-mta", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "winch-mta is provided by winch-mta-a, winch-mta-b; name one of them",
			FixArgs:      &module.Pkg{Name: []string{"hello"}},
		},
		{
			Name: "a name that the old index knows only as provided installs after the refresh",
			// The index knows only winch-virt, which provides hello, as on a
			// new host whose index misses the section of hello.
			Setup: "rm -f /var/lib/apt/lists/*_Packages* && mkdir -p /root/virt && " +
				`printf 'Package: winch-virt\nVersion: 1\nArchitecture: all\nProvides: hello\nMaintainer: winch\nFilename: winch-virt.deb\nSize: 1\nDescription: test\n' > /root/virt/Packages && ` +
				`printf 'Types: deb\nURIs: file:/root/virt\nSuites: ./\nTrusted: yes\n' > /etc/apt/sources.list.d/winch-virt.sources && ` +
				"apt-get update -q -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winch-virt.sources -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 >/dev/null && " +
				"apt-cache showpkg hello | grep -q '^winch-virt '",
			Args:      &module.Pkg{Name: []string{"hello"}},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello", later}},
			WantState: module.State{IndexFresh: true},
			After:     "dpkg-query -W -f='${db:Status-Abbrev}' hello | grep -q '^ii'",
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
			Name:         "a list names the provided name after a real package",
			Args:         &module.Pkg{Name: []string{"hello", "libssl3"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello, libssl3", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "libssl3 is provided by libssl3t64; name that package",
			After:        "! dpkg -s hello >/dev/null 2>&1",
			FixArgs:      &module.Pkg{Name: []string{"hello"}},
		},
		{
			Name: "a name that the index of the check does not know fails when only one package provides it",
			// The source of winch-virt, which provides winch-virtual, has no
			// index before the refresh, as on a new host.
			Setup: "mkdir -p /root/virt/pkg/DEBIAN && " +
				`printf 'Package: winch-virt\nVersion: 1\nArchitecture: all\nProvides: winch-virtual\nMaintainer: winch\nDescription: test\n' > /root/virt/pkg/DEBIAN/control && ` +
				"dpkg-deb -b /root/virt/pkg /root/virt/winch-virt.deb >/dev/null && cd /root/virt && " +
				`{ cat pkg/DEBIAN/control && printf 'Filename: winch-virt.deb\nSize: %s\nSHA256: %s\n' "$(stat -c %s winch-virt.deb)" "$(sha256sum winch-virt.deb | cut -d' ' -f1)"; } > Packages && ` +
				`printf 'Types: deb\nURIs: file:/root/virt\nSuites: ./\nTrusted: yes\n' > /etc/apt/sources.list.d/winch-virt.sources && ` +
				"! apt-cache showpkg winch-virtual 2>/dev/null | grep -q '^winch-virt '",
			Args:         &module.Pkg{Name: []string{"hello", "winch-virtual"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{refresh, "install hello, winch-virtual", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "winch-virtual is provided by winch-virt; name that package",
			After:        "! dpkg -s hello >/dev/null 2>&1 && ! dpkg -s winch-virt >/dev/null 2>&1",
			FixArgs:      &module.Pkg{Name: []string{"hello"}},
		},
		{
			Name:    "absent of a name that only another package provides fails the check",
			Args:    &module.Pkg{Name: []string{"libssl3"}, Absent: true},
			WantErr: "libssl3 is provided by libssl3t64; name that package",
		},
		{
			Name:  "absent of a name that no installed package provides is ok",
			Setup: localArmhf,
			Args:  &module.Pkg{Name: []string{"winch-mta"}, Absent: true},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name: "the providing package converges",
			// Ubuntu's image has libssl3t64 as an automatic install.
			Setup: "apt-mark manual libssl3t64 >/dev/null",
			Args:  &module.Pkg{Name: []string{"libssl3t64"}},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:         "an unknown package checks as a change and fails at apply",
			State:        module.State{IndexFresh: true},
			Args:         &module.Pkg{Name: []string{"winch-no-such-package"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install winch-no-such-package", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "Unable to locate package winch-no-such-package",
			FixArgs:      &module.Pkg{Name: []string{"hello"}},
		},
		{
			Name:         "a dotted name is no regular expression",
			State:        module.State{IndexFresh: true},
			Args:         &module.Pkg{Name: []string{"lib.c6"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install lib.c6", later}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "Unable to locate package lib.c6",
			FixArgs:      &module.Pkg{Name: []string{"hello"}},
		},
	})
}

// spec: Modules/pkg; Running a pipeline/Apply
func TestPkgConfiguresAfterAFix(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "fragile")
	vm.MustRun(t, fragileDeb+" && "+halfConfigure)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
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
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}

// spec: Running a pipeline/Plan; Modules/pkg; Modules/debconf
func TestPkgPlanRules(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pkgplan")
	const (
		deps   = "      - pkg:\n          name: winch-up-deps\n"
		gone   = "      - pkg:\n          name: winch-up-new\n          absent: true\n"
		reconf = "      - pkg:\n          name: winch-reconf\n"
		answer = "      - debconf:\n          package: winch-reconf\n          question: winch-reconf/enabled\n          type: boolean\n          value: \"true\"\n"
		undo   = "; the two steps undo each other on every run"
	)
	pipeline := func(steps string) string {
		return "stages:\n  - name: s\n    hosts: all\n    steps:\n" + steps
	}
	// winch-up-deps depends on winch-up-new.
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":             "name: pkgplan\ninventory: test\n",
		"inventories/test.yaml":  "hosts:\n  pkgplan: {}\n",
		"pipelines/install.yaml": pipeline(deps + gone),
		"pipelines/remove.yaml":  pipeline(gone + deps),
		"pipelines/late.yaml":    pipeline(reconf + answer),
		"pipelines/early.yaml":   pipeline(answer + reconf),
		// winch-conflict conflicts with hello.
		"pipelines/swap.yaml": pipeline("      - pkg:\n          name: hello\n          absent: true\n      - pkg:\n          name: winch-conflict\n" + gone),
		// winch-uses-fragile depends on winch-fragile.
		"pipelines/unknown.yaml": pipeline("      - pkg:\n          name: [winch-uses-fragile, winch-nowhere]\n" + gone),
		// winch-up-top depends on winch-up-deps.
		"pipelines/top.yaml": pipeline(gone + "      - pkg:\n          name: winch-up-top\n"),
		// winch-local depends on hello, and the package index does not know it.
		"pipelines/cleanup.yaml": pipeline("      - pkg:\n          name: hello\n          absent: true\n      - pkg:\n          name: winch-local\n          absent: true\n"),
	})
	fails := func(name, pipeline, want string) {
		t.Helper()
		r := lab.Winch(t, dir, "plan", pipeline)
		if r.Code == 0 || !strings.Contains(r.Stdout+r.Stderr, want) {
			t.Errorf("%s: exit %d, want the error %q:\n%s%s", name, r.Code, want, r.Stdout, r.Stderr)
		}
	}

	// A fresh VM has no index, but the plan knows the packages that a step
	// names.
	fails("a debconf answer after the install", "late", "s: debconf winch-reconf/enabled: s: pkg winch-reconf installs winch-reconf before this step sets the answer; move this step before it")
	if r := lab.Winch(t, dir, "apply", "early", "--yes"); r.Code != 0 {
		t.Fatalf("a debconf answer before the install: exit %d, stderr %q", r.Code, r.Stderr)
	}
	if out := vm.MustRun(t, "cat /etc/winch-reconf"); out != "true\n" {
		t.Errorf("after the answer before the install: %q", out)
	}
	if r := lab.Winch(t, dir, "plan", "late"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("a debconf answer after an installed package: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	vm.MustRun(t, "apt-get update -q >/dev/null")
	fails("an install that pulls a removed package", "install", "s: pkg winch-up-new: s: pkg winch-up-deps also installs winch-up-new, which this step removes"+undo)
	fails("a removed package that an install pulls", "remove", "s: pkg winch-up-deps: this step also installs winch-up-new, which s: pkg winch-up-new removes"+undo)
	vm.MustRun(t, "DEBIAN_FRONTEND=noninteractive apt-get install -y -q winch-up-new >/dev/null")
	fails("a removal that takes a package of an earlier install", "install", "s: pkg winch-up-new: this step also removes winch-up-deps, which s: pkg winch-up-deps installs"+undo)
	vm.MustRun(t, "DEBIAN_FRONTEND=noninteractive apt-get install -y -q hello >/dev/null")
	plans := func(name, pipeline string) {
		t.Helper()
		if r := lab.Winch(t, dir, "plan", pipeline); r.Code != 0 {
			t.Errorf("%s: exit %d:\n%s%s", name, r.Code, r.Stdout, r.Stderr)
		}
	}
	plans("a removal after an install that replaces a removed package", "swap")
	plans("a removal after an install with unknown dependencies", "unknown")
	vm.MustRun(t, "mkdir -p /tmp/winch-local/DEBIAN && printf 'Package: winch-local\\nVersion: 1\\nArchitecture: all\\nMaintainer: winch\\nDepends: hello\\nDescription: test\\n' >/tmp/winch-local/DEBIAN/control && dpkg-deb -b /tmp/winch-local /tmp/winch-local.deb >/dev/null && dpkg -i /tmp/winch-local.deb >/dev/null")
	plans("a removal of a package that an earlier removal takes and the index does not know", "cleanup")
	vm.MustRun(t, "DEBIAN_FRONTEND=noninteractive apt-get install -y -q winch-up-deps >/dev/null")
	fails("a removal that takes an installed package", "install", "s: pkg winch-up-new: this step also removes winch-up-deps, which s: pkg winch-up-deps installs"+undo)
	fails("an installed package that a removal takes", "remove", "s: pkg winch-up-deps: s: pkg winch-up-new also removes winch-up-deps, which this step installs"+undo)
	fails("an install that pulls back a package that an earlier removal takes", "top", "s: pkg winch-up-top: this step also installs winch-up-new, which s: pkg winch-up-new removes"+undo)
}
