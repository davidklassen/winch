package integration

import (
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// quietApt stops the apt timers, so no other apt run holds the lock or
// refreshes the index during a test.
const quietApt = "systemctl stop apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service"

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
	reset := "rm -f /etc/apt/apt.conf.d/99norecommends /etc/apt/sources.list.d/winch-down.sources; dpkg --purge hello sl figlet tree fortune-mod fortunes-min librecode3 at >/dev/null 2>&1; true"
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
			Name:         "an unknown package checks as a change and fails at apply",
			State:        module.State{IndexFresh: true},
			Args:         &module.Pkg{Name: []string{"winch-no-such-package"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"install winch-no-such-package"}},
			WantState:    module.State{IndexFresh: true},
			WantApplyErr: "Unable to locate package winch-no-such-package",
		},
	})
}
