package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

const (
	unitOne = "[Service]\nEnvironment=WINCH=one\nExecStart=/bin/sleep infinity\n"
	unitTwo = "[Service]\nEnvironment=WINCH=two\nExecStart=/bin/sleep infinity\n"
)

// spec: Modules/service and unit; Modules/file, dir, link
func TestUnitModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "unit")
	const path = "/etc/systemd/system/winch-u.service"
	reset := `systemctl stop 'winch-u*' 2>/dev/null
chattr -i ` + path + ` 2>/dev/null
rm -rf ` + path + ` /etc/systemd/system/winch-u@.service /opt/winch-u.service /root/pid
systemctl daemon-reload`
	write := "printf '%s' '" + unitOne + "' > " + path + "\n"
	vmtest.RunCases(t, vm, "unit", reset, []vmtest.Case{
		{
			Name:      "a new unit",
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitOne)},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"owner root, group root, mode 0644", "daemon-reload"}, Old: new("")},
			Unchanged: "test ! -e " + path,
			After:     `systemctl show -P LoadState winch-u | grep -qx loaded && systemctl start winch-u && systemctl show -P Environment winch-u | grep -qx WINCH=one`,
		},
		{
			Name:      "a changed unit reloads systemd and keeps the unit running",
			Setup:     write + "systemctl daemon-reload && systemctl start winch-u && systemctl show -P MainPID winch-u > /root/pid",
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitTwo)},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"daemon-reload"}, Old: new(unitOne)},
			Unchanged: "grep -qx Environment=WINCH=one " + path,
			After: `systemctl show -P NeedDaemonReload winch-u | grep -qx no
systemctl show -P Environment winch-u | grep -qx WINCH=two
test "$(systemctl show -P MainPID winch-u)" = "$(cat /root/pid)"`,
		},
		{
			Name:      "a wrong mode",
			Setup:     write + "chmod 0600 " + path,
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitOne)},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mode 0600 → 0644", "daemon-reload"}},
			Unchanged: "test $(stat -c %a " + path + ") = 600",
			After:     "test $(stat -c %a " + path + ") = 644",
		},
		{
			Name:  "the same unit",
			Setup: write,
			Args:  &module.Unit{Name: "winch-u.service", Data: []byte(unitOne)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "a unit file that systemd has not loaded",
			Setup:     "printf '%s' '" + unitTwo + "' > " + path + " && systemctl daemon-reload && systemctl start winch-u\n" + write + "systemctl show -P NeedDaemonReload winch-u | grep -qx yes",
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitOne)},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"daemon-reload"}},
			Unchanged: "systemctl show -P NeedDaemonReload winch-u | grep -qx yes",
			After:     "systemctl show -P NeedDaemonReload winch-u | grep -qx no && systemctl show -P Environment winch-u | grep -qx WINCH=one",
		},
		{
			Name:  "the same template",
			Setup: "printf '%s' '" + unitOne + "' > /etc/systemd/system/winch-u@.service && systemctl daemon-reload",
			Args:  &module.Unit{Name: "winch-u@.service", Data: []byte(unitOne)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a template",
			Args:  &module.Unit{Name: "winch-u@.service", Data: []byte(unitOne)},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"owner root, group root, mode 0644", "daemon-reload"}, Old: new("")},
			After: "systemctl start winch-u@one && systemctl is-active -q winch-u@one",
		},
		{
			Name:      "a masked unit fails",
			Setup:     "systemctl mask winch-u",
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitOne)},
			WantErr:   "winch-u.service is masked; systemctl unmask winch-u.service removes the mask",
			Unchanged: "test -L " + path,
		},
		{
			Name:      "a link fails",
			Setup:     "printf '%s' '" + unitOne + "' > /opt/winch-u.service && ln -s /opt/winch-u.service " + path,
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitTwo)},
			WantErr:   path + " is a symbolic link to /opt/winch-u.service",
			Unchanged: "test -L " + path,
		},
		{
			Name:      "a directory fails",
			Setup:     "mkdir " + path,
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitOne)},
			WantErr:   path + " is a directory, not a file",
			Unchanged: "test -d " + path,
		},
		{
			Name:      "an immutable unit file fails",
			Setup:     write + "chattr +i " + path,
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitTwo)},
			WantErr:   path + " is immutable; chattr -i changes it",
			Unchanged: "grep -qx Environment=WINCH=one " + path,
		},
	})
}

const unitRecipe = `steps:
  - unit:
      name: winch-hb.service
      source: winch-hb.service
    notify: restart
  - service:
      name: winch-hb
      running: true
      enabled: true
handlers:
  restart:
    - service:
        name: winch-hb
        restarted: true
`

const hbUnit = "[Service]\nEnvironment=HB=%s\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n"

// spec: Modules/service and unit
func TestUnitPipeline(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "unitpipe")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":                         "name: units\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml":              "hosts:\n  unitpipe: {}\n",
		"pipelines/site.yaml":                "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: app\n",
		"recipes/app/recipe.yaml":            unitRecipe,
		"recipes/app/files/winch-hb.service": strings.Replace(hbUnit, "%s", "one", 1),
	})

	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "unitpipe: app: + unit winch-hb.service") {
		t.Fatalf("first apply: exit %d, stdout %q", r.Code, r.Stdout)
	}
	if out := vm.MustRun(t, "systemctl is-active winch-hb; systemctl is-enabled winch-hb; systemctl show -P Environment winch-hb"); out != "active\nenabled\nHB=one\n" {
		t.Errorf("after the first apply: %q", out)
	}
	pid := vm.MustRun(t, "systemctl show -P MainPID winch-hb")

	if err := os.WriteFile(filepath.Join(dir, "recipes/app/files/winch-hb.service"), []byte(strings.Replace(hbUnit, "%s", "two", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	r = lab.Winch(t, dir, "plan", "site")
	for _, want := range []string{"~ unit winch-hb.service", "-Environment=HB=one", "+Environment=HB=two", "daemon-reload", "! handler app.restart"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("plan after a change: no %q in %q", want, r.Stdout)
		}
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("second apply: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "systemctl show -P NeedDaemonReload winch-hb; systemctl show -P Environment winch-hb"); out != "no\nHB=two\n" {
		t.Errorf("after the change: %q", out)
	}
	if got := vm.MustRun(t, "systemctl show -P MainPID winch-hb"); got == pid {
		t.Errorf("the handler did not restart winch-hb: main PID %s", strings.TrimSpace(got))
	}

	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("third plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
