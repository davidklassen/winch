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
			Name:      "a link is replaced by the file",
			Setup:     "printf '%s' '" + unitOne + "' > /opt/winch-u.service && systemctl link /opt/winch-u.service",
			Args:      &module.Unit{Name: "winch-u.service", Data: []byte(unitTwo)},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"replace the symbolic link to /opt/winch-u.service", "owner root, group root, mode 0644", "daemon-reload"}, Old: new("")},
			Unchanged: "test -L " + path,
			After:     "test -f " + path + " && test ! -L " + path + " && grep -qx Environment=WINCH=one /opt/winch-u.service && systemctl show -P FragmentPath winch-u | grep -qx " + path + " && systemctl show -P Environment winch-u | grep -qx WINCH=two",
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
			WantErr:   path + " is immutable; chattr -i removes the flag",
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
		"winch.yaml":                         "name: units\ninventory: test\n",
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

const (
	kindStatic  = "[Service]\nExecStart=/bin/sleep infinity\n"
	kindInstall = kindStatic + "[Install]\nWantedBy=multi-user.target\n"
	kindOneshot = "[Service]\nType=oneshot\nExecStart=/bin/true\n"
	kindRemain  = "[Service]\nType=oneshot\nRemainAfterExit=True\nExecStart=/bin/true\n"
)

// spec: Modules/service and unit
func TestServiceNewUnitFile(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "unitkind")
	const path = "/etc/systemd/system/winch-k.service"
	reset := `systemctl stop 'winch-k*' 2>/dev/null
systemctl disable winch-k.service winch-k@one.service 2>/dev/null
rm -rf ` + path + ` ` + path + `.d /etc/systemd/system/winch-k@.service /etc/systemd/system/*.wants/winch-k.service
systemctl daemon-reload`
	write := func(file, content string) string {
		return "printf '%s' '" + content + "' > /etc/systemd/system/" + file + " && systemctl daemon-reload"
	}
	vmtest.RunCases(t, vm, "service", reset, []vmtest.Case{
		{
			Name:        "enable a static unit that gets [Install]",
			Setup:       write("winch-k.service", kindStatic),
			Args:        &module.Service{Name: "winch-k", Enabled: new(true), NewFile: []byte(kindInstall)},
			Want:        module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"enable"}},
			Unchanged:   "systemctl is-enabled winch-k | grep -qx static",
			BeforeApply: write("winch-k.service", kindInstall),
			After:       "systemctl is-enabled winch-k | grep -qx enabled",
		},
		{
			Name:        "enable an instance of a static template that gets [Install]",
			Setup:       write("winch-k@.service", kindStatic),
			Args:        &module.Service{Name: "winch-k@one", Enabled: new(true), NewFile: []byte(kindInstall)},
			Want:        module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"enable"}},
			BeforeApply: write("winch-k@.service", kindInstall),
			After:       "systemctl is-enabled winch-k@one | grep -qx enabled",
		},
		{
			Name:    "enable a unit that loses [Install] fails",
			Setup:   write("winch-k.service", kindInstall),
			Args:    &module.Service{Name: "winch-k", Enabled: new(true), NewFile: []byte(kindStatic)},
			WantErr: `winch-k.service is static: it has no [Install] section, so enabled: true cannot enable it; remove enabled, or enable the unit that wants it`,
		},
		{
			Name:    "enable a new unit without [Install] fails",
			Args:    &module.Service{Name: "winch-k", Enabled: new(true), NewFile: []byte(kindStatic)},
			WantErr: `winch-k.service is static: it has no [Install] section, so enabled: true cannot enable it; remove enabled, or enable the unit that wants it`,
		},
		{
			Name:    "run a unit that becomes oneshot fails",
			Setup:   write("winch-k.service", kindStatic),
			Args:    &module.Service{Name: "winch-k", Running: new(true), NewFile: []byte(kindOneshot)},
			WantErr: "winch-k.service is a oneshot unit without RemainAfterExit=yes",
		},
		{
			Name:  "an enabled unit that loses [Install] stays enabled",
			Setup: write("winch-k.service", kindInstall) + " && systemctl enable winch-k",
			Args:  &module.Service{Name: "winch-k", Enabled: new(true), NewFile: []byte(kindStatic)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:        "disable an enabled unit that loses [Install]",
			Setup:       write("winch-k.service", kindInstall) + " && systemctl enable winch-k",
			Args:        &module.Service{Name: "winch-k", Enabled: new(false), NewFile: []byte(kindStatic)},
			Want:        module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"disable"}},
			BeforeApply: write("winch-k.service", kindStatic) + " && systemctl is-enabled winch-k | grep -qx enabled",
			After:       "test ! -e /etc/systemd/system/multi-user.target.wants/winch-k.service",
		},
		{
			Name:        "run a oneshot unit with RemainAfterExit=True",
			Setup:       write("winch-k.service", kindStatic),
			Args:        &module.Service{Name: "winch-k", Running: new(true), NewFile: []byte(kindRemain)},
			Want:        module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"start"}},
			BeforeApply: write("winch-k.service", kindRemain),
			After:       "systemctl is-active -q winch-k",
		},
		{
			Name:    "a unit file that systemd has not loaded",
			Setup:   write("winch-k.service", kindStatic) + " && systemctl start winch-k && printf '%s' '" + kindOneshot + "' > " + path + " && systemctl show -P NeedDaemonReload winch-k | grep -qx yes",
			Args:    &module.Service{Name: "winch-k", Running: new(true), NewFile: []byte(kindOneshot)},
			WantErr: "winch-k.service is a oneshot unit without RemainAfterExit=yes",
		},
		{
			Name:        "a new unit file fixes a bad setting",
			Setup:       write("winch-k.service", "[Service]\nExecStart=relative/path\n") + " && systemctl show -P LoadState winch-k | grep -qx bad-setting",
			Args:        &module.Service{Name: "winch-k", Running: new(true), NewFile: []byte(kindStatic)},
			Want:        module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"start"}},
			BeforeApply: write("winch-k.service", kindStatic),
			After:       "systemctl is-active -q winch-k",
		},
		{
			Name:        "a drop-in adds [Install] to the new unit file",
			Setup:       "mkdir " + path + ".d && printf '[Install]\nWantedBy=multi-user.target\n' > " + path + ".d/i.conf && " + write("winch-k.service", kindStatic),
			Args:        &module.Service{Name: "winch-k", Enabled: new(true), NewFile: []byte(kindStatic + "Environment=K=1\n")},
			Want:        module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"enable"}},
			BeforeApply: write("winch-k.service", kindStatic+"Environment=K=1\n"),
			After:       "systemctl is-enabled winch-k | grep -qx enabled",
		},
	})
}

const kindRecipe = `steps:
  - unit:
      name: winch-k.service
      source: winch-k.service
  - service:
      name: winch-k
      running: true
      enabled: true
  - unit:
      name: winch-l.service
      source: winch-l.service
  - service:
      name: winch-l
      enabled: true
  - unit:
      name: winch-m.service
      source: winch-k.service
  - service:
      name: winch-m
      enabled: true
`

// spec: Modules/service and unit
func TestUnitChangesKind(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "unitkindpipe")
	vm.MustRun(t, "printf '%s' '"+kindStatic+"' > /etc/systemd/system/winch-k.service\n"+
		"printf '%s' '"+kindStatic+"' > /opt/winch-l.service && systemctl link /opt/winch-l.service\n"+
		"printf '%s' '"+kindStatic+"[Install]\nAlias=winch-m.service\n' > /etc/systemd/system/winch-ma.service && systemctl enable winch-ma\n"+
		"systemctl daemon-reload")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":                        "name: units\ninventory: test\n",
		"inventories/test.yaml":             "hosts:\n  unitkindpipe: {}\n",
		"pipelines/site.yaml":               "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: app\n",
		"recipes/app/recipe.yaml":           kindRecipe,
		"recipes/app/files/winch-k.service": kindInstall,
		"recipes/app/files/winch-l.service": kindInstall,
	})

	r := lab.Winch(t, dir, "plan", "site")
	for _, want := range []string{"~ unit winch-k.service", "+[Install]", "~ service winch-k", "enable", "start", "~ unit winch-l.service", "replace the symbolic link to /opt/winch-l.service", "replace the symbolic link to /etc/systemd/system/winch-ma.service", "winch-m.service does not exist yet"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("first plan: no %q in stdout %q, stderr %q", want, r.Stdout, r.Stderr)
		}
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if out := vm.MustRun(t, "systemctl is-active winch-k; systemctl is-enabled winch-k; test -f /etc/systemd/system/winch-l.service && test ! -L /etc/systemd/system/winch-l.service && echo file; systemctl show -P FragmentPath winch-l; systemctl is-enabled winch-l; systemctl show -P Id winch-m; systemctl is-enabled winch-m"); out != "active\nenabled\nfile\n/etc/systemd/system/winch-l.service\nenabled\nwinch-m.service\nenabled\n" {
		t.Errorf("after apply: %q", out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
