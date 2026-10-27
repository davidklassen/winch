package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/hostname and timezone
func TestHostnameModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "hostname")
	reset := "hostnamectl set-hostname base"
	vmtest.RunCases(t, vm, "hostname", reset, []vmtest.Case{
		{
			Name:      "a new name",
			Args:      &module.Hostname{Name: "wthost"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"name base → wthost"}},
			Unchanged: `[ "$(hostname)" = base ]`,
			After:     `[ "$(hostname)" = wthost ] && [ "$(cat /etc/hostname)" = wthost ]`,
		},
		{
			Name: "the name",
			Args: &module.Hostname{Name: "base"},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "a running name that differs",
			Setup: "hostname other",
			Args:  &module.Hostname{Name: "wthost"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"static name base → wthost", "running name other → wthost"}},
			After: `[ "$(hostname)" = wthost ] && [ "$(cat /etc/hostname)" = wthost ]`,
		},
	})
}

// spec: Modules/hostname and timezone
func TestTimezoneModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "timezone")
	reset := "timedatectl set-timezone Etc/UTC && rm -f /etc/timezone"
	vmtest.RunCases(t, vm, "timezone", reset, []vmtest.Case{
		{
			Name:      "a new zone",
			Args:      &module.Timezone{Name: "Europe/Berlin"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"time zone Etc/UTC → Europe/Berlin"}},
			Unchanged: `[ "$(timedatectl show -p Timezone --value)" = Etc/UTC ]`,
			After:     `[ "$(timedatectl show -p Timezone --value)" = Europe/Berlin ] && test ! -e /etc/timezone`,
		},
		{
			Name: "the zone",
			Args: &module.Timezone{Name: "Etc/UTC"},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "UTC converges",
			Args:  &module.Timezone{Name: "UTC"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"time zone Etc/UTC → UTC"}},
			After: `[ "$(timedatectl show -p Timezone --value)" = UTC ]`,
		},
		{
			Name:         "a zone without its file: an earlier step can install it",
			Args:         &module.Timezone{Name: "Mars/Olympus"},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"time zone Etc/UTC → Mars/Olympus (/usr/share/zoneinfo/Mars/Olympus does not exist yet)"}},
			WantApplyErr: "unknown time zone Mars/Olympus: /usr/share/zoneinfo/Mars/Olympus does not exist; an old name such as US/Eastern needs the package tzdata-legacy",
			After:        `[ "$(timedatectl show -p Timezone --value)" = Etc/UTC ]`,
		},
		{
			Name:      "a stale /etc/timezone",
			Setup:     "echo America/New_York > /etc/timezone",
			Args:      &module.Timezone{Name: "Etc/UTC"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"/etc/timezone America/New_York → Etc/UTC"}},
			Unchanged: `[ "$(cat /etc/timezone)" = America/New_York ]`,
			After:     `[ "$(cat /etc/timezone)" = Etc/UTC ] && [ "$(stat -c '%U %G %a' /etc/timezone)" = "root root 644" ]`,
		},
	})
}

// spec: Modules/reboot; Modules/hostname and timezone; Remote execution/Facts
// (reboot_required)
func TestReboot(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "reboot")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  reboot: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - hostname:
          name: wtreboot
      - timezone:
          name: Europe/Berlin
      - reboot:
          if_required: true
          timeout: 300
`,
	})
	boot := func() string { return vm.MustRun(t, "cat /proc/sys/kernel/random/boot_id") }

	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "* reboot if required\n") {
		t.Fatalf("plan without a pending reboot: exit %d", r.Code)
	}

	vm.MustRun(t, "touch /run/reboot-required")
	before := boot()
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ reboot if required\n        the host requires a reboot\n") {
		t.Fatalf("plan with /run/reboot-required: exit %d", r.Code)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "reboot: base: ~ reboot if required (rebooted") {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if boot() == before {
		t.Fatal("the boot ID did not change")
	}
	for cmd, want := range map[string]string{
		"hostname":                                  "wtreboot\n",
		"cat /etc/hostname":                         "wtreboot\n",
		"timedatectl show -p Timezone --value":      "Europe/Berlin\n",
		"test -e /run/reboot-required || echo gone": "gone\n",
	} {
		if got := vm.MustRun(t, cmd); got != want {
			t.Errorf("%s after the reboot: %q, want %q", cmd, got, want)
		}
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after the reboot: exit %d", r.Code)
	}

	// A pending reboot and no other change.
	vm.MustRun(t, "touch /run/reboot-required")
	before = boot()
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ reboot if required\n") || strings.Contains(r.Stdout, "hostname") {
		t.Fatalf("plan with only a pending reboot: exit %d", r.Code)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if boot() == before {
		t.Error("the boot ID did not change")
	}
}
