package integration

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/hostname and timezone
func TestHostnameModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "hostname")
	reset := "chattr -ia /etc/hostname; echo base > /etc/hostname && hostnamectl set-hostname base"
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
		{
			Name:  "a comment above the name",
			Setup: `printf '# provider comment\nbase\n' > /etc/hostname`,
			Args:  &module.Hostname{Name: "base"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "a comment above an old name",
			Setup:     `printf '# provider comment\nbase\n' > /etc/hostname`,
			Args:      &module.Hostname{Name: "wthost"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"name base → wthost"}},
			Unchanged: `[ "$(hostname)" = base ]`,
			After:     `[ "$(hostname)" = wthost ] && [ "$(cat /etc/hostname)" = wthost ]`,
		},
		{
			Name:  "no /etc/hostname",
			Setup: "rm /etc/hostname",
			Args:  &module.Hostname{Name: "wthost"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"static name (none) → wthost", "running name base → wthost"}},
			After: `[ "$(hostname)" = wthost ] && [ "$(cat /etc/hostname)" = wthost ]`,
		},
		{
			Name:  "only a comment in /etc/hostname",
			Setup: `printf '# provider comment\n' > /etc/hostname`,
			Args:  &module.Hostname{Name: "wthost"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"static name (none) → wthost", "running name base → wthost"}},
			After: `[ "$(hostname)" = wthost ] && [ "$(cat /etc/hostname)" = wthost ]`,
		},
		{
			Name:      "an immutable /etc/hostname",
			Setup:     "chattr +i /etc/hostname",
			Args:      &module.Hostname{Name: "wthost"},
			WantErr:   "/etc/hostname is immutable; chattr -i changes it",
			Unchanged: `[ "$(hostname)" = base ]`,
		},
		{
			Name:  "an immutable /etc/hostname with the static name",
			Setup: "hostname other && chattr +i /etc/hostname",
			Args:  &module.Hostname{Name: "base"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"running name other → base"}},
			After: `[ "$(hostname)" = base ]`,
		},
		{
			Name:    "an append-only /etc/hostname",
			Setup:   "chattr +a /etc/hostname",
			Args:    &module.Hostname{Name: "wthost"},
			WantErr: "/etc/hostname is append-only; chattr -a changes it",
		},
		{
			Name:  "the name with an immutable /etc/hostname",
			Setup: "chattr +i /etc/hostname",
			Args:  &module.Hostname{Name: "base"},
			Want:  module.Result{Status: module.OK},
		},
	})
}

// spec: Modules/hostname and timezone
func TestTimezoneModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "timezone")
	reset := "chattr -ia /etc/timezone 2>/dev/null; timedatectl set-timezone Etc/UTC && rm -rf /etc/timezone /usr/share/zoneinfo/Mars"
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
			Fix:          "mkdir /usr/share/zoneinfo/Mars && cp /usr/share/zoneinfo/Etc/UTC /usr/share/zoneinfo/Mars/Olympus",
		},
		{
			Name:      "a stale /etc/timezone",
			Setup:     "echo America/New_York > /etc/timezone",
			Args:      &module.Timezone{Name: "Etc/UTC"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"/etc/timezone America/New_York → Etc/UTC"}},
			Unchanged: `[ "$(cat /etc/timezone)" = America/New_York ]`,
			After:     `[ "$(cat /etc/timezone)" = Etc/UTC ] && [ "$(stat -c '%U %G %a' /etc/timezone)" = "root root 644" ]`,
		},
		{
			Name:      "an immutable /etc/timezone",
			Setup:     "echo Etc/UTC > /etc/timezone && chattr +i /etc/timezone",
			Args:      &module.Timezone{Name: "Europe/Berlin"},
			WantErr:   "/etc/timezone is immutable; chattr -i changes it",
			Unchanged: `[ "$(timedatectl show -p Timezone --value)" = Etc/UTC ]`,
		},
		{
			Name:  "an immutable /etc/timezone with the zone",
			Setup: "echo Europe/Berlin > /etc/timezone && chattr +i /etc/timezone",
			Args:  &module.Timezone{Name: "Europe/Berlin"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"time zone Etc/UTC → Europe/Berlin"}},
			After: `[ "$(timedatectl show -p Timezone --value)" = Europe/Berlin ]`,
		},
		{
			Name:  "the zone with an immutable /etc/timezone",
			Setup: "echo Etc/UTC > /etc/timezone && chattr +i /etc/timezone",
			Args:  &module.Timezone{Name: "Etc/UTC"},
			Want:  module.Result{Status: module.OK},
		},
	})
}

// spec: Modules/reboot; Modules/hostname and timezone; Remote execution/Facts
// (reboot_required)
func TestReboot(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "reboot")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
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

	// A pending reboot and no other change. The boot holds /run/nologin for
	// 20 seconds after sshd starts, so the login fails at first. At log
	// level INFO, ssh prints the text of /run/nologin and "Connection
	// closed".
	conf := filepath.Join(lab.Dir, "hosts", vm.Name+".conf")
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.WriteHost(vm.Name, string(data)+"  LogLevel INFO\n"); err != nil {
		t.Fatal(err)
	}
	restore := sync.OnceFunc(func() {
		if _, err := lab.WriteHost(vm.Name, string(data)); err != nil {
			t.Error(err)
		}
		vm.MustRun(t, "systemctl disable wt-slow-boot")
	})
	t.Cleanup(restore)
	vm.MustRun(t, `printf '[Unit]\nBefore=systemd-user-sessions.service\n[Service]\nType=oneshot\nExecStart=/bin/sleep 20\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/wt-slow-boot.service && systemctl enable wt-slow-boot && touch /run/reboot-required`)
	before = boot()
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ reboot if required\n") || strings.Contains(r.Stdout, "hostname") {
		t.Fatalf("plan with only a pending reboot: exit %d", r.Code)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply with /run/nologin at the boot: exit %d", r.Code)
	}
	restore()
	if boot() == before {
		t.Error("the boot ID did not change")
	}
	if out := vm.MustRun(t, "journalctl -b -o cat --grep 'by PAM account configuration' || true"); !strings.Contains(out, "Access denied for user admin by PAM account configuration") {
		t.Errorf("sshd refused no login while the host booted: %q", out)
	}

	// The host boots a kernel older than the newest one in /boot.
	running := strings.TrimSpace(vm.MustRun(t, "uname -r"))
	newest := "99.0.0+deb13-" + running[strings.Index(running, "-")+1:]
	vm.MustRun(t, "touch /boot/vmlinuz-"+newest)
	defer vm.MustRun(t, "rm /boot/vmlinuz-"+newest)
	before = boot()
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	want := "the host still needs a reboot after the reboot: running kernel " + running + ", newest kernel " + newest
	if r.Code == 0 || !strings.Contains(r.Stdout+r.Stderr, want) {
		t.Errorf("apply with an old kernel: exit %d, want a failure with %q:\n%s%s", r.Code, want, r.Stdout, r.Stderr)
	}
	if boot() == before {
		t.Error("the boot ID did not change")
	}
}
