package integration

import (
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

const units = `cat > /etc/systemd/system/winch-test.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
U
cat > /etc/systemd/system/winch-test.timer <<'U'
[Timer]
OnCalendar=daily
[Install]
WantedBy=timers.target
U
cat > /etc/systemd/system/winch-static.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
U
cat > /etc/systemd/system/winch-crash.service <<'U'
[Service]
ExecStart=/bin/false
Restart=always
RestartSec=1h
U
cat > /etc/systemd/system/winch-notify.service <<'U'
[Service]
Type=notify
ExecStart=/bin/sleep infinity
TimeoutStartSec=infinity
U
cat > /usr/lib/systemd/system/winch-vendor.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
U
systemctl daemon-reload`

const waitCrash = `timeout 10 sh -c 'until systemctl show -P SubState winch-crash | grep -qx auto-restart; do sleep 0.1; done'`

// spec: Modules/service and unit
func TestServiceModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "service")
	vm.MustRun(t, units)
	reset := "if [ -d /etc/systemd/system/winch-test.service.d ]; then rm -r /etc/systemd/system/winch-test.service.d; systemctl daemon-reload; fi; systemctl unmask winch-vendor; systemctl stop winch-test.service winch-test.timer winch-static.service winch-vendor.service winch-crash.service winch-notify.service; systemctl disable winch-test.service winch-test.timer 2>/dev/null; true"
	change := func(changes ...string) module.Result {
		return module.Result{Status: module.Change, Action: module.Modify, Changes: changes}
	}
	vmtest.RunCases(t, vm, "service", reset, []vmtest.Case{
		{
			Name:      "start",
			Args:      &module.Service{Name: "winch-test", Running: new(true)},
			Want:      change("start"),
			Unchanged: `! systemctl is-active -q winch-test`,
			After:     `systemctl is-active -q winch-test`,
		},
		{
			Name: "a new drop-in reloads systemd before the start",
			Setup: `systemctl enable winch-test
mkdir /etc/systemd/system/winch-test.service.d
printf '[Service]\nLimitNOFILE=12345\n' > /etc/systemd/system/winch-test.service.d/limits.conf
systemctl show -P NeedDaemonReload winch-test | grep -qx yes`,
			Args:      &module.Service{Name: "winch-test", Running: new(true)},
			Want:      change("daemon-reload", "start"),
			Unchanged: `systemctl show -P NeedDaemonReload winch-test | grep -qx yes`,
			After:     `grep -q '^Max open files  *12345 ' /proc/$(systemctl show -P MainPID winch-test)/limits`,
		},
		{
			Name: "a new drop-in of a running unit reloads systemd",
			Setup: `systemctl enable --now winch-test
mkdir /etc/systemd/system/winch-test.service.d
printf '[Service]\nLimitNOFILE=12345\n' > /etc/systemd/system/winch-test.service.d/limits.conf
systemctl show -P NeedDaemonReload winch-test | grep -qx yes`,
			Args:  &module.Service{Name: "winch-test", Running: new(true)},
			Want:  change("daemon-reload"),
			After: `systemctl show -P NeedDaemonReload winch-test | grep -qx no`,
		},
		{
			Name:       "a unit that waits to restart after a crash is not running",
			Setup:      "systemctl start winch-crash\n" + waitCrash,
			Args:       &module.Service{Name: "winch-crash", Running: new(true)},
			Want:       change("start"),
			After:      waitCrash,
			NoConverge: true,
		},
		{
			Name:  "stop a unit that waits to restart after a crash",
			Setup: "systemctl start winch-crash\n" + waitCrash,
			Args:  &module.Service{Name: "winch-crash", Running: new(false)},
			Want:  change("stop"),
			After: `systemctl show -P ActiveState winch-crash | grep -qx inactive`,
		},
		{
			Name:  "ok when the unit starts",
			Setup: `systemctl start --no-block winch-notify && timeout 10 sh -c 'until systemctl show -P ActiveState winch-notify | grep -qx activating; do sleep 0.1; done'`,
			Args:  &module.Service{Name: "winch-notify", Running: new(true)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "ok when running",
			Setup: `systemctl start winch-test`,
			Args:  &module.Service{Name: "winch-test", Running: new(true)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "stop",
			Setup: `systemctl start winch-test`,
			Args:  &module.Service{Name: "winch-test", Running: new(false)},
			Want:  change("stop"),
			After: `! systemctl is-active -q winch-test`,
		},
		{
			Name:      "enable",
			Args:      &module.Service{Name: "winch-test", Enabled: new(true)},
			Want:      change("enable"),
			Unchanged: `! systemctl is-enabled -q winch-test`,
			After:     `systemctl is-enabled -q winch-test && ! systemctl is-active -q winch-test`,
		},
		{
			Name:  "disable",
			Setup: `systemctl enable winch-test`,
			Args:  &module.Service{Name: "winch-test", Enabled: new(false)},
			Want:  change("disable"),
			After: `! systemctl is-enabled -q winch-test`,
		},
		{
			Name: "ok when disabled",
			Args: &module.Service{Name: "winch-test", Enabled: new(false), Running: new(false)},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "enable and start with the .service suffix",
			Args:  &module.Service{Name: "winch-test.service", Enabled: new(true), Running: new(true)},
			Want:  change("enable", "start"),
			After: `systemctl is-enabled -q winch-test && systemctl is-active -q winch-test`,
		},
		{
			Name:  "stop and disable",
			Setup: `systemctl enable --now winch-test`,
			Args:  &module.Service{Name: "winch-test", Enabled: new(false), Running: new(false)},
			Want:  change("disable", "stop"),
			After: `! systemctl is-enabled -q winch-test && ! systemctl is-active -q winch-test`,
		},
		{
			Name:  "a timer",
			Args:  &module.Service{Name: "winch-test.timer", Enabled: new(true), Running: new(true)},
			Want:  change("enable", "start"),
			After: `systemctl is-enabled -q winch-test.timer && systemctl is-active -q winch-test.timer && ! systemctl is-active -q winch-test.service`,
		},
		{
			Name:  "start a static unit",
			Args:  &module.Service{Name: "winch-static", Running: new(true)},
			Want:  change("start"),
			After: `systemctl is-active -q winch-static`,
		},
		{
			Name:    "enable a static unit fails",
			Args:    &module.Service{Name: "winch-static", Enabled: new(true)},
			WantErr: `winch-static.service has the unit file state "static"; enabled: true needs an enabled or disabled unit`,
		},
		{
			Name: "a static unit is not enabled",
			Args: &module.Service{Name: "winch-static", Enabled: new(false)},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:    "a masked unit that must run fails",
			Setup:   `systemctl mask winch-masked`,
			Args:    &module.Service{Name: "winch-masked", Running: new(true)},
			WantErr: `winch-masked.service has the load state "masked"`,
		},
		{
			Name:    "a masked unit that must be enabled fails",
			Setup:   `systemctl mask winch-masked`,
			Args:    &module.Service{Name: "winch-masked", Enabled: new(true)},
			WantErr: `winch-masked.service has the load state "masked"`,
		},
		{
			Name:  "a masked unit that must not run is ok",
			Setup: `systemctl mask winch-masked && systemctl show -P LoadState winch-masked | grep -qx masked`,
			Args:  &module.Service{Name: "winch-masked", Enabled: new(false), Running: new(false)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a masked unit with only running: false is ok",
			Setup: `systemctl mask winch-masked`,
			Args:  &module.Service{Name: "winch-masked", Running: new(false)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a masked unit with only enabled: false is ok",
			Setup: `systemctl mask winch-masked`,
			Args:  &module.Service{Name: "winch-masked", Enabled: new(false)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a masked unit that still runs stops",
			Setup: `systemctl start winch-vendor && systemctl mask winch-vendor && systemctl show -P LoadState winch-vendor | grep -qx masked`,
			Args:  &module.Service{Name: "winch-vendor", Enabled: new(false), Running: new(false)},
			Want:  change("stop"),
			After: `! systemctl is-active -q winch-vendor`,
		},
		{
			Name:         "a missing unit checks as a change and fails at apply",
			Args:         &module.Service{Name: "winch-nope", Enabled: new(true), Running: new(true)},
			Want:         change("winch-nope.service does not exist yet", "enable", "start"),
			WantApplyErr: "winch-nope.service does not exist",
		},
		{
			Name:    "an alias fails and names the unit",
			Setup:   `systemctl is-enabled -q ssh && test -L /etc/systemd/system/sshd.service`,
			Args:    &module.Service{Name: "sshd", Enabled: new(true)},
			WantErr: "sshd is an alias of ssh.service; use ssh",
		},
		{
			Name:    "an alias with the .service suffix fails",
			Setup:   `systemctl is-enabled -q ssh && test -L /etc/systemd/system/sshd.service`,
			Args:    &module.Service{Name: "sshd.service", Running: new(true)},
			WantErr: "sshd.service is an alias of ssh.service; use ssh",
		},
		{
			Name:  "the unit of an alias is ok",
			Setup: `systemctl is-enabled -q ssh && systemctl is-active -q ssh`,
			Args:  &module.Service{Name: "ssh", Enabled: new(true), Running: new(true)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name: "a missing unit that must not run is ok",
			Args: &module.Service{Name: "winch-nope", Enabled: new(false), Running: new(false)},
			Want: module.Result{Status: module.OK},
		},
	})
}
