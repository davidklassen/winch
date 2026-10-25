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
cat > /etc/systemd/system/winch-tpl@.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
U
cat > /etc/systemd/system/winch-oneshot.service <<'U'
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo x >> /tmp/oneshot'
U
cat > /etc/systemd/system/winch-remain.service <<'U'
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
U
cat > /etc/systemd/system/winch-boom.service <<'U'
[Service]
ExecStartPre=/bin/sh -c 'if [ -e /tmp/boom ]; then cat /tmp/boom; exit 1; fi'
ExecStart=/bin/sleep infinity
ExecReload=/bin/sh -c 'echo boom on reload; exit 1'
U
mkdir -p /opt/winch
cat > /opt/winch/winch-linked.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
U
cat > /usr/lib/systemd/system/winch-vendor.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload`

const waitCrash = `timeout 10 sh -c 'until systemctl show -P SubState winch-crash | grep -qx auto-restart; do sleep 0.1; done'`

// oddUnit has the instance "a b;$(touch /tmp/pwn)", as systemd-escape writes it.
const oddUnit = `winch-tpl@a\x20b\x3b\x24\x28touch\x20-tmp-pwn\x29`

// spec: Modules/service and unit
func TestServiceModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "service")
	vm.MustRun(t, units)
	reset := "systemctl unmask --runtime winch-vendor; if [ -d /etc/systemd/system/winch-test.service.d ]; then rm -r /etc/systemd/system/winch-test.service.d; systemctl daemon-reload; fi; systemctl unmask winch-vendor winch-tpl@one; systemctl stop 'winch-tpl@*' winch-test.service winch-test.timer winch-static.service winch-vendor.service winch-crash.service winch-notify.service winch-boom.service winch-remain.service; rm -f /tmp/boom; if [ -L /run/systemd/system/multi-user.target.wants/winch-test.service ]; then systemctl disable --runtime winch-test.service; fi; systemctl disable winch-test.service winch-test.timer winch-vendor.service winch-tpl@one.service winch-tpl@two.service 2>/dev/null; if [ -L /etc/systemd/system/winch-linked.service ]; then systemctl disable winch-linked.service; rm -f /etc/systemd/system/winch-linked.service; systemctl daemon-reload; fi; true"
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
			Name:      "an instance name with escaped spaces and shell characters",
			Args:      &module.Service{Name: oddUnit, Running: new(true)},
			Want:      change("start"),
			Unchanged: `! systemctl is-active -q ` + vmtest.Quote(oddUnit),
			After:     `systemctl is-active -q ` + vmtest.Quote(oddUnit),
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
			Name:      "enable a template instance",
			Args:      &module.Service{Name: "winch-tpl@one", Enabled: new(true)},
			Want:      change("enable"),
			Unchanged: `! systemctl is-enabled -q winch-tpl@one`,
			After:     `test -L /etc/systemd/system/multi-user.target.wants/winch-tpl@one.service`,
		},
		{
			Name:  "disable a template instance",
			Setup: `systemctl enable winch-tpl@one`,
			Args:  &module.Service{Name: "winch-tpl@one", Enabled: new(false)},
			Want:  change("disable"),
			After: `! systemctl is-enabled -q winch-tpl@one && test -f /etc/systemd/system/winch-tpl@.service`,
		},
		{
			Name:  "enable a second instance while the first is enabled",
			Setup: `systemctl enable winch-tpl@one`,
			Args:  &module.Service{Name: "winch-tpl@two", Enabled: new(true)},
			Want:  change("enable"),
			After: `systemctl is-enabled -q winch-tpl@one && systemctl is-enabled -q winch-tpl@two`,
		},
		{
			Name:  "a second instance is not enabled by the first",
			Setup: `systemctl enable winch-tpl@one`,
			Args:  &module.Service{Name: "winch-tpl@two", Enabled: new(false)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "disable a second instance keeps the first",
			Setup: `systemctl enable winch-tpl@one winch-tpl@two`,
			Args:  &module.Service{Name: "winch-tpl@two", Enabled: new(false)},
			Want:  change("disable"),
			After: `systemctl is-enabled -q winch-tpl@one && ! systemctl is-enabled -q winch-tpl@two`,
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
			Name:  "a mask of an enabled unit disables it",
			Setup: `systemctl enable winch-vendor && systemctl mask winch-vendor && systemctl is-enabled winch-vendor | grep -qx masked`,
			Args:  &module.Service{Name: "winch-vendor", Enabled: new(false)},
			Want:  change("disable"),
			After: `systemctl is-enabled winch-vendor | grep -qx masked && systemctl unmask winch-vendor && systemctl is-enabled winch-vendor | grep -qx disabled && systemctl mask winch-vendor`,
		},
		{
			Name:  "a mask of an enabled template instance disables it",
			Setup: `systemctl enable winch-tpl@one && systemctl mask winch-tpl@one && systemctl is-enabled winch-tpl@one | grep -qx masked`,
			Args:  &module.Service{Name: "winch-tpl@one", Enabled: new(false)},
			Want:  change("disable"),
			After: `systemctl is-enabled winch-tpl@one | grep -qx masked && systemctl unmask winch-tpl@one && systemctl is-enabled winch-tpl@one | grep -qx disabled && systemctl mask winch-tpl@one`,
		},
		{
			Name:  "a relative mask link stays",
			Setup: `systemctl enable winch-vendor && ln -s ../../../dev/null /etc/systemd/system/winch-vendor.service && systemctl daemon-reload && systemctl is-enabled winch-vendor | grep -qx masked`,
			Args:  &module.Service{Name: "winch-vendor", Enabled: new(false)},
			Want:  change("disable"),
			After: `test -L /etc/systemd/system/winch-vendor.service && test ! -e /etc/systemd/system/multi-user.target.wants/winch-vendor.service`,
		},
		{
			Name:  "a runtime mask of an enabled unit disables it",
			Setup: `systemctl enable winch-vendor && systemctl mask --runtime winch-vendor && systemctl is-enabled winch-vendor | grep -qx masked-runtime`,
			Args:  &module.Service{Name: "winch-vendor", Enabled: new(false)},
			Want:  change("disable"),
			After: `systemctl is-enabled winch-vendor | grep -qx masked-runtime && systemctl unmask --runtime winch-vendor && systemctl is-enabled winch-vendor | grep -qx disabled && systemctl mask --runtime winch-vendor`,
		},
		{
			Name:  "a runtime mask of an enabled running unit disables and stops it",
			Setup: `systemctl enable --now winch-vendor && systemctl mask --runtime winch-vendor && systemctl is-enabled winch-vendor | grep -qx masked-runtime`,
			Args:  &module.Service{Name: "winch-vendor", Enabled: new(false), Running: new(false)},
			Want:  change("disable", "stop"),
			After: `! systemctl is-active -q winch-vendor && test ! -e /etc/systemd/system/multi-user.target.wants/winch-vendor.service`,
		},
		{
			Name:  "a runtime mask of an aliased unit removes the alias",
			Setup: `ln -s /usr/lib/systemd/system/winch-vendor.service /etc/systemd/system/winch-alias.service && systemctl mask --runtime winch-vendor && systemctl is-enabled winch-vendor | grep -qx masked-runtime`,
			Args:  &module.Service{Name: "winch-vendor", Enabled: new(false)},
			Want:  change("disable"),
			After: `test ! -L /etc/systemd/system/winch-alias.service`,
		},
		{
			Name:  "a runtime mask of a disabled unit is ok",
			Setup: `systemctl mask --runtime winch-vendor && systemctl is-enabled winch-vendor | grep -qx masked-runtime`,
			Args:  &module.Service{Name: "winch-vendor", Enabled: new(false)},
			Want:  module.Result{Status: module.OK},
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
			Name:       "restarted restarts a running unit",
			Setup:      `systemctl start winch-test && systemctl show -P InvocationID winch-test > /tmp/inv`,
			Args:       &module.Service{Name: "winch-test", Restarted: true},
			Want:       change("restart"),
			NoConverge: true,
			Unchanged:  `[ "$(systemctl show -P InvocationID winch-test)" = "$(cat /tmp/inv)" ]`,
			After:      `systemctl is-active -q winch-test && [ "$(systemctl show -P InvocationID winch-test)" != "$(cat /tmp/inv)" ]`,
		},
		{
			Name:       "restarted keeps a stopped unit stopped",
			Args:       &module.Service{Name: "winch-test", Restarted: true},
			Want:       change("restart"),
			NoConverge: true,
			After:      `! systemctl is-active -q winch-test`,
		},
		{
			Name:       "reloaded keeps a stopped unit stopped",
			Args:       &module.Service{Name: "winch-test", Reloaded: true},
			Want:       change("reload"),
			NoConverge: true,
			After:      `! systemctl is-active -q winch-test`,
		},
		{
			Name: "restarted after a unit change reloads systemd first",
			Setup: `systemctl start winch-test
mkdir /etc/systemd/system/winch-test.service.d
printf '[Service]\nLimitNOFILE=12345\n' > /etc/systemd/system/winch-test.service.d/limits.conf`,
			Args:       &module.Service{Name: "winch-test", Restarted: true},
			Want:       change("daemon-reload", "restart"),
			NoConverge: true,
			// The second check needs daemon-reload again.
			After: `grep -q '^Max open files  *12345 ' /proc/$(systemctl show -P MainPID winch-test)/limits && printf '[Service]\nLimitNOFILE=12346\n' > /etc/systemd/system/winch-test.service.d/limits.conf`,
		},
		{
			Name:       "reloaded restarts a unit without ExecReload",
			Setup:      `systemctl start winch-test && systemctl show -P InvocationID winch-test > /tmp/inv`,
			Args:       &module.Service{Name: "winch-test", Reloaded: true},
			Want:       change("reload"),
			NoConverge: true,
			After:      `systemctl is-active -q winch-test && [ "$(systemctl show -P InvocationID winch-test)" != "$(cat /tmp/inv)" ]`,
		},
		{
			Name: "reloaded reloads a unit with ExecReload",
			Setup: `rm -f /tmp/reloads
printf '[Service]\nExecStart=/bin/sleep infinity\nExecReload=/bin/sh -c "echo x >> /tmp/reloads"\n' > /etc/systemd/system/winch-reload.service
systemctl daemon-reload && systemctl start winch-reload && systemctl show -P InvocationID winch-reload > /tmp/inv`,
			Args:       &module.Service{Name: "winch-reload", Reloaded: true},
			Want:       change("reload"),
			NoConverge: true,
			After:      `[ -s /tmp/reloads ] && [ "$(systemctl show -P InvocationID winch-reload)" = "$(cat /tmp/inv)" ]`,
		},
		{
			Name:    "a oneshot unit that must run fails",
			Args:    &module.Service{Name: "winch-oneshot", Running: new(true)},
			WantErr: "winch-oneshot.service is a oneshot unit without RemainAfterExit=yes, so it is never running after its job; start its timer, or use cmd",
		},
		{
			Name: "a oneshot unit that must not run is ok",
			Args: &module.Service{Name: "winch-oneshot", Running: new(false)},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "start a oneshot unit with RemainAfterExit",
			Args:  &module.Service{Name: "winch-remain", Running: new(true)},
			Want:  change("start"),
			After: `systemctl is-active -q winch-remain`,
		},
		{
			Name:      "enable a unit that is enabled only at runtime",
			Setup:     `systemctl enable --runtime winch-test && systemctl is-enabled winch-test | grep -qx enabled-runtime`,
			Args:      &module.Service{Name: "winch-test", Enabled: new(true)},
			Want:      change("enable"),
			Unchanged: `systemctl is-enabled winch-test | grep -qx enabled-runtime`,
			After:     `test -L /etc/systemd/system/multi-user.target.wants/winch-test.service`,
		},
		{
			Name:      "enable a linked unit",
			Setup:     `systemctl link /opt/winch/winch-linked.service && systemctl is-enabled winch-linked | grep -qx linked`,
			Args:      &module.Service{Name: "winch-linked", Enabled: new(true)},
			Want:      change("enable"),
			Unchanged: `systemctl is-enabled winch-linked | grep -qx linked`,
			After:     `test -L /etc/systemd/system/multi-user.target.wants/winch-linked.service`,
		},
		{
			Name:         "a failed start shows the journal",
			Setup:        `echo boom on start > /tmp/boom`,
			Args:         &module.Service{Name: "winch-boom", Running: new(true)},
			Want:         change("start"),
			WantApplyErr: "\nboom on start",
		},
		{
			Name:         "a failed restart shows the journal",
			Setup:        `systemctl start winch-boom && echo boom on restart > /tmp/boom`,
			Args:         &module.Service{Name: "winch-boom", Restarted: true},
			Want:         change("restart"),
			WantApplyErr: "\nboom on restart",
		},
		{
			Name:         "a failed reload shows the journal",
			Setup:        `systemctl start winch-boom`,
			Args:         &module.Service{Name: "winch-boom", Reloaded: true},
			Want:         change("reload"),
			WantApplyErr: "\nboom on reload",
		},
		{
			Name: "restarted on a missing unit is ok",
			Args: &module.Service{Name: "winch-nope", Restarted: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name: "reloaded on a missing unit is ok",
			Args: &module.Service{Name: "winch-nope", Reloaded: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name: "a missing unit that must not run is ok",
			Args: &module.Service{Name: "winch-nope", Enabled: new(false), Running: new(false)},
			Want: module.Result{Status: module.OK},
		},
	})
}
