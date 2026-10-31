package integration

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
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
Type=forking
ExecStart=/bin/true
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
ExecReload=/bin/sh -c 'if [ -e /tmp/boom ]; then cat /tmp/boom; exit 1; fi'
U
cat > /etc/systemd/system/winch-slowstop.service <<'U'
[Unit]
JobTimeoutSec=1
[Service]
ExecStart=/bin/sleep infinity
ExecStop=/bin/sh -c 'echo boom on stop; sleep 3'
U
cat > /etc/systemd/system/winch-bad.service <<'U'
[Service]
ExecStart=relative/path
U
cat > /etc/systemd/system/winch-noexec.service <<'U'
[Service]
Type=simple
[Install]
WantedBy=multi-user.target
U
mkdir -p /opt/winch
cat > /opt/winch/winch-linked.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
U
cat > /opt/winch/winch-noinstall.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
U
cat > /opt/winch/winch-dropin.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
U
cat > /opt/winch/winch-ltpl@.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
U
cat > /etc/systemd/system/winch-cond.service <<'U'
[Unit]
ConditionPathExists=/tmp/winch-cond
ConditionPathExists=/
[Service]
ExecStart=/bin/sleep infinity
U
cat > /etc/systemd/system/winch-quick.service <<'U'
[Service]
Type=forking
ExecStart=/bin/true
U
cat > /etc/systemd/system/winch-late.service <<'U'
[Service]
ExecStart=/bin/sh -c 'sleep 0.5; exit 1'
U
cat > /etc/systemd/system/winch-later.service <<'U'
[Service]
Type=simple
ExecStart=/bin/sh -c 'sleep 1; exit 1'
U
cat > /etc/systemd/system/winch-ready.service <<'U'
[Service]
Type=notify
NotifyAccess=all
ExecStart=/bin/sh -c 'systemd-notify --ready; exec sleep infinity'
U
cat > /etc/systemd/system/winch-loop.service <<'U'
[Service]
ExecStart=/bin/sh -c 'sleep 0.5; exit 1'
Restart=on-failure
U
cat > /etc/systemd/system/winch-indirect.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
U
ln -sf winch-indirect.service /etc/systemd/system/winch-indirect2.service
cat > /etc/systemd/system/winch-also.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
Also=winch-a.service winch-b.socket
Also=winch-c.service
U
cat > /usr/lib/systemd/system/winch-vendor.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload`

// enableSSH enables ssh.service. Ubuntu enables only ssh.socket, which
// starts ssh.service.
const enableSSH = "systemctl enable -q ssh"

const waitCrash = `timeout 10 sh -c 'until systemctl show -P SubState winch-crash | grep -qx auto-restart; do sleep 0.1; done'`

const crashDropIn = `mkdir /etc/systemd/system/winch-test.service.d
printf '[Service]\nExecStart=\nExecStart=/bin/sh -c "sleep 0.5; exit 1"\n' > /etc/systemd/system/winch-test.service.d/crash.conf
systemctl daemon-reload`

const noexecErr = `winch-noexec.service has the load state "bad-setting"
winch-noexec.service: Service has no ExecStart=`

// atStartLimit makes 5 starts of winch-test, the start limit of systemd in 10
// seconds. The reset drops the starts of earlier cases.
const atStartLimit = `systemctl reset-failed winch-test 2>/dev/null; systemctl start winch-test && for i in 1 2 3 4; do systemctl restart winch-test; done && systemctl show -P InvocationID winch-test > /tmp/inv`

// oddUnit has the instance "a b;$(touch /tmp/pwn)", as systemd-escape writes it.
const oddUnit = `winch-tpl@a\x20b\x3b\x24\x28touch\x20-tmp-pwn\x29`

// spec: Modules/service and unit
func TestServiceModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "service")
	vm.MustRun(t, units)
	reset := "systemctl unmask --runtime winch-vendor; systemctl reset-failed winch-crash winch-quick winch-late winch-later winch-loop; if [ -d /etc/systemd/system/winch-crash.service.d ] || [ -d /etc/systemd/system/winch-quick.service.d ] || [ -d /etc/systemd/system/winch-slowstop.service.d ] || [ -d /etc/systemd/system/winch-test.service.d ]; then rm -rf /etc/systemd/system/winch-crash.service.d /etc/systemd/system/winch-quick.service.d /etc/systemd/system/winch-slowstop.service.d /etc/systemd/system/winch-test.service.d; systemctl daemon-reload; fi; systemctl unmask winch-vendor winch-tpl@one; if [ -e /etc/systemd/system/winch-nope.service ]; then systemctl disable --now winch-nope; rm /etc/systemd/system/winch-nope.service; systemctl daemon-reload; fi; systemctl stop 'winch-tpl@*' winch-test.service winch-test.timer winch-static.service winch-vendor.service winch-crash.service winch-notify.service winch-boom.service winch-remain.service winch-lost.service winch-cond.service winch-slowstop.service winch-late.service winch-later.service winch-ready.service winch-loop.service; rm -f /tmp/boom /tmp/winch-cond; if [ -L /run/systemd/system/multi-user.target.wants/winch-test.service ]; then systemctl disable --runtime winch-test.service; fi; systemctl disable winch-test.service winch-test.timer winch-vendor.service winch-tpl@one.service winch-tpl@two.service winch-noexec.service 2>/dev/null; if [ -L /etc/systemd/system/winch-linked.service ] || [ -L /etc/systemd/system/winch-noinstall.service ] || [ -L /etc/systemd/system/winch-dropin.service ] || [ -L /etc/systemd/system/winch-ltpl@.service ]; then systemctl stop winch-linked.service; for u in winch-linked winch-dropin winch-ltpl@one; do systemctl disable $u.service 2>/dev/null; done; rm -rf /etc/systemd/system/winch-linked.service /etc/systemd/system/winch-noinstall.service /etc/systemd/system/winch-dropin.service /etc/systemd/system/winch-dropin.service.d /etc/systemd/system/winch-ltpl@.service /etc/systemd/system/winch-ltpl@one.service; systemctl daemon-reload; fi; true"
	change := func(changes ...string) module.Result {
		return module.Result{Status: module.Change, Action: module.Modify, Changes: changes}
	}
	t.Run("a masked unit fails without journal lines", func(t *testing.T) {
		vm.MustRun(t, "systemctl start winch-vendor && systemctl stop winch-vendor && systemctl mask --runtime winch-vendor")
		defer vm.MustRun(t, "systemctl unmask --runtime winch-vendor")
		_, err := vm.Session(t).Check(t.Context(), "service", &module.Service{Name: "winch-vendor", Running: new(true)}, &module.State{})
		if want := `winch-vendor.service has the load state "masked"`; err == nil || err.Error() != want {
			t.Errorf("check error = %v, want %q", err, want)
		}
	})
	t.Run("a start of a unit that crashes soon after fails each time", func(t *testing.T) {
		s := vm.Session(t)
		args := &module.Service{Name: "winch-late", Running: new(true)}
		for i := range 10 {
			if _, err := s.Check(t.Context(), "service", args, &module.State{}); err != nil {
				t.Fatalf("run %d: check: %v", i, err)
			}
			_, err := s.Apply(t.Context(), "service", args, &module.State{}, nil, nil, nil, protocol.Guard{})
			if want := "winch-late.service is not running after its start: failed (failed)\n"; err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("run %d: apply error = %v, want %q", i, err, want)
			}
		}
	})
	t.Run("a start of a simple unit that exits after 1 s fails", func(t *testing.T) {
		s := vm.Session(t)
		args := &module.Service{Name: "winch-later", Running: new(true)}
		if _, err := s.Check(t.Context(), "service", args, &module.State{}); err != nil {
			t.Fatal(err)
		}
		_, err := s.Apply(t.Context(), "service", args, &module.State{}, nil, nil, nil, protocol.Guard{})
		if want := "winch-later.service is not running after its start: failed (failed)\n"; err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("apply error = %v, want %q", err, want)
		}
	})
	t.Run("a start of a notify unit has no watch", func(t *testing.T) {
		out := vm.MustRun(t, "a=$(date +%s%N); systemctl start winch-ready; b=$(date +%s%N); systemctl stop winch-ready; echo $((b-a))")
		ns, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		s := vm.Session(t)
		args := &module.Service{Name: "winch-ready", Running: new(true)}
		if _, err := s.Check(t.Context(), "service", args, &module.State{}); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := s.Apply(t.Context(), "service", args, &module.State{}, nil, nil, nil, protocol.Guard{}); err != nil {
			t.Fatal(err)
		}
		if d, sys := time.Since(start), time.Duration(ns); d > sys+time.Second {
			t.Errorf("apply took %s, systemctl start %s; want less than 1s more", d, sys)
		}
		vm.MustRun(t, "systemctl stop winch-ready")
	})
	t.Run("a start of a unit that crashes and restarts fails each time", func(t *testing.T) {
		s := vm.Session(t)
		args := &module.Service{Name: "winch-loop", Running: new(true)}
		for i := range 10 {
			vm.MustRun(t, "systemctl stop winch-loop")
			if _, err := s.Check(t.Context(), "service", args, &module.State{}); err != nil {
				t.Fatalf("run %d: check: %v", i, err)
			}
			_, err := s.Apply(t.Context(), "service", args, &module.State{}, nil, nil, nil, protocol.Guard{})
			if want := "winch-loop.service restarted after its start\n"; err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("run %d: apply error = %v, want %q", i, err, want)
			}
		}
		vm.MustRun(t, "systemctl stop winch-loop")
	})
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
			// systemd 255 reports no NeedDaemonReload for a new drop-in
			// directory.
			Setup: `systemctl enable winch-test
mkdir /etc/systemd/system/winch-test.service.d
printf '[Service]\nLimitNOFILE=12345\n' > /etc/systemd/system/winch-test.service.d/limits.conf`,
			Args:      &module.Service{Name: "winch-test", Running: new(true)},
			Want:      change("daemon-reload", "start"),
			Unchanged: `[ "$(systemctl show -P LimitNOFILE winch-test)" != 12345 ]`,
			After:     `grep -q '^Max open files  *12345 ' /proc/$(systemctl show -P MainPID winch-test)/limits`,
		},
		{
			Name: "a new drop-in of a running unit reloads systemd",
			Setup: `systemctl enable --now winch-test
mkdir /etc/systemd/system/winch-test.service.d
printf '[Service]\nLimitNOFILE=12345\n' > /etc/systemd/system/winch-test.service.d/limits.conf`,
			Args:  &module.Service{Name: "winch-test", Running: new(true)},
			Want:  change("daemon-reload"),
			After: `systemctl show -P LimitNOFILE winch-test | grep -qx 12345`,
		},
		{
			Name:         "a start that leaves the unit waiting to restart fails",
			Setup:        "systemctl start winch-crash\n" + waitCrash + "\nsystemctl show -P InvocationID winch-crash > /tmp/inv",
			Args:         &module.Service{Name: "winch-crash", Running: new(true)},
			Want:         change("start"),
			WantApplyErr: "winch-crash.service is not running after its start: activating (auto-restart)\n",
			After:        waitCrash + ` && [ "$(systemctl show -P InvocationID winch-crash)" != "$(cat /tmp/inv)" ]`,
			Fix:          "mkdir /etc/systemd/system/winch-crash.service.d && printf '[Service]\\nRemainAfterExit=yes\\n' > /etc/systemd/system/winch-crash.service.d/up.conf && systemctl daemon-reload",
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
			WantErr: `winch-static.service has the unit file state "static"; enabled: true needs an enabled, disabled, enabled-runtime, or linked unit`,
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
			Fix:          "printf '[Service]\\nExecStart=/bin/sleep infinity\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/winch-nope.service && systemctl daemon-reload",
		},
		{
			Name:    "an alias fails and names the unit",
			Setup:   enableSSH + " && test -L /etc/systemd/system/sshd.service",
			Args:    &module.Service{Name: "sshd", Enabled: new(true)},
			WantErr: "sshd is an alias of ssh.service; use ssh",
		},
		{
			Name:    "an alias with the .service suffix fails",
			Setup:   enableSSH + " && test -L /etc/systemd/system/sshd.service",
			Args:    &module.Service{Name: "sshd.service", Running: new(true)},
			WantErr: "sshd.service is an alias of ssh.service; use ssh",
		},
		{
			Name:  "the unit of an alias is ok",
			Setup: enableSSH + " && systemctl start ssh && systemctl is-active -q ssh",
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
			Name:       "restarted restarts a unit at the start limit",
			Setup:      atStartLimit,
			Args:       &module.Service{Name: "winch-test", Restarted: true},
			Want:       change("restart"),
			NoConverge: true,
			After:      `systemctl is-active -q winch-test && [ "$(systemctl show -P InvocationID winch-test)" != "$(cat /tmp/inv)" ]`,
		},
		{
			Name:       "reloaded restarts a unit at the start limit",
			Setup:      atStartLimit,
			Args:       &module.Service{Name: "winch-test", Reloaded: true},
			Want:       change("reload"),
			NoConverge: true,
			After:      `systemctl is-active -q winch-test && [ "$(systemctl show -P InvocationID winch-test)" != "$(cat /tmp/inv)" ]`,
		},
		{
			Name:  "start a unit that failed on the start limit",
			Setup: `systemctl start winch-test; for i in 1 2 3 4 5; do systemctl restart winch-test 2>/dev/null || break; done; systemctl is-failed -q winch-test`,
			Args:  &module.Service{Name: "winch-test", Running: new(true)},
			Want:  change("start"),
			After: `systemctl is-active -q winch-test`,
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
			Name:         "restarted on a unit whose new config crashes fails",
			Setup:        "systemctl start winch-test\n" + crashDropIn,
			Args:         &module.Service{Name: "winch-test", Restarted: true},
			Want:         change("restart"),
			WantApplyErr: "winch-test.service is not running after its restart: failed (failed)\n",
			Fix:          "rm -r /etc/systemd/system/winch-test.service.d && systemctl daemon-reload",
			NoConverge:   true,
		},
		{
			Name:         "reloaded on a unit whose new config crashes fails",
			Setup:        "systemctl start winch-test\n" + crashDropIn,
			Args:         &module.Service{Name: "winch-test", Reloaded: true},
			Want:         change("reload"),
			WantApplyErr: "winch-test.service is not running after its reload: failed (failed)\n",
			Fix:          "rm -r /etc/systemd/system/winch-test.service.d && systemctl daemon-reload",
			NoConverge:   true,
		},
		{
			Name: "restarted on a unit whose new config crashes and waits to restart fails",
			Setup: "systemctl start winch-test\n" + crashDropIn + `
printf '[Service]\nRestart=on-failure\nRestartSec=1h\n' > /etc/systemd/system/winch-test.service.d/restart.conf
systemctl daemon-reload`,
			Args:         &module.Service{Name: "winch-test", Restarted: true},
			Want:         change("restart"),
			WantApplyErr: "winch-test.service is not running after its restart: activating (auto-restart)\n",
			Fix:          "rm -r /etc/systemd/system/winch-test.service.d && systemctl daemon-reload",
			NoConverge:   true,
		},
		{
			Name: "reloaded on a unit whose reload ends it fails",
			Setup: `systemctl start winch-test
mkdir /etc/systemd/system/winch-test.service.d
printf '[Service]\nExecReload=/bin/kill $MAINPID\n' > /etc/systemd/system/winch-test.service.d/reload.conf
systemctl daemon-reload`,
			Args:         &module.Service{Name: "winch-test", Reloaded: true},
			Want:         change("reload"),
			WantApplyErr: "winch-test.service is not running after its reload: ",
			Fix:          "rm -r /etc/systemd/system/winch-test.service.d && systemctl daemon-reload",
			NoConverge:   true,
		},
		{
			// systemd cancels the reload job when the unit ends before its
			// ExecReload ends, and systemctl fails.
			Name: "reloaded on a unit that ends during its reload fails",
			Setup: `systemctl start winch-test
mkdir /etc/systemd/system/winch-test.service.d
printf '[Service]\nExecReload=/bin/sh -c "kill $MAINPID; sleep 1"\n' > /etc/systemd/system/winch-test.service.d/reload.conf
systemctl daemon-reload`,
			Args:         &module.Service{Name: "winch-test", Reloaded: true},
			Want:         change("reload"),
			WantApplyErr: "winch-test.service is not running after its reload: ",
			Fix:          "rm -r /etc/systemd/system/winch-test.service.d && systemctl daemon-reload",
			NoConverge:   true,
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
			Name:  "disable a linked unit keeps its link",
			Setup: `systemctl link /opt/winch/winch-linked.service && systemctl enable winch-linked && systemctl is-enabled winch-linked | grep -qx enabled`,
			Args:  &module.Service{Name: "winch-linked", Enabled: new(false)},
			Want:  change("disable"),
			After: `test -L /etc/systemd/system/winch-linked.service && test ! -e /etc/systemd/system/multi-user.target.wants/winch-linked.service && systemctl show -P LoadState winch-linked | grep -qx loaded && systemctl is-enabled winch-linked | grep -qx linked && ! systemctl show -P Wants multi-user.target | grep -qw winch-linked.service`,
		},
		{
			Name:  "disable and stop a running linked unit",
			Setup: `systemctl link /opt/winch/winch-linked.service && systemctl enable --now winch-linked`,
			Args:  &module.Service{Name: "winch-linked", Enabled: new(false), Running: new(false)},
			Want:  change("disable", "stop"),
			After: `test -L /etc/systemd/system/winch-linked.service && ! systemctl is-active -q winch-linked && systemctl show -P LoadState winch-linked | grep -qx loaded`,
		},
		{
			Name:  "disable an instance of a linked template keeps the template link",
			Setup: `systemctl link /opt/winch/winch-ltpl@.service && systemctl enable winch-ltpl@one && systemctl is-enabled winch-ltpl@one | grep -qx enabled`,
			Args:  &module.Service{Name: "winch-ltpl@one", Enabled: new(false)},
			Want:  change("disable"),
			After: `test -L /etc/systemd/system/winch-ltpl@.service && test ! -e /etc/systemd/system/winch-ltpl@one.service && systemctl is-enabled winch-ltpl@one | grep -qx disabled`,
		},
		{
			Name: "enable a linked unit with [Install] in a drop-in",
			Setup: `systemctl link /opt/winch/winch-dropin.service && mkdir /etc/systemd/system/winch-dropin.service.d
printf '[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/winch-dropin.service.d/install.conf
systemctl daemon-reload && systemctl is-enabled winch-dropin | grep -qx linked`,
			Args:  &module.Service{Name: "winch-dropin", Enabled: new(true)},
			Want:  change("enable"),
			After: `test -L /etc/systemd/system/multi-user.target.wants/winch-dropin.service`,
		},
		{
			Name:    "enable a linked unit without an [Install] section fails",
			Setup:   `systemctl link /opt/winch/winch-noinstall.service && systemctl is-enabled winch-noinstall | grep -qx linked`,
			Args:    &module.Service{Name: "winch-noinstall", Enabled: new(true)},
			WantErr: `winch-noinstall.service has no [Install] section with WantedBy, RequiredBy, UpheldBy, or Alias; enabled: true cannot enable it`,
		},
		{
			Name:         "a failed start shows the journal",
			Setup:        `echo boom on start > /tmp/boom`,
			Args:         &module.Service{Name: "winch-boom", Running: new(true)},
			Want:         change("start"),
			WantApplyErr: "\nboom on start",
			Fix:          "rm /tmp/boom",
		},
		{
			Name:         "a start that a condition skips fails and names the condition",
			Args:         &module.Service{Name: "winch-cond", Running: new(true)},
			Want:         change("start"),
			WantApplyErr: "winch-cond.service did not start: ConditionPathExists=/tmp/winch-cond failed",
			Fix:          "touch /tmp/winch-cond",
		},
		{
			Name:         "a start that leaves the unit inactive fails",
			Args:         &module.Service{Name: "winch-quick", Running: new(true)},
			Want:         change("start"),
			WantApplyErr: "winch-quick.service is not running after its start: inactive (dead)\nStarting winch-quick.service...\n",
			Fix:          "mkdir /etc/systemd/system/winch-quick.service.d && printf '[Service]\\nRemainAfterExit=yes\\n' > /etc/systemd/system/winch-quick.service.d/up.conf && systemctl daemon-reload",
		},
		{
			Name:    "enable a unit with only Also= fails and names its units",
			Args:    &module.Service{Name: "winch-also", Enabled: new(true)},
			WantErr: `winch-also.service has the unit file state "indirect"; enabled: true cannot enable it; enable the units in its Also=: winch-a.service, winch-b.socket, winch-c.service`,
		},
		{
			Name:    "enable an indirect unit without Also= fails",
			Setup:   `systemctl is-enabled winch-indirect | grep -qx indirect`,
			Args:    &module.Service{Name: "winch-indirect", Enabled: new(true)},
			WantErr: `winch-indirect.service has the unit file state "indirect"; enabled: true needs an enabled, disabled, enabled-runtime, or linked unit`,
		},
		{
			Name:         "a failed restart shows the journal",
			Setup:        `systemctl start winch-boom && echo boom on restart > /tmp/boom`,
			Args:         &module.Service{Name: "winch-boom", Restarted: true},
			Want:         change("restart"),
			WantApplyErr: "\nboom on restart",
			Fix:          "rm /tmp/boom",
			NoConverge:   true,
		},
		{
			Name:         "a failed reload shows the journal",
			Setup:        `systemctl start winch-boom && echo boom on reload > /tmp/boom`,
			Args:         &module.Service{Name: "winch-boom", Reloaded: true},
			Want:         change("reload"),
			WantApplyErr: "\nboom on reload",
			Fix:          "rm /tmp/boom",
			NoConverge:   true,
		},
		{
			Name:         "a failed reload of a unit that keeps running names the unit and the reload",
			Setup:        `systemctl start winch-boom && echo boom on reload > /tmp/boom`,
			Args:         &module.Service{Name: "winch-boom", Reloaded: true},
			Want:         change("reload"),
			WantApplyErr: "winch-boom.service did not reload: systemctl try-reload-or-restart: ",
			Fix:          "rm /tmp/boom",
			NoConverge:   true,
		},
		{
			Name:         "a failed stop shows the journal",
			Setup:        `systemctl start winch-slowstop`,
			Args:         &module.Service{Name: "winch-slowstop", Running: new(false)},
			Want:         change("stop"),
			WantApplyErr: "\nboom on stop",
			Fix:          "mkdir /etc/systemd/system/winch-slowstop.service.d && printf '[Unit]\\nJobTimeoutSec=infinity\\n' > /etc/systemd/system/winch-slowstop.service.d/wait.conf && systemctl daemon-reload",
		},
		{
			Name:    "a bad load state shows the journal",
			Args:    &module.Service{Name: "winch-bad", Running: new(true)},
			WantErr: "\n/etc/systemd/system/winch-bad.service:2: Neither a valid executable name nor an absolute path: relative/path",
		},
		{
			Name:  "a unit without ExecStart that must not run is ok",
			Setup: `systemctl show -P LoadState winch-noexec | grep -qx bad-setting`,
			Args:  &module.Service{Name: "winch-noexec", Enabled: new(false), Running: new(false)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "disable a unit without ExecStart",
			Setup: `systemctl enable winch-noexec && systemctl show -P LoadState winch-noexec | grep -qx bad-setting`,
			Args:  &module.Service{Name: "winch-noexec", Enabled: new(false)},
			Want:  change("disable"),
			After: `! systemctl is-enabled -q winch-noexec`,
		},
		{
			Name: "stop a running unit that lost its ExecStart",
			Setup: `printf '[Service]\nExecStart=/bin/sleep infinity\n' > /etc/systemd/system/winch-lost.service
systemctl daemon-reload && systemctl start winch-lost
printf '[Service]\nType=simple\n' > /etc/systemd/system/winch-lost.service
systemctl daemon-reload && systemctl show -P LoadState winch-lost | grep -qx bad-setting && systemctl is-active -q winch-lost`,
			Args:  &module.Service{Name: "winch-lost", Running: new(false)},
			Want:  change("stop"),
			After: `! systemctl is-active -q winch-lost`,
		},
		{
			Name:    "a unit without ExecStart that must be enabled shows the journal",
			Args:    &module.Service{Name: "winch-noexec", Enabled: new(true)},
			WantErr: noexecErr,
		},
		{
			Name:    "a unit without ExecStart that must run shows the journal",
			Args:    &module.Service{Name: "winch-noexec", Enabled: new(false), Running: new(true)},
			WantErr: noexecErr,
		},
		{
			Name:    "restarted on a unit without ExecStart shows the journal",
			Args:    &module.Service{Name: "winch-noexec", Restarted: true},
			WantErr: noexecErr,
		},
		{
			Name:    "reloaded on a unit without ExecStart shows the journal",
			Args:    &module.Service{Name: "winch-noexec", Reloaded: true},
			WantErr: noexecErr,
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
