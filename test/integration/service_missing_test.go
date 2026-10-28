package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/service and unit
func TestServiceMissingUnitFile(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "servicemissing")
	const note = "winch-missing.service: unit file not found"
	const stop = "      - service: {name: winch-missing, running: false}\n"
	const remove = "      - file: {path: /etc/systemd/system/winch-missing.service, absent: true}\n"
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":              "name: servicemissing\ninventory: test\n",
		"inventories/test.yaml":   "hosts:\n  servicemissing: {}\n",
		"pipelines/stop.yaml":     "stages:\n  - name: services\n    hosts: all\n    steps:\n" + stop,
		"pipelines/before.yaml":   "stages:\n  - name: services\n    hosts: all\n    steps:\n" + remove + stop,
		"pipelines/after.yaml":    "stages:\n  - name: services\n    hosts: all\n    steps:\n" + stop + remove,
		"pipelines/disabled.yaml": "stages:\n  - name: services\n    hosts: all\n    steps:\n      - service: {name: winch-missing, enabled: false}\n",
	})
	start := func(t *testing.T) {
		vm.MustRun(t, `cat >/etc/systemd/system/winch-missing.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
U
systemctl daemon-reload
systemctl start winch-missing
systemctl show --value -p MainPID winch-missing >/tmp/winch-missing.pid`)
	}
	stopped := func(t *testing.T) {
		vm.MustRun(t, `test "$(systemctl show --value -p MainPID winch-missing)" = 0
! kill -0 "$(cat /tmp/winch-missing.pid)" 2>/dev/null`)
	}
	t.Run("a missing stopped unit is noted", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "stop")
		if r.Code != 0 || !unchanged(r.Stdout, 1) || !strings.Contains(r.Stdout+r.Stderr, note) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	t.Run("a missing unit is noted with JSON output", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "stop", "--json")
		if r.Code != 0 || !strings.Contains(r.Stderr, note) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	t.Run("disabling alone does not note a missing unit", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "disabled")
		if r.Code != 0 || !unchanged(r.Stdout, 1) || strings.Contains(r.Stdout+r.Stderr, note) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	for _, reload := range []bool{false, true} {
		name := "stops after deletion"
		if reload {
			name += " and reload"
		}
		t.Run(name, func(t *testing.T) {
			start(t)
			vm.MustRun(t, "rm /etc/systemd/system/winch-missing.service")
			if reload {
				vm.MustRun(t, "systemctl daemon-reload")
			}
			r := lab.Winch(t, dir, "apply", "stop", "--yes")
			if r.Code != 0 || !strings.Contains(r.Stdout+r.Stderr, note) || strings.Contains(r.Stdout+r.Stderr, "does not exist yet") {
				t.Errorf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
			}
			stopped(t)
		})
	}
	for _, pipeline := range []string{"before", "after"} {
		t.Run("missing active cleanup "+pipeline, func(t *testing.T) {
			start(t)
			vm.MustRun(t, "rm /etc/systemd/system/winch-missing.service && systemctl daemon-reload")
			r := lab.Winch(t, dir, "apply", pipeline, "--yes")
			if r.Code != 0 || strings.Contains(r.Stdout+r.Stderr, note) || strings.Contains(r.Stdout+r.Stderr, "does not exist yet") {
				t.Errorf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
			}
			stopped(t)
		})
		t.Run("repeated cleanup "+pipeline, func(t *testing.T) {
			start(t)
			for range 3 {
				r := lab.Winch(t, dir, "apply", pipeline, "--yes")
				if r.Code != 0 || strings.Contains(r.Stdout+r.Stderr, note) || strings.Contains(r.Stdout+r.Stderr, "does not exist yet") {
					t.Errorf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
				}
				stopped(t)
			}
		})
	}
	t.Run("a deleted linked fragment can still stop", func(t *testing.T) {
		vm.MustRun(t, `mkdir -p /opt/winch-missing
cat >/opt/winch-missing/winch-missing.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
U
systemctl link /opt/winch-missing/winch-missing.service
systemctl start winch-missing
systemctl show --value -p MainPID winch-missing >/tmp/winch-missing.pid
systemctl show --property=UnitFileState winch-missing
rm /opt/winch-missing/winch-missing.service`)
		r := lab.Winch(t, dir, "apply", "stop", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout+r.Stderr, note) {
			t.Errorf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		stopped(t)
	})
}
