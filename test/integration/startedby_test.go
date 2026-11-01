package integration

import (
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

const socketUnits = `cat > /etc/systemd/system/winch-sock.socket <<'U'
[Socket]
ListenStream=127.0.0.1:7979
[Install]
WantedBy=sockets.target
U
cat > /etc/systemd/system/winch-sock.path <<'U'
[Path]
PathExists=/tmp/winch-sock
U
cat > /etc/systemd/system/winch-sock.service <<'U'
[Service]
ExecStart=/bin/sleep infinity
U
systemctl daemon-reload`

const socketReset = `systemctl stop winch-sock.socket winch-sock.path winch-sock.service; systemctl disable winch-sock.socket 2>/dev/null; true`

const stopSock = `      - service:
          name: winch-sock
          running: false
          enabled: false
`

const stopSocket = `      - service:
          name: winch-sock.socket
          running: false
          enabled: false
`

// spec: Modules/service and unit
func TestServiceStartedBy(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "startedby")
	vm.MustRun(t, socketUnits)

	t.Run("the check names an active or enabled socket", func(t *testing.T) {
		s := vm.Session(t)
		stop := &module.Service{Name: "winch-sock", Running: new(false), Enabled: new(false)}
		tests := []struct {
			name, setup string
			args        *module.Service
			want        []string
		}{
			{"active and enabled", "systemctl enable --now winch-sock.socket", stop, []string{"winch-sock.socket"}},
			{"active", "systemctl start winch-sock.socket", stop, []string{"winch-sock.socket"}},
			{"enabled", "systemctl enable winch-sock.socket", stop, []string{"winch-sock.socket"}},
			{"neither", "true", stop, nil},
			{"running: false alone", "systemctl start winch-sock.socket", &module.Service{Name: "winch-sock", Running: new(false)}, []string{"winch-sock.socket"}},
			{"enabled: false alone", "systemctl enable winch-sock.socket", &module.Service{Name: "winch-sock", Enabled: new(false)}, []string{"winch-sock.socket"}},
			{"running: true", "systemctl start winch-sock.socket", &module.Service{Name: "winch-sock", Running: new(true)}, nil},
			{"a socket and a path", "systemctl start winch-sock.socket winch-sock.path", stop, []string{"winch-sock.path", "winch-sock.socket"}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				vm.MustRun(t, socketReset+"\n"+tt.setup)
				res, err := s.Check(t.Context(), "service", tt.args, &module.State{})
				if err != nil {
					t.Fatal(err)
				}
				slices.Sort(res.StartedBy)
				if !slices.Equal(res.StartedBy, tt.want) {
					t.Errorf("started by %q, want %q", res.StartedBy, tt.want)
				}
			})
		}
		vm.MustRun(t, socketReset)
	})

	t.Run("the check names the socket of a unit without ExecStart", func(t *testing.T) {
		vm.MustRun(t, `cat > /etc/systemd/system/winch-bsock.socket <<'U'
[Socket]
ListenStream=127.0.0.1:7980
[Install]
WantedBy=sockets.target
U
printf '[Service]\nType=simple\n' > /etc/systemd/system/winch-bsock.service
systemctl daemon-reload && systemctl enable winch-bsock.socket && systemctl show -P LoadState winch-bsock.service | grep -qx bad-setting`)
		defer vm.MustRun(t, "systemctl disable winch-bsock.socket")
		res, err := vm.Session(t).Check(t.Context(), "service", &module.Service{Name: "winch-bsock", Running: new(false)}, &module.State{})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"winch-bsock.socket"}; !slices.Equal(res.StartedBy, want) {
			t.Errorf("started by %q, want %q", res.StartedBy, want)
		}
	})

	t.Run("a step for the socket stops it", func(t *testing.T) {
		vm.MustRun(t, socketReset+"\nsystemctl enable --now winch-sock.socket && systemctl start winch-sock.service")
		pipeline := "stages:\n  - name: s\n    hosts: all\n    steps:\n"
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: sdemo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  startedby: {}\n",
			"pipelines/alone.yaml":  pipeline + stopSock,
			"pipelines/both.yaml":   pipeline + stopSock + stopSocket,
		})
		r := lab.Winch(t, dir, "plan", "alone")
		if want := "s: service winch-sock: winch-sock.socket starts winch-sock.service; add a service step that stops and disables winch-sock.socket"; r.Code != 1 || !strings.Contains(r.Stderr, want) {
			t.Fatalf("plan without a step for the socket: exit %d, stderr %q, want %q", r.Code, r.Stderr, want)
		}
		r = lab.Winch(t, dir, "apply", "both", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply: exit %d, stderr %q", r.Code, r.Stderr)
		}
		r = lab.Winch(t, dir, "plan", "both")
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
		vm.MustRun(t, `! systemctl is-active -q winch-sock.socket && ! systemctl is-enabled -q winch-sock.socket && ! systemctl is-active -q winch-sock.service`)
	})
}
