package run_test

import (
	"context"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/run"
)

// spec: Remote execution/Lockout protection
func TestSSHServerCutOff(t *testing.T) {
	stage := func(name, steps string) string {
		return "  - name: " + name + "\n    hosts: all\n    steps:\n" + steps
	}
	service := func(name, values string) string {
		return "      - service:\n          name: " + name + "\n" + values
	}
	const off = "          running: false\n          enabled: false\n"
	const on = "          running: true\n          enabled: true\n"
	const maskSSH = "      - link:\n          path: /etc/systemd/system/ssh.service\n          target: /dev/null\n"
	tests := []struct {
		name, pipeline, want string
	}{
		{"stop ssh", stage("s", service("ssh", "          running: false\n")),
			"s: service ssh: this stops ssh.service, and no step starts and enables ssh.socket; this cuts off winch's access"},
		{"disable ssh", stage("s", service("ssh", "          enabled: false\n")),
			"s: service ssh: this disables ssh.service, and no step starts and enables ssh.socket; this cuts off winch's access"},
		{"stop ssh.socket", stage("s", service("ssh.socket", off)),
			"s: service ssh.socket: this stops and disables ssh.socket, and no step starts and enables ssh.service; this cuts off winch's access"},
		{"ssh already stopped", stage("s", service("ssh.service", off)), ""},
		{"mask ssh", stage("s", maskSSH), "s: link /etc/systemd/system/ssh.service: this cuts off winch's access"},
		{"ssh.socket already masked", stage("s", "      - link:\n          path: /etc/systemd/system/ssh.socket\n          target: /dev/null\n"), ""},
		{"mask ssh with a relative target", stage("s", "      - link:\n          path: /etc/systemd/system/ssh.service\n          target: ../../../dev/null\n"),
			"s: link /etc/systemd/system/ssh.service: this cuts off winch's access"},
		{"a link to /dev/null in another directory", stage("s", "      - link:\n          path: /etc/systemd/system/other/ssh.service\n          target: /dev/null\n"), ""},
		{"stop ssh.socket, start ssh", stage("s", service("ssh.socket", off)+service("ssh", on)), ""},
		{"start ssh, stop ssh.socket", stage("s", service("ssh", on)+service("ssh.socket", off)), ""},
		{"start ssh in a later stage", stage("s", service("ssh.socket", off)) + stage("t", service("ssh", on)), ""},
		{"start ssh without enabling it", stage("s", service("ssh.socket", off)+service("ssh", "          running: true\n")),
			"s: service ssh.socket: this stops and disables ssh.socket, and no step starts and enables ssh.service; this cuts off winch's access"},
		{"stop ssh, start ssh.socket", stage("s", service("ssh", off)+service("ssh.socket", on)), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n" + tt.pipeline})
			h := fakehost.New()
			stop := module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"disable", "stop"}}
			h.SetResult("web1", "ssh", stop)
			h.SetResult("web1", "ssh.socket", stop)
			h.SetResult("web1", "ssh.service", module.Result{Status: module.OK})
			mask := module.Result{Status: module.Change, Action: module.Create}
			h.SetResult("web1", "/etc/systemd/system/ssh.service", mask)
			h.SetResult("web1", "/etc/systemd/system/other/ssh.service", mask)
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			got := ""
			if err := plan.Failed["web1"]; err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
		})
	}
}
