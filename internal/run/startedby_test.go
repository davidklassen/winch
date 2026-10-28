package run_test

import (
	"context"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/service and unit
func TestStartedBy(t *testing.T) {
	const stop = `      - service:
          name: rpcbind
          running: false
          enabled: false
`
	const socket = `      - service:
          name: rpcbind.socket
          running: false
          enabled: false
`
	stage := func(name, steps string) string {
		return "  - name: " + name + "\n    hosts: all\n    steps:\n" + steps
	}
	const want = "s: service rpcbind: rpcbind.service is started by rpcbind.socket; add a step for rpcbind.socket"
	tests := []struct {
		name, pipeline, want string
	}{
		{"no step for the socket", stage("s", stop), want},
		{"a later step for the socket", stage("s", stop+socket), ""},
		{"an earlier step for the socket", stage("s", socket+stop), ""},
		{"a step for the socket in a later stage", stage("s", stop) + stage("t", socket), ""},
		{"a step for the socket in an earlier stage", stage("t", socket) + stage("s", stop), ""},
		{"a later stage without a step for the socket", stage("s", stop) + stage("t", `      - service:
          name: rpcbind.timer
          running: false
`), want},
		{"two units start the unit", stage("s", `      - service:
          name: nfs
          running: false
`), "s: service nfs: nfs.service is started by nfs.socket; add a step for nfs.socket\n" +
			"s: service nfs: nfs.service is started by nfs.path; add a step for nfs.path"},
		{"a stopped unit", stage("s", `      - service:
          name: stopped
          running: false
`), "s: service stopped: stopped.service is started by rpcbind.socket; add a step for rpcbind.socket"},
		{"a step for another unit", stage("s", stop+`      - service:
          name: rpcbind.timer
          running: false
`), want},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml":   "stages:\n" + tt.pipeline,
			})
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
			if err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			h.SetResult("web1", "rpcbind", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"stop"}, StartedBy: []string{"rpcbind.socket"}})
			h.SetResult("web1", "rpcbind.socket", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"disable", "stop"}})
			h.SetResult("web1", "rpcbind.timer", module.Result{Status: module.OK})
			h.SetResult("web1", "nfs", module.Result{Status: module.OK, StartedBy: []string{"nfs.socket", "nfs.path"}})
			h.SetResult("web1", "stopped", module.Result{Status: module.OK, StartedBy: []string{"rpcbind.socket"}})
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
