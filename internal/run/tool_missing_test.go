package run_test

import (
	"bytes"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/firewall
func TestToolMissingNote(t *testing.T) {
	const firewall = "      - firewall: {allow: [{tcp: 22}]}\n"
	const note = "web1: warning: nft is missing; install the package nftables in an earlier pkg step\n"
	for _, tt := range []struct {
		name  string
		steps string
		host  func(h *fakehost.Hosts)
		want  string
	}{
		{"no pkg step", firewall, nil, note},
		{"an earlier pkg step", "      - pkg: {name: [curl, nftables]}\n" + firewall, nil, ""},
		{"an earlier pkg step of a package that depends on it", "      - pkg: {name: fail2ban}\n" + firewall, func(h *fakehost.Hosts) { h.SetPkgDeps("fail2ban", "nftables") }, ""},
		{"a later pkg step", firewall + "      - pkg: {name: nftables}\n", nil, note},
		{"an earlier pkg step that removes it", "      - pkg: {name: nftables, absent: true}\n" + firewall, func(h *fakehost.Hosts) { h.SetPkg("web1", "nftables") }, note},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: missing\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml":   steps(tt.steps),
			})
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
			if err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			h.SetResult("web1", "", module.Result{Status: module.Change, Action: module.Create, Changes: []string{"load the rules"},
				MissingTools: []module.Tool{{Name: "nft", Package: "nftables"}}})
			if tt.host != nil {
				tt.host(h)
			}
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			if len(plan.Failed) > 0 {
				t.Fatal(plan.Failed)
			}
			var errOut bytes.Buffer
			plan.WriteNotes(plain(&errOut))
			if errOut.String() != tt.want {
				t.Errorf("notes = %q, want %q", errOut.String(), tt.want)
			}
		})
	}
}
