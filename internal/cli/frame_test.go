package cli

import (
	"path/filepath"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
)

// spec: CLI/Messages ("A line has one prefix"; notes); CLI/JSON output
func TestFrame(t *testing.T) {
	assertStep := `stages:
  - name: base
    hosts: web1
    steps:
      - file:
          path: /etc/motd
          content: "hello\n"
      - assert:
          command: probe
          message: |-
            port 25 is closed
            open it in the firewall
`
	firewallStep := `stages:
  - name: base
    hosts: web1
    steps:
      - file:
          path: /etc/motd
          content: "hello\n"
      - firewall: {allow: [{tcp: 22}]}
`
	tests := []struct {
		name     string
		pipeline string
		setup    func(h *fakehost.Hosts)
		args     []string
	}{
		{name: "project-error", pipeline: "stages:\n  - name: base\n    hosts: all\n    steps:\n      - fiel: {}\n", args: []string{"validate"}},
		{name: "command-line-error", pipeline: motd, args: []string{"run", "web1"}},
		{name: "host-error-lines", pipeline: assertStep, setup: func(h *fakehost.Hosts) {
			h.FailCommand("web1", "probe")
		}, args: []string{"apply", "site", "--yes"}},
		{name: "note", pipeline: firewallStep, setup: func(h *fakehost.Hosts) {
			h.SetNote("web1", "/etc/motd", "the certificate a expires on 2026-11-20; check its renewal")
			h.SetResult("web1", "", module.Result{Status: module.Change, Action: module.Create, Changes: []string{"load the rules"},
				MissingTools: []module.Tool{{Name: "nft", Package: "nftables"}}})
		}, args: []string{"apply", "site", "--yes"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, tt.pipeline)
			run := func(args ...string) result {
				h := fakehost.New()
				if tt.setup != nil {
					tt.setup(h)
				}
				return winch(t, dir, h, false, "", args...)
			}
			text := run(tt.args...)
			js := run(append(tt.args, "--json")...)
			golden.Assert(t, filepath.Join("testdata", "frame", tt.name+".golden"),
				[]byte("text stderr:\n"+text.err+"json stdout:\n"+js.out+"json stderr:\n"+js.err))
		})
	}
}
