package project

import (
	"testing"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
)

// spec: Steps (confirm_access: service steps only, in steps or in handlers)
func TestConfirmAccess(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - recipe: ssh
      - recipe: plain
      - service:
          name: nftables
          running: true
        confirm_access: true
  - name: other
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: hi
`,
		"recipes/ssh/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/sshd_config.d/local.conf
      content: "PasswordAuthentication no\n"
    notify: reload
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`,
		"recipes/plain/recipe.yaml": `steps:
  - service:
      name: cron
      running: true
    confirm_access: false
`,
	})
	p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	stages := p.Pipeline.Stages
	if !stages[0].Steps[2].ConfirmAccess || !stages[0].ConfirmsAccess() || stages[1].ConfirmsAccess() {
		t.Errorf("stage steps: confirm_access %v, stage base %v, stage other %v", stages[0].Steps[2].ConfirmAccess, stages[0].ConfirmsAccess(), stages[1].ConfirmsAccess())
	}
	ssh, plain := stages[0].Steps[0].Recipe, stages[0].Steps[1].Recipe
	if !ssh.Handlers[0].Steps[0].ConfirmAccess || !ssh.ConfirmsAccess() {
		t.Errorf("recipe ssh: handler step confirm_access %v, recipe %v", ssh.Handlers[0].Steps[0].ConfirmAccess, ssh.ConfirmsAccess())
	}
	if plain.Steps[0].ConfirmAccess || plain.ConfirmsAccess() {
		t.Error("confirm_access: false confirms")
	}
}

// spec: Remote execution/Facts (reboot_required)
func TestRebootRequiredFact(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: !tpl "reboot: {{ .facts.reboot_required }}\n"
        when: !expr facts.reboot_required
`,
	})
	p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []bool{false, true} {
		env, err := p.Start(p.Inventory.Hosts[0], facts.Facts{OS: facts.OS{ID: "debian"}, RebootRequired: required})
		if err != nil {
			t.Fatal(err)
		}
		steps, err := p.Pipeline.Stages[0].Steps[0].Eval(env)
		if err != nil {
			t.Fatal(err)
		}
		if len(steps) != map[bool]int{false: 0, true: 1}[required] {
			t.Fatalf("reboot_required %v: %d steps", required, len(steps))
		}
		if required && string(steps[0].Args.(*module.File).Data) != "reboot: true\n" {
			t.Errorf("content %q", steps[0].Args.(*module.File).Data)
		}
	}
}
