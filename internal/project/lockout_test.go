package project

import (
	"testing"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
)

// spec: Steps (confirm_access: service steps only)
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
`,
		"recipes/ssh/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/sshd_config.d/local.conf
      content: "PasswordAuthentication no\n"
  - service:
      name: ssh
      reloaded: true
    on_change: [/etc/ssh]
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
	ssh, plain := stages[0].Steps[0].Recipe, stages[0].Steps[1].Recipe
	if !stages[0].Steps[2].ConfirmAccess || !ssh.Steps[1].ConfirmAccess || plain.Steps[0].ConfirmAccess {
		t.Errorf("confirm_access: stage step %v, ssh %v, plain %v", stages[0].Steps[2].ConfirmAccess, ssh.Steps[1].ConfirmAccess, plain.Steps[0].ConfirmAccess)
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
          content: !tpl "reboot: {{ facts.reboot_required }}\n"
        when: !expr facts.reboot_required
`,
	})
	p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []bool{false, true} {
		env, err := p.Start(p.Inventory.Hosts[0], facts.Facts{OS: facts.OS{ID: "debian"}, RebootRequired: required}, nil)
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
