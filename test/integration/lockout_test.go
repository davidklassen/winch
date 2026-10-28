package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/vmtest"
)

const nftablesRecipe = `vars:
  nftables_tcp_ports: [22]
steps:
  - pkg:
      name: nftables
  - file:
      path: /etc/nftables.conf
      template: nftables.conf.tmpl
      mode: "0755"
      validate: nft -c -f /etc/nftables.conf
    notify: reload
  - service:
      name: nftables
      enabled: true
      running: true
    confirm_access: true
handlers:
  reload:
    - service:
        name: nftables
        reloaded: true
      confirm_access: true
`

const nftablesTemplate = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;

		ct state established,related accept
		ct state invalid drop
		iif lo accept
		tcp dport { {{ join .vars.nftables_tcp_ports ", " }} } accept
	}
}
`

// spec: Running a pipeline/Lockout protection; Steps (confirm_access)
func TestLockoutFirewall(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "firewall")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":                                    "name: demo\ninventory: test\n",
		"inventories/test.yaml":                         "hosts:\n  firewall: {}\n",
		"pipelines/site.yaml":                           "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: nftables\n",
		"recipes/nftables/recipe.yaml":                  nftablesRecipe,
		"recipes/nftables/templates/nftables.conf.tmpl": nftablesTemplate,
	})

	// A good rule passes.
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply with SSH open: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "nft list ruleset"); !strings.Contains(out, "tcp dport 22 accept") {
		t.Fatalf("the ruleset is not in place:\n%s", out)
	}
	if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d", r.Code)
	}
	// The next session clears the stores of the run before.
	if out := vm.MustRun(t, "ls /var/lib/winch/rollback/demo; ls /var/lib/winch/rollback"); out != "demo\n" {
		t.Errorf("the rollback store after the next session: %q", out)
	}

	// A rule that drops SSH is rolled back, and the host fails.
	start := time.Now()
	r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.nftables_tcp_ports=[80]")
	took := time.Since(start)
	if r.Code != 1 || !strings.Contains(r.Stderr, "firewall: nftables: failed: handler nftables.reload: service nftables: no new SSH connection works: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply with SSH dropped: exit %d", r.Code)
	}
	// Two access checks of up to 15 seconds each, 5 seconds apart, and then
	// the controller's rollback: before the timer's 60 seconds.
	if took > 50*time.Second {
		t.Errorf("the rollback took %s", took)
	}
	if out := vm.MustRun(t, "nft list ruleset"); !strings.Contains(out, "tcp dport 22 accept") {
		t.Errorf("the old ruleset is not back:\n%s", out)
	}
	if out := vm.MustRun(t, "cat /etc/nftables.conf"); !strings.Contains(out, "tcp dport { 22 } accept") {
		t.Errorf("the old /etc/nftables.conf is not back:\n%s", out)
	}
	// The next plan reaches the host, and shows the change again.
	r = lab.Winch(t, dir, "plan", "site", "--set", "vars.nftables_tcp_ports=[80]")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ file /etc/nftables.conf") {
		t.Errorf("plan after the rollback: exit %d", r.Code)
	}
}

// spec: Running a pipeline/Lockout protection (a user step that changes the
// keys of the login user)
func TestLockoutKeys(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "keys")
	other := fakeKey('4', "other")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  keys: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - user:
          name: admin
          authorized_keys:
            - ` + other + `
`,
	})
	keysState := "stat -c '%U %G %a' /home/admin/.ssh /home/admin/.ssh/authorized_keys; cat /home/admin/.ssh/authorized_keys"
	before := vm.MustRun(t, keysState)
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "changes the keys of the login user admin") {
		t.Fatalf("plan: exit %d", r.Code)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "keys: base: failed: user admin: no new SSH connection works: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if got := vm.MustRun(t, keysState); got != before {
		t.Errorf("authorized_keys after the rollback:\n%s\nwant\n%s", got, before)
	}
	if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 {
		t.Errorf("plan after the rollback: exit %d", r.Code)
	}
}
