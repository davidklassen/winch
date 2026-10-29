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

// spec: Running a pipeline/Lockout protection (a step saves in the store of
// its own recipe and in that of each recipe whose confirm_access handler it
// notifies)
func TestLockoutNotifiedStore(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "notified-store")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\nvars:\n  ssh_drop: false\n",
		"inventories/test.yaml": "hosts:\n  notified-store: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: ssh\n      - recipe: nftables\n",
		"recipes/ssh/recipe.yaml": `steps:
  - file:
      path: /etc/nftables-ssh.nft
      content: !tpl |
        table inet ssh {
        	chain input {
        		type filter hook input priority -10; policy accept;
        		{{ if .vars.ssh_drop }}ct state new tcp dport 22 drop{{ end }}
        	}
        }
    notify: nftables.reload
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`,
		"recipes/nftables/recipe.yaml": `steps:
  - pkg:
      name: nftables
  - file:
      path: /etc/nftables.conf
      content: |
        #!/usr/sbin/nft -f
        flush ruleset
        include "/etc/nftables-ssh.nft"
      mode: "0755"
      validate: nft -c -f /etc/nftables.conf
    notify: reload
  - service:
      name: nftables
      enabled: true
      running: true
handlers:
  reload:
    - service:
        name: nftables
        reloaded: true
      confirm_access: true
`,
	})
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply with SSH open: exit %d", r.Code)
	}
	good := vm.MustRun(t, "cat /etc/nftables-ssh.nft")

	r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.ssh_drop=true")
	if r.Code != 1 || !strings.Contains(r.Stderr, "notified-store: nftables: failed: handler nftables.reload: service nftables: no new SSH connection works: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply with SSH dropped: exit %d", r.Code)
	}
	if got := vm.MustRun(t, "cat /etc/nftables-ssh.nft"); got != good {
		t.Errorf("/etc/nftables-ssh.nft after the rollback:\n%s\nwant\n%s", got, good)
	}
	if out := vm.MustRun(t, "nft list ruleset"); strings.Contains(out, "drop") {
		t.Errorf("the ruleset drops SSH after the rollback:\n%s", out)
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

// spec: Running a pipeline/Lockout protection; Modules/user and group (a
// groups change that only adds groups to the login user)
func TestLockoutGroups(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "groups")
	vm.MustRun(t, "groupadd wtok && groupadd wtdeny && echo 'DenyGroups wtdeny' > /etc/ssh/sshd_config.d/wt.conf && systemctl reload ssh")
	files := map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  groups: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: admin\n",
	}

	// A group that sshd denies: the step rolls back.
	files["recipes/admin/recipe.yaml"] = "steps:\n  - user:\n      name: admin\n      groups: [admin, wtdeny]\n"
	dir := vmtest.WriteProject(t, files)
	groupsState := "id -nG admin; sha256sum /etc/group /etc/gshadow"
	before := vm.MustRun(t, groupsState)
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "changes the groups of the login user admin") {
		t.Fatalf("plan: exit %d", r.Code)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "groups: admin: failed: user admin: no new SSH connection works: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if got := vm.MustRun(t, groupsState); got != before {
		t.Errorf("the groups after the rollback:\n%s\nwant\n%s", got, before)
	}

	// A rollback of the recipe's sshd change keeps the groups that the
	// recipe's other steps created and added.
	files["recipes/admin/recipe.yaml"] = `steps:
  - user:
      name: admin
      groups: [admin, wtok]
  - group:
      name: wtnew
  - file:
      path: /etc/ssh/sshd_config.d/port.conf
      content: "Port 2222\n"
    notify: restart
handlers:
  restart:
    - service:
        name: ssh
        restarted: true
      confirm_access: true
`
	dir = vmtest.WriteProject(t, files)
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "no new SSH connection works: ") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply with sshd on port 2222: exit %d", r.Code)
	}
	if got := vm.MustRun(t, "id -nG admin; getent group wtnew | cut -d: -f1; test ! -e /etc/ssh/sshd_config.d/port.conf"); got != "admin wtok\nwtnew\n" {
		t.Errorf("the groups after the rollback of sshd: %q", got)
	}
}

const sshPortRecipe = `vars:
  sshd_ports: [22, 2222]
steps:
  - file:
      path: /etc/ssh/sshd_config.d/port.conf
      content: !tpl "{{ range .vars.sshd_ports }}Port {{ . }}\n{{ end }}"
    notify: restart
handlers:
  restart:
    - service:
        name: ssh
        restarted: true
      confirm_access: true
`

// spec: Running a pipeline/Lockout protection; Modules/service and unit
// (sshd from ssh.socket)
func TestLockoutSSHPort(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "ssh-port")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":               "name: demo\ninventory: test\n",
		"inventories/test.yaml":    "hosts:\n  ssh-port: {}\n",
		"pipelines/site.yaml":      "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: sshd\n",
		"recipes/sshd/recipe.yaml": sshPortRecipe,
	})
	// Ubuntu starts sshd from ssh.socket.
	socket := osRelease().id == "ubuntu"
	if got := vm.MustRun(t, "systemctl is-active ssh.socket || true") == "active\n"; got != socket {
		t.Fatalf("ssh.socket active: %t, want %t", got, socket)
	}
	listens := func(t *testing.T, want string) {
		t.Helper()
		out := vm.MustRun(t, "ss -Hltn")
		var got []string
		for _, port := range []string{"22", "2222"} {
			if strings.Contains(out, ":"+port+" ") {
				got = append(got, port)
			}
		}
		if strings.Join(got, " ") != want {
			t.Errorf("sshd listens on %q, want %q:\n%s", got, want, out)
		}
	}

	// Only the new port: the access check fails, and the old port is back.
	// With ssh.socket, the file step moves the port, and its own access
	// check fails.
	failed := "ssh-port: sshd: failed: handler sshd.restart: service ssh: no new SSH connection works: "
	if socket {
		failed = "ssh-port: sshd: failed: file /etc/ssh/sshd_config.d/port.conf: no new SSH connection works: "
	}
	r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.sshd_ports=[2222]")
	if r.Code != 1 || !strings.Contains(r.Stderr, failed) ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply with only port 2222: exit %d", r.Code)
	}
	vm.MustRun(t, "test ! -e /etc/ssh/sshd_config.d/port.conf")
	listens(t, "22")

	// Both ports: sshd listens on the new port too.
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || socket != strings.Contains(r.Stdout, "daemon-reload\n          restart ssh.socket\n") ||
		socket != strings.Contains(r.Stdout, "changes the ports of ssh.socket, which winch connects to\n") {
		t.Errorf("plan: exit %d; ssh.socket active: %t", r.Code, socket)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply with both ports: exit %d", r.Code)
	}
	listens(t, "22 2222")
	if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d", r.Code)
	}

	if !socket {
		return
	}
	// A port that another program holds: the restart of ssh.socket fails,
	// and the rollback brings back the old ports.
	vm.MustRun(t, "setsid -f python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\"0.0.0.0\", 2223)); s.listen(); time.sleep(600)' >/dev/null 2>&1 </dev/null; sleep 1")
	r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.sshd_ports=[22, 2223]")
	if r.Code != 1 || !strings.Contains(r.Stderr, "ssh-port: sshd: failed: file /etc/ssh/sshd_config.d/port.conf: systemctl restart: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") {
		t.Fatalf("apply with a taken port: exit %d", r.Code)
	}
	listens(t, "22 2222")
}
