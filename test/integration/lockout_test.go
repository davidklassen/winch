package integration

import (
	"archive/tar"
	"slices"
	"strings"
	"syscall"
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
  - service:
      name: nftables
      enabled: true
      running: true
    confirm_access: true
  - service:
      name: nftables
      reloaded: true
    on_change: [/etc/nftables.conf]
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
		tcp dport { {{ join(map(vars.nftables_tcp_ports, string(#)), ", ") }} } accept
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
	if r.Code != 1 || !strings.Contains(r.Stderr, "firewall: nftables: failed: service nftables: the access check failed: ") ||
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

// spec: Running a pipeline/Lockout protection (a step saves each path that
// it changes in the store of each later guarded step that reacts to it)
func TestLockoutStoreOfALaterRecipe(t *testing.T) {
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
        		{{ if vars.ssh_drop }}ct state new tcp dport 22 drop{{ end }}
        	}
        }
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
  - service:
      name: nftables
      enabled: true
      running: true
  - service:
      name: nftables
      reloaded: true
    on_change: [/etc/nftables-ssh.nft, /etc/nftables.conf]
    confirm_access: true
`,
	})
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply with SSH open: exit %d", r.Code)
	}
	good := vm.MustRun(t, "cat /etc/nftables-ssh.nft")

	r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.ssh_drop=true")
	if r.Code != 1 || !strings.Contains(r.Stderr, "notified-store: nftables: failed: service nftables: the access check failed: ") ||
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
	if r.Code != 1 || !strings.Contains(r.Stderr, "keys: base: failed: user admin: the access check failed: ") ||
		!strings.Contains(r.Stderr, "cannot log in after this change: ") || !strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
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
	if r.Code != 1 || !strings.Contains(r.Stderr, "groups: admin: failed: user admin: the access check failed: ") ||
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
  - service:
      name: ssh
      restarted: true
    on_change: [/etc/ssh/sshd_config.d/port.conf]
    confirm_access: true
`
	dir = vmtest.WriteProject(t, files)
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "the access check failed: ") || strings.Contains(r.Stderr, "the rollback failed") {
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
      content: !tpl "{{ for port in vars.sshd_ports }}Port {{ port }}\n{{ end }}"
  - service:
      name: ssh
      restarted: true
    on_change: [/etc/ssh/sshd_config.d/port.conf]
    confirm_access: true
`

// spec: Running a pipeline/Lockout protection (a guarded reload of sshd puts
// back the sshd config of other recipes)
func TestLockoutSSHDConfigOfAnotherRecipe(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "sshd-other-recipe")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  sshd-other-recipe: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: hardening\n      - recipe: ssh\n",
		"recipes/hardening/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/sshd_config.d/00-deny.conf
      content: "DenyUsers *\n"
`,
		"recipes/ssh/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/sshd_config.d/local.conf
      content: "MaxAuthTries 6\n"
  - service:
      name: ssh
      reloaded: true
    on_change: [/etc/ssh/sshd_config.d/local.conf]
    confirm_access: true
`,
	})
	// With ssh.socket, the drop-in step restarts it, and its own access check
	// fails.
	failed := "sshd-other-recipe: ssh: failed: service ssh: the access check failed: "
	if osRelease().id == "ubuntu" {
		failed = "sshd-other-recipe: hardening: failed: file /etc/ssh/sshd_config.d/00-deny.conf: the access check failed: "
	}
	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, failed) ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply with DenyUsers: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "ls /etc/ssh/sshd_config.d"); strings.Contains(out, "00-deny.conf") {
		t.Errorf("the drop-in stays after the rollback:\n%s", out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "file /etc/ssh/sshd_config.d/00-deny.conf") {
		t.Errorf("plan after the rollback: exit %d, want the change again", r.Code)
	}
}

// spec: Running a pipeline/Lockout protection (the run of a host ends before
// a guarded sshd reload that holds saved sshd files ran)
func TestLockoutSSHDConfigBeforeAReload(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "sshd-before-reload")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\nvars:\n  tries: 6\n  fail: false\n  sleep: 0\n",
		"inventories/test.yaml": "hosts:\n  sshd-before-reload: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - recipe: hardening
      - name: Fails on request
        cmd:
          command: exit 3
        when: !expr vars.fail
      - cmd:
          command: !tpl "sleep {{ vars.sleep }}"
      - recipe: ssh
`,
		"recipes/hardening/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/sshd_config.d/hardening.conf
      content: !tpl "MaxAuthTries {{ vars.tries }}\n"
`,
		"recipes/ssh/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/winch-tries
      content: !tpl "{{ vars.tries }}\n"
  - service:
      name: ssh
      reloaded: true
    on_change: [/etc/ssh/winch-tries]
    confirm_access: true
`,
	})
	const conf = "cat /etc/ssh/sshd_config.d/hardening.conf"
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("first apply: exit %d\n%s", r.Code, r.Stderr)
	}

	t.Run("a failed step puts back the drop-in", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.tries=7", "--set", "vars.fail=true")
		if r.Code != 1 || !strings.Contains(r.Stderr, "Fails on request") {
			t.Fatalf("apply: exit %d, want the failed step\n%s", r.Code, r.Stderr)
		}
		if out := vm.MustRun(t, conf); out != "MaxAuthTries 6\n" {
			t.Errorf("drop-in after the failed run: %q, want the old file", out)
		}
	})

	t.Run("Ctrl-C puts back the drop-in", func(t *testing.T) {
		w := startWinch(t, dir, "apply", "site", "--yes", "--set", "vars.tries=8", "--set", "vars.sleep=10")
		vm.MustRun(t, `timeout 60 sh -c 'until grep -qx "MaxAuthTries 8" /etc/ssh/sshd_config.d/hardening.conf; do sleep 0.2; done'`)
		w.signal(t, syscall.SIGINT)
		if code := w.wait(t); code == 0 {
			t.Fatal("apply: exit 0 after Ctrl-C")
		}
		vm.MustRun(t, `timeout 60 sh -c 'until flock -n /var/lib/winch/lock true; do sleep 0.5; done'`)
		if out := vm.MustRun(t, conf); out != "MaxAuthTries 6\n" {
			t.Errorf("drop-in after Ctrl-C: %q, want the old file", out)
		}
	})
}

// spec: Running a pipeline/Lockout protection; Modules/service and unit
// (sshd from ssh.socket; move sshd to a new port in three runs)
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
	failed := "ssh-port: sshd: failed: service ssh: the access check failed: "
	if socket {
		failed = "ssh-port: sshd: failed: file /etc/ssh/sshd_config.d/port.conf: the access check failed: "
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

	if socket {
		// A port that another program holds: the restart of ssh.socket
		// fails, and the rollback brings back the old ports.
		vm.MustRun(t, "setsid -f python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\"0.0.0.0\", 2223)); s.listen(); time.sleep(600)' >/dev/null 2>&1 </dev/null; sleep 1")
		r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.sshd_ports=[22, 2223]")
		if r.Code != 1 || !strings.Contains(r.Stderr, "ssh-port: sshd: failed: file /etc/ssh/sshd_config.d/port.conf: systemctl restart: ") ||
			!strings.HasSuffix(r.Stderr, "; the old files are back\n") {
			t.Fatalf("apply with a taken port: exit %d", r.Code)
		}
		listens(t, "22 2222")
	}

	// The SSH config names the new port: the old port goes.
	if err := vm.UsePort(2222); err != nil {
		t.Fatal(err)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.sshd_ports=[2222]"); r.Code != 0 {
		t.Fatalf("apply with only port 2222: exit %d", r.Code)
	}
	listens(t, "2222")
	if r := lab.Winch(t, dir, "plan", "site", "--set", "vars.sshd_ports=[2222]"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after the move: exit %d", r.Code)
	}
}

const sshSwitchRecipe = `steps:
  - dir:
      path: /etc/systemd/system/ssh.socket.d
  - file:
      path: /etc/systemd/system/ssh.socket.d/port.conf
      content: "[Socket]\nListenStream=\nListenStream=2299\n"
  - service:
      name: ssh
      running: false
      enabled: false
  - service:
      name: ssh.socket
      running: true
      enabled: true
    confirm_access: true
`

// spec: Running a pipeline/Lockout protection (the rollback of a switch
// between ssh.service and ssh.socket)
func TestLockoutSSHSwitch(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "ssh-switch")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":              "name: demo\ninventory: test\n",
		"inventories/test.yaml":   "hosts:\n  ssh-switch: {}\n",
		"pipelines/boot.yaml":     "stages:\n  - name: boot\n    hosts: all\n    steps:\n      - reboot:\n          if_required: false\n",
		"pipelines/site.yaml":     "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: ssh\n",
		"recipes/ssh/recipe.yaml": sshSwitchRecipe,
	})
	// Ubuntu starts sshd from ssh.socket: the test starts from ssh.service.
	// A stop of ssh.socket leaves the sshd that it started outside of
	// ssh.service, so the change of the units needs a reboot.
	if osRelease().id == "ubuntu" {
		vm.MustRun(t, "systemctl disable -q ssh.socket && systemctl enable -q ssh")
		if r := lab.Winch(t, dir, "apply", "boot", "--yes"); r.Code != 0 {
			t.Fatalf("apply of the reboot: exit %d", r.Code)
		}
	}

	// ssh.socket listens on a port that winch does not connect to: the access
	// check fails, and ssh.service runs again.
	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "ssh-switch: ssh: failed: service ssh.socket: the access check failed: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply: exit %d", r.Code)
	}
	// The rollback keeps ssh.socket enabled, and it can run beside ssh.service.
	want := "active\nenabled\n"
	if got := vm.MustRun(t, "systemctl is-active ssh; systemctl is-enabled ssh; test ! -e /etc/systemd/system/ssh.socket.d"); got != want {
		t.Errorf("ssh.service after the rollback = %q, want %q", got, want)
	}
}

// spec: Running a pipeline/Lockout protection (a drop-in of ssh.socket is
// sshd's config)
func TestLockoutSSHSocketDropIn(t *testing.T) {
	t.Parallel()
	if osRelease().id != "ubuntu" {
		t.Skip("Debian starts sshd from ssh.service")
	}
	vm := lab.StartVM(t, "ssh-socket-drop-in")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  ssh-socket-drop-in: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: ssh\n",
		"recipes/ssh/recipe.yaml": `steps:
  - dir:
      path: /etc/systemd/system/ssh.socket.d
  - file:
      path: /etc/systemd/system/ssh.socket.d/port.conf
      content: "[Socket]\nListenStream=\nListenStream=2222\n"
  - service:
      name: ssh.socket
      restarted: true
    on_change: [/etc/systemd/system/ssh.socket.d]
`,
	})
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "+ file /etc/systemd/system/ssh.socket.d/port.conf\n          changes the ports of ssh.socket, which winch connects to\n") {
		t.Errorf("plan: exit %d, want the ports line at the file step", r.Code)
	}
	// The file step restarts ssh.socket on the new port, and its own access
	// check fails.
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "ssh-socket-drop-in: ssh: failed: file /etc/systemd/system/ssh.socket.d/port.conf: the access check failed: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply: exit %d", r.Code)
	}
	vm.MustRun(t, "test ! -e /etc/systemd/system/ssh.socket.d/port.conf")
	if out := vm.MustRun(t, "ss -Hltn"); !strings.Contains(out, ":22 ") || strings.Contains(out, ":2222 ") {
		t.Errorf("ssh.socket after the rollback listens on:\n%s", out)
	}
}

const sshNoteSteps = `  - name: root
    line:
      path: /etc/ssh/sshd_config
      match: "^#?PermitRootLogin "
      line: PermitRootLogin no
  - name: port
    line:
      path: /etc/ssh/sshd_config
      match: "^#?Port "
      line: Port 2222
  - name: drop-in
    file:
      path: /etc/ssh/sshd_config.d/winch.conf
      content: "PasswordAuthentication no\n"
`

// spec: Running a pipeline/Lockout protection (ssh.socket: the plan line of a
// change of sshd's config)
func TestLockoutSSHSocketNote(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "ssh-note")
	dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": "name: demo\nhosts:\n  ssh-note: {}\nsteps:\n" + sshNoteSteps})
	socket := osRelease().id == "ubuntu"
	if got := vm.MustRun(t, "systemctl is-active ssh.socket || true") == "active\n"; got != socket {
		t.Fatalf("ssh.socket active: %t, want %t", got, socket)
	}
	// A restart of ssh.socket under the access check tests the new config.
	var warnings []string
	if !socket {
		for _, at := range []string{"5:5", "10:5", "15:5"} {
			warnings = append(warnings, "winch.yaml:"+at+": warning: sshd's config changes, and no step reloads sshd with confirm_access: true; the new config loads untested at the next restart")
		}
	}
	r := lab.WinchEnvWarnings(t, dir, nil, warnings, "plan")
	if r.Code != 0 {
		t.Fatalf("plan: exit %d", r.Code)
	}
	for _, c := range []struct{ step, note string }{
		{"root: line /etc/ssh/sshd_config", "restarts ssh.socket, which winch connects to"},
		{"port: line /etc/ssh/sshd_config", "changes the ports of ssh.socket, which winch connects to"},
		{"drop-in: file /etc/ssh/sshd_config.d/winch.conf", "restarts ssh.socket, which winch connects to"},
	} {
		_, after, ok := strings.Cut(r.Stdout, c.step+"\n")
		if !ok {
			t.Fatalf("plan has no step %q:\n%s", c.step, r.Stdout)
		}
		// The lines of a step are indented more than the headers.
		var got []string
		for line := range strings.Lines(after) {
			if !strings.HasPrefix(line, "      ") {
				break
			}
			got = append(got, strings.TrimSpace(line))
		}
		restarts := slices.Contains(got, "daemon-reload") && slices.Contains(got, "restart ssh.socket")
		if len(got) == 0 || socket && (got[0] != c.note || !restarts) || !socket && strings.Contains(strings.Join(got, "\n"), "ssh.socket") {
			t.Errorf("plan lines of %q = %q; ssh.socket active: %t, want %q first and the restart of ssh.socket", c.step, got, socket, c.note)
		}
	}
}

const rollbackStartPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/winch-rb.conf
          content: !tpl "{{ vars.conf }}\n"
      - service:
          name: winch-rb
          restarted: true
        on_change: [/etc/winch-rb.conf]
        confirm_access: true
`

// spec: Running a pipeline/Lockout protection (the rollback reverses a
// restart; a rollback that fails)
func TestLockoutRollbackStart(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "rollback-start")
	vm.MustRun(t, `printf '[Service]\nExecStartPre=/bin/sh -c "test -e /run/winch-rb && grep -qx ok /etc/winch-rb.conf"\nExecStart=/bin/sleep infinity\n' > /etc/systemd/system/winch-rb.service && echo ok > /etc/winch-rb.conf && touch /run/winch-rb && systemctl daemon-reload && systemctl start winch-rb`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\nvars:\n  conf: ok\n",
		"inventories/test.yaml": "hosts:\n  rollback-start: {}\n",
		"pipelines/site.yaml":   rollbackStartPipeline,
	})

	// The restart fails; the rollback puts back the file and starts the unit.
	r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.conf=bad")
	if r.Code != 1 || !strings.Contains(r.Stderr, "service winch-rb: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply with a bad config: exit %d", r.Code)
	}
	if got := vm.MustRun(t, "cat /etc/winch-rb.conf; systemctl is-active winch-rb || true"); got != "ok\nactive\n" {
		t.Errorf("config and state after the rollback = %q, want %q", got, "ok\nactive\n")
	}

	// The start of the rollback fails too: the error says so.
	vm.MustRun(t, "rm /run/winch-rb")
	r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.conf=bad")
	if r.Code != 1 || !strings.Contains(r.Stderr, "; the rollback failed: service winch-rb: ") || strings.Contains(r.Stderr, "the old files are back") {
		t.Fatalf("apply with a bad config and a unit that cannot start: exit %d", r.Code)
	}
	if got := vm.MustRun(t, "cat /etc/winch-rb.conf"); got != "ok\n" {
		t.Errorf("config after the rollback = %q, want %q", got, "ok\n")
	}

	// A oneshot unit that runs its job is up, but no start keeps it running:
	// the undo only restarts it.
	vm.MustRun(t, `printf '[Service]\nType=oneshot\nExecStartPre=/bin/sh -c "grep -qx ok /etc/winch-rb.conf"\nExecStart=/bin/sleep 600\n' > /etc/systemd/system/winch-rb.service && touch /run/winch-rb && systemctl daemon-reload && systemctl reset-failed winch-rb; systemctl start --no-block winch-rb && timeout 10 sh -c 'until systemctl show -P SubState winch-rb | grep -qx start; do sleep 0.1; done'`)
	r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.conf=bad")
	if r.Code != 1 || !strings.Contains(r.Stderr, "service winch-rb: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply with a bad config on a oneshot unit: exit %d", r.Code)
	}
}

const failedRollbackPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/winch-frb.conf
          content: !tpl "{{ vars.conf }}\n"
      - service:
          name: winch-frb
          running: true
        on_change: [/etc/winch-frb.conf]
        confirm_access: true
      - cmd:
          command: echo done >> /root/frb-done
        on_change: [/etc/winch-frb.conf]
`

// spec: Running a pipeline/Lockout protection (when a rollback fails, the
// records of the steps that react to the changes stay)
func TestLockoutFailedRollbackKeepsTheRecords(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "failed-rollback")
	// A start with a bad config makes the config immutable, so the rollback
	// cannot put back the old file.
	vm.MustRun(t, `printf '[Service]\nExecStartPre=/bin/sh -c "grep -qx ok /etc/winch-frb.conf || { chattr +i /etc/winch-frb.conf; exit 1; }"\nExecStart=/bin/sleep infinity\n' > /etc/systemd/system/winch-frb.service && echo ok > /etc/winch-frb.conf && systemctl daemon-reload`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\nvars:\n  conf: ok\n",
		"inventories/test.yaml": "hosts:\n  failed-rollback: {}\n",
		"pipelines/site.yaml":   failedRollbackPipeline,
	})

	r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.conf=bad")
	if r.Code != 1 || !strings.Contains(r.Stderr, "service winch-frb: ") || !strings.Contains(r.Stderr, "; the rollback failed: ") {
		t.Fatalf("apply with a bad config: exit %d, want the failed rollback\n%s", r.Code, r.Stderr)
	}
	if got := vm.MustRun(t, "cat /etc/winch-frb.conf"); got != "bad\n" {
		t.Fatalf("config after the failed rollback = %q, want the new file", got)
	}
	// With the config fixed by hand, only the records show in the plan.
	vm.MustRun(t, "chattr -i /etc/winch-frb.conf && echo ok > /etc/winch-frb.conf && systemctl start winch-frb")
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || strings.Contains(r.Stdout, "~ service") {
		t.Errorf("plan after the fix by hand: exit %d, want only the records\n%s", r.Code, r.Stdout)
	}
	for _, want := range []string{"! service winch-frb (pending from an earlier run)\n", "! cmd echo done >> /root/frb-done (pending from an earlier run)\n"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("plan after the failed rollback: want %q\n%s", want, r.Stdout)
		}
	}
}

const pendingConfirmPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/ssh/sshd_config.d/winch.conf
          content: !tpl "MaxAuthTries {{ vars.tries }}\n"
        then: !expr vars.wait
      - name: Fails on request
        cmd:
          command: exit 3
        when: !expr vars.fail
      - reboot:
          if_required: true
          timeout: 300
      - name: Fails after the reboot on request
        cmd:
          command: exit 4
        when: !expr vars.fail_late
      - service:
          name: ssh
          reloaded: true
        on_change: [/etc/ssh/sshd_config.d/winch.conf]
        confirm_access: true
`

// spec: Running a pipeline/Lockout protection (the run of a host ends before
// a guarded step that reacts to a change of the run ran)
func TestLockoutPendingGuardedStep(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pending-confirm")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: pdemo\ninventory: test\nvars:\n  tries: 6\n  wait: \"true\"\n  fail: false\n  fail_late: false\n",
		"inventories/test.yaml": "hosts:\n  pending-confirm: {}\n",
		"pipelines/site.yaml":   pendingConfirmPipeline,
	})
	const conf = "cat /etc/ssh/sshd_config.d/winch.conf"
	// records are the records of the reload of ssh.
	const records = "grep -F '\"module\":\"service\"' /var/lib/winch/react/pdemo 2>/dev/null; true"
	// The reboot loads a drop-in that no access check tested. On Ubuntu, the
	// step's restart of ssh.socket tests it.
	var warnings []string
	if osRelease().id != "ubuntu" {
		warnings = []string{"pipelines/site.yaml:13:9: warning: sshd loads a changed config without an access check; reload it in a service step with on_change and confirm_access: true"}
	}
	if r := lab.WinchEnvWarnings(t, dir, nil, warnings, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("first apply: exit %d\n%s", r.Code, r.Stderr)
	}

	t.Run("a failed step puts back the file", func(t *testing.T) {
		r := lab.WinchEnvWarnings(t, dir, nil, warnings, "apply", "site", "--yes", "--set", "vars.tries=7", "--set", "vars.fail=true")
		if r.Code != 1 || !strings.Contains(r.Stderr, "Fails on request") {
			t.Fatalf("apply: exit %d, want the failed step\n%s", r.Code, r.Stderr)
		}
		if out := vm.MustRun(t, conf); out != "MaxAuthTries 6\n" {
			t.Errorf("sshd config after the failed run: %q, want the old file", out)
		}
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records of the reload = %q, want none", out)
		}
		r = lab.WinchEnvWarnings(t, dir, nil, warnings, "plan", "site", "--set", "vars.tries=7")
		if r.Code != 0 || !strings.Contains(r.Stdout, "~ file /etc/ssh/sshd_config.d/winch.conf") {
			t.Errorf("plan after the failed run: exit %d, want the change again\n%s", r.Code, r.Stdout)
		}
	})

	t.Run("a broken session puts back the file", func(t *testing.T) {
		w := startWinch(t, dir, "apply", "site", "--yes", "--set", "vars.tries=8", "--set", "vars.wait=sleep 10")
		vm.MustRun(t, `timeout 60 sh -c 'until grep -qF "\"module\":\"service\"" /var/lib/winch/react/pdemo 2>/dev/null && grep -qx "MaxAuthTries 8" /etc/ssh/sshd_config.d/winch.conf; do sleep 0.2; done'`)
		// The kill reaches ssh too, so the connection drops.
		if err := syscall.Kill(-w.cmd.Process.Pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		<-w.done
		// The helper ends after the command of then.
		vm.MustRun(t, `timeout 60 sh -c 'until flock -n /var/lib/winch/lock true; do sleep 0.5; done'`)
		if out := vm.MustRun(t, conf); out != "MaxAuthTries 6\n" {
			t.Errorf("sshd config after the broken session: %q, want the old file", out)
		}
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records of the reload = %q, want none", out)
		}
	})

	t.Run("the commands of the helper do not ignore SIGPIPE", func(t *testing.T) {
		// SIGPIPE is signal 13: bit 0x1000 of the mask.
		r := lab.Winch(t, dir, "exec", "all", "--", "grep SigIgn /proc/self/status")
		if r.Code != 0 || !strings.HasSuffix(strings.TrimSpace(r.Stdout), "SigIgn:\t0000000000000000") {
			t.Errorf("exec: exit %d, want no ignored signal\n%s", r.Code, r.Stdout)
		}
	})

	t.Run("a failed step after a reboot puts back the file", func(t *testing.T) {
		vm.MustRun(t, "touch /run/reboot-required")
		r := lab.WinchEnvWarnings(t, dir, nil, warnings, "apply", "site", "--yes", "--set", "vars.tries=10", "--set", "vars.fail_late=true")
		if r.Code != 1 || !strings.Contains(r.Stderr, "Fails after the reboot on request") {
			t.Fatalf("apply: exit %d, want the failed step\n%s", r.Code, r.Stderr)
		}
		if out := vm.MustRun(t, conf); out != "MaxAuthTries 6\n" {
			t.Errorf("sshd config after the failed run: %q, want the old file", out)
		}
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records of the reload = %q, want none", out)
		}
	})

	t.Run("a reboot keeps the file for the reload", func(t *testing.T) {
		vm.MustRun(t, "touch /run/reboot-required")
		r := lab.WinchEnvWarnings(t, dir, nil, warnings, "apply", "site", "--yes", "--set", "vars.tries=9")
		if r.Code != 0 || !strings.Contains(r.Stdout, "base: ~ service ssh") {
			t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, conf); out != "MaxAuthTries 9\n" {
			t.Errorf("sshd config after the reboot: %q, want the new file", out)
		}
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records of the reload = %q, want none", out)
		}
	})
}

// spec: Running a pipeline/Lockout protection; Modules/download (the
// rollback puts back the old tree of an unpack, and the next plan unpacks
// again)
func TestLockoutPendingGuardedStepUnpack(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pending-unpack")
	v1 := tarGz(t, []entry{{name: "bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho v1\n"}})
	v2 := tarGz(t, []entry{{name: "bin/tool", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho v2\n"}})
	url1 := lab.Serve(t, "pending-unpack/v1.tar.gz", v1)
	url2 := lab.Serve(t, "pending-unpack/v2.tar.gz", v2)
	project := func(url, sum string) string {
		return vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: udemo\ninventory: test\nvars:\n  fail: false\n",
			"inventories/test.yaml": "hosts:\n  pending-unpack: {}\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - download:
          url: ` + url + `
          sha256: ` + sum + `
          unpack: /opt/winch-test/app
      - name: Fails on request
        cmd:
          command: exit 3
        when: !expr vars.fail
      - service:
          name: ssh
          reloaded: true
        on_change: [/opt/winch-test/app]
        confirm_access: true
`,
		})
	}
	if r := lab.Winch(t, project(url1, sha(v1)), "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("first apply: exit %d\n%s", r.Code, r.Stderr)
	}
	dir := project(url2, sha(v2))
	r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.fail=true")
	if r.Code != 1 || !strings.Contains(r.Stderr, "Fails on request") {
		t.Fatalf("apply: exit %d, want the failed step\n%s", r.Code, r.Stderr)
	}
	if out := vm.MustRun(t, "/opt/winch-test/app/bin/tool"); out != "v1\n" {
		t.Errorf("tool after the failed run: %q, want the old tree", out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ download /opt/winch-test/app") {
		t.Errorf("plan after the failed run: exit %d, want the unpack again\n%s", r.Code, r.Stdout)
	}
}

// spec: Running a pipeline/Lockout protection (a change of /etc/pam.d)
func TestLockoutPAM(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pam")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  pam: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/pam.d/common-account
          content: "account requisite pam_deny.so\n"
`,
	})
	before := vm.MustRun(t, "stat -c '%U %G %a' /etc/pam.d/common-account; cat /etc/pam.d/common-account")
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "changes the PAM rules, which every login reads") {
		t.Fatalf("plan: exit %d", r.Code)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "pam: base: failed: file /etc/pam.d/common-account: the access check failed: ") ||
		!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if got := vm.MustRun(t, "stat -c '%U %G %a' /etc/pam.d/common-account; cat /etc/pam.d/common-account"); got != before {
		t.Errorf("common-account after the rollback:\n%s\nwant\n%s", got, before)
	}
}

// spec: Modules/cmd (changes); Running a pipeline/Lockout protection (a cmd
// whose changes names /etc/pam.d)
func TestLockoutCmdChanges(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pam-cmd")
	project := func(command, changes string) string {
		return vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  pam-cmd: {}\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - cmd:
          command: ` + command + changes + "\n",
		})
	}
	breaks := "mkdir /etc/winch-test; touch /etc/pam.d/winch-test; echo 'account requisite pam_deny.so' > /etc/pam.d/common-account"
	state := "find /etc/pam.d /etc/winch-test -printf '%p %y %u %g %m\\n' 2>&1 | sort; find /etc/pam.d -type f -exec sha256sum {} + | sort"
	before := vm.MustRun(t, state)
	for _, tt := range []struct{ name, command, want string }{
		{"the command passes", breaks, "/etc/pam.d/common-account: the access check failed: "},
		{"the command fails", breaks + "; exit 3", "exit status 3; the access check failed: "},
		// The command outlasts the 60 seconds of the rollback timer.
		{"a long command", "sleep 90; " + breaks, "/etc/pam.d/common-account: the access check failed: "},
	} {
		dir := project(tt.command, "\n          changes: [/etc/pam.d, /etc/winch-test]")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "changes the PAM rules, which every login reads") {
			t.Fatalf("%s: plan: exit %d\n%s", tt.name, r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 1 || !strings.Contains(r.Stderr, "pam-cmd: base: failed: cmd ") || !strings.Contains(r.Stderr, tt.want) ||
			!strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
			t.Fatalf("%s: apply: exit %d\n%s", tt.name, r.Code, r.Stderr)
		}
		if got := vm.MustRun(t, state); got != before {
			t.Errorf("%s: /etc/pam.d after the rollback:\n%s\nwant\n%s", tt.name, got, before)
		}
	}

	r := lab.Winch(t, project(breaks, ""), "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "pam-cmd: the access check after the run failed: ") || strings.Contains(r.Stderr, "pam-cmd: base: failed:") {
		t.Errorf("without changes: apply: exit %d\n%s", r.Code, r.Stderr)
	}
}

// spec: Running a pipeline/Lockout protection (the access check after the
// run)
func TestLockoutAfterRun(t *testing.T) {
	t.Parallel()
	lab.StartVM(t, "after-run")
	// The then drops new SSH connections and keeps the session. The timeout
	// of the set element lets the VM answer again after 60 seconds.
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  after-run: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - pkg:
          name: nftables
      - file:
          path: /etc/motd
          content: "hi\n"
        then: |
          nft add table inet block
          nft add set inet block ssh '{ type inet_service; timeout 60s; elements = { 22 }; }'
          nft add chain inet block input '{ type filter hook input priority -10; }'
          nft add rule inet block input tcp dport @ssh ct state new drop
`,
	})
	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "after-run: the access check after the run failed: ") {
		t.Errorf("apply: exit %d", r.Code)
	}
}

// spec: Running a pipeline/Lockout protection (a step that removes the SSH
// server, sudo, or the login shell)
func TestLockoutPackages(t *testing.T) {
	t.Parallel()
	vm := upgradeVM(t, "lockout-pkgs")
	// winch-shell ships a copy of bash in /usr/bin; the login shell of admin
	// is its path in /bin.
	vm.MustRun(t, installV1("winch-up-nossh")+` && mkdir -p /root/debs/winch-shell/DEBIAN /root/debs/winch-shell/usr/bin &&
printf 'Package: winch-shell\nVersion: 1\nArchitecture: all\nMaintainer: winch\nDescription: test\n' > /root/debs/winch-shell/DEBIAN/control &&
cp /usr/bin/bash /root/debs/winch-shell/usr/bin/winch-sh && dpkg-deb -b /root/debs/winch-shell /root/debs/winch-shell.deb >/dev/null && `+installV1("winch-shell"))
	// On Ubuntu 26.04 sudo is sudo-rs, through an alternative.
	sudo := strings.TrimSpace(vm.MustRun(t, "dpkg -S $(readlink -f /usr/bin/sudo) | cut -d: -f1"))
	stage := func(step string) string { return "stages:\n  - name: base\n    hosts: all\n    steps:\n" + step }
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":             "name: demo\ninventory: test\n",
		"inventories/test.yaml":  "hosts:\n  lockout-pkgs: {}\n",
		"pipelines/upgrade.yaml": stage("      - upgrade:\n          mode: full\n"),
		"pipelines/sudo.yaml":    stage("      - pkg:\n          name: " + sudo + "\n          absent: true\n"),
		"pipelines/sftp.yaml":    stage("      - pkg:\n          name: openssh-sftp-server\n          absent: true\n"),
		"pipelines/shell.yaml":   stage("      - pkg:\n          name: winch-shell\n          absent: true\n"),
		"pipelines/other.yaml":   stage("      - pkg:\n          name: winch-up-nossh\n          absent: true\n"),
	})
	for _, c := range []struct{ pipeline, want string }{
		{"upgrade", "lockout-pkgs: base: upgrade full: this cuts off winch's access"},
		{"sudo", "lockout-pkgs: base: pkg " + sudo + ": this cuts off winch's access"},
		// apt also removes openssh-server, which depends on it.
		{"sftp", "lockout-pkgs: base: pkg openssh-sftp-server: this cuts off winch's access"},
	} {
		if r := lab.Winch(t, dir, "plan", c.pipeline); r.Code != 1 || !strings.Contains(r.Stderr, c.want) {
			t.Errorf("plan %s: exit %d, want the error %q", c.pipeline, r.Code, c.want)
		}
	}
	if r := lab.Winch(t, dir, "plan", "shell"); r.Code != 0 {
		t.Errorf("plan shell before the change of the login shell: exit %d", r.Code)
	}
	vm.MustRun(t, "echo /bin/winch-sh >> /etc/shells && usermod -s /bin/winch-sh admin")
	if r := lab.Winch(t, dir, "plan", "shell"); r.Code != 1 || !strings.Contains(r.Stderr, "lockout-pkgs: base: pkg winch-shell: this cuts off winch's access") {
		t.Errorf("plan shell: exit %d", r.Code)
	}
	if r := lab.Winch(t, dir, "plan", "other"); r.Code != 0 {
		t.Errorf("plan other: exit %d", r.Code)
	}
}

const dueRollbackPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/winch-due.conf
          content: !tpl "{{ vars.conf }}\n"
      - service:
          name: winch-due
          reloaded: true
        on_change: [/etc/winch-due.conf]
        confirm_access: true
`

// spec: Running a pipeline/Lockout protection (a timer whose process is gone
// does not run on its own: the plan shows its rollback as the first change of
// the host, and apply runs it first)
func TestLockoutDueRollback(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "due-rollback")
	vm.MustRun(t, `printf '[Service]\nExecStart=/bin/sleep infinity\nExecReload=/bin/sleep 10\n' > /etc/systemd/system/winch-due.service && echo old > /etc/winch-due.conf && systemctl daemon-reload && systemctl start winch-due`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\nvars:\n  conf: old\n",
		"inventories/test.yaml": "hosts:\n  due-rollback: {}\n",
		"pipelines/site.yaml":   dueRollbackPipeline,
	})
	const job = "/var/lib/winch/rollback/timer.json"

	// The helper and its timer die while the guarded reload runs.
	w := startWinch(t, dir, "apply", "site", "--yes", "--set", "vars.conf=new")
	vm.MustRun(t, "timeout 60 sh -c 'until [ -e "+job+" ]; do sleep 0.1; done' && pkill -KILL -f '^/var/lib/winch/bin/'")
	<-w.done
	if w.err == nil {
		t.Fatal("apply succeeded after the helper died")
	}

	r := lab.Winch(t, dir, "plan", "site")
	want := "due-rollback\n  ! rollback of an earlier run\n      put back /etc/winch-due.conf\n      service winch-due: reload\n  base\n"
	if r.Code != 0 || !strings.HasPrefix(r.Stdout, want) {
		t.Fatalf("plan: exit %d, want it to start with:\n%s\ngot:\n%s%s", r.Code, want, r.Stdout, r.Stderr)
	}
	if got := vm.MustRun(t, "cat /etc/winch-due.conf; ls "+job); got != "new\n"+job+"\n" {
		t.Errorf("after the plan: %q, want the new file and the job", got)
	}

	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 || !strings.HasPrefix(r.Stdout, "due-rollback\n  ! rollback of an earlier run\n") || !strings.Contains(r.Stdout, "\ndue-rollback: ! rollback of an earlier run\n") {
		t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	if got := vm.MustRun(t, "cat /etc/winch-due.conf; ls /var/lib/winch/rollback"); got != "old\ndemo\n" {
		t.Errorf("after the apply: %q, want the old file and no job", got)
	}
	if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after the apply: exit %d\n%s", r.Code, r.Stdout)
	}
}

const putBackPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/ssh/sshd_config.d/winch-pb.conf
          content: !tpl "MaxAuthTries {{ vars.tries }}\n"
      - file:
          path: /etc/winch-pb
          content: !tpl "{{ vars.tries }}\n"
      - name: Fails on request
        cmd:
          command: exit 3
        when: !expr vars.fail
      - service:
          name: ssh
          reloaded: true
        on_change: [/etc/ssh/sshd_config.d/winch-pb.conf]
        confirm_access: true
`

// spec: Running a pipeline/Lockout protection (the store of a guarded step
// holds the paths of the changes it reacts to; the line when it did not run)
func TestLockoutPutBack(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "put-back")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: pbdemo\ninventory: test\nvars:\n  tries: 6\n  fail: false\n",
		"inventories/test.yaml": "hosts:\n  put-back: {}\n",
		"pipelines/site.yaml":   putBackPipeline,
	})
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("first apply: exit %d\n%s", r.Code, r.Stderr)
	}
	r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.tries=7", "--set", "vars.fail=true")
	if r.Code != 1 || !strings.Contains(r.Stdout, "put-back: put back /etc/ssh/sshd_config.d/winch-pb.conf: service ssh did not run\n") {
		t.Fatalf("apply: exit %d, want the put back line\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	// The other file of the run stays: the reload does not react to it.
	if out := vm.MustRun(t, "cat /etc/ssh/sshd_config.d/winch-pb.conf /etc/winch-pb"); out != "MaxAuthTries 6\n7\n" {
		t.Errorf("files after the failed run: %q, want the old drop-in and the new file", out)
	}
	if out := vm.MustRun(t, "sed '/^version 1$/d' /var/lib/winch/react/pbdemo 2>/dev/null; true"); out != "" {
		t.Errorf("records = %q, want none", out)
	}
	r = lab.Winch(t, dir, "plan", "site", "--set", "vars.tries=7")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ file /etc/ssh/sshd_config.d/winch-pb.conf") {
		t.Errorf("plan after the failed run: exit %d, want the change again\n%s", r.Code, r.Stdout)
	}
}
