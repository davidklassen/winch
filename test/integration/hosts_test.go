package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Remote execution/Facts; Templates and expressions/Data; Running a pipeline/Plan
func TestOtherHostFacts(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "hosts")
	backup := lab.StartVM(t, "hosts-backup")

	// The VMs come from one image; a key of its own tells the hosts apart.
	backup.MustRun(t, "ssh-keygen -q -t ed25519 -N '' -C test -f /tmp/k && cp /tmp/k.pub /etc/ssh/ssh_host_ed25519_key.pub")
	vm.MustRun(t, "mkdir -p -m 700 /root/.ssh && touch /root/.ssh/known_hosts")
	key := strings.TrimSpace(backup.MustRun(t, "cut -d ' ' -f 1,2 /etc/ssh/ssh_host_ed25519_key.pub"))
	own := strings.TrimSpace(vm.MustRun(t, "cut -d ' ' -f 1,2 /etc/ssh/ssh_host_ed25519_key.pub"))
	ipv4 := strings.TrimSpace(vm.MustRun(t, `ip -4 -o addr show dev "$(ip -4 route show default | awk '{print $5; exit}')" | awk '{print $4; exit}' | cut -d / -f 1`))
	if ipv4 == "" {
		t.Fatal("the VM has no address on the device of its default route")
	}

	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  hosts: {}\n  hosts-backup: {}\n",
		"pipelines/site.yaml": `stages:
  - name: site
    hosts: all
    steps:
      - file:
          path: /etc/winch-facts
          content: !tpl "{{ facts.ssh.ed25519 }}\n{{ facts.net.ipv4 }}\n"
      - line:
          path: /root/.ssh/known_hosts
          match: '^hosts-backup '
          line: !tpl 'hosts-backup {{ match("hosts-backup")[0].facts.ssh.ed25519 }}'
`,
	})

	r := lab.Winch(t, dir, "plan", "site", "--hosts", "hosts")
	if r.Code != 0 || !strings.Contains(r.Stdout, "+hosts-backup "+key+"\n") {
		t.Fatalf("plan: exit %d, want 0 and the line with the key of hosts-backup", r.Code)
	}
	r = lab.Winch(t, dir, "apply", "site", "--hosts", "hosts", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "cat /etc/winch-facts"); out != own+"\n"+ipv4+"\n" {
		t.Errorf("/etc/winch-facts = %q, want the host key %q and the address %q", out, own, ipv4)
	}
	if out := vm.MustRun(t, "cat /root/.ssh/known_hosts"); out != "hosts-backup "+key+"\n" {
		t.Errorf("known_hosts = %q, want the key of hosts-backup %q", out, key)
	}
	if out := backup.MustRun(t, "ls /etc/winch-facts 2>&1 || true"); !strings.Contains(out, "No such file") {
		t.Errorf("hosts-backup has /etc/winch-facts: %q", out)
	}
}
