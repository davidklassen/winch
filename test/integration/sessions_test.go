package integration

import (
	"strconv"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Remote execution/Sessions ("plan and apply each make one handshake
// per host")
func TestOneHandshakePerHost(t *testing.T) {
	t.Parallel()
	vms := []*vmtest.VM{lab.StartVM(t, "sess-a"), lab.StartVM(t, "sess-b")}
	// winch logs in as root, so the admin logins of the test do not count.
	for _, vm := range vms {
		vm.MustRun(t, "cp /home/admin/.ssh/authorized_keys /root/.ssh/authorized_keys")
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: sess\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  sess-a:\n    user: root\n  sess-b:\n    user: root\n",
		"pipelines/site.yaml": `stages:
  - name: one
    hosts: all
    steps:
      - file:
          path: /root/one
          content: "x\n"
  - name: two
    hosts: all
    steps:
      - file:
          path: /root/two
          content: "x\n"
  - name: three
    hosts: all
    steps:
      - file:
          path: /root/three
          content: "x\n"
`,
	})
	logins := func(vm *vmtest.VM) int {
		t.Helper()
		out := vm.MustRun(t, "journalctl -q -o cat -u ssh | grep -c 'Accepted publickey for root' || true")
		n, err := strconv.Atoi(strings.TrimSpace(out))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := []int{logins(vms[0]), logins(vms[1])}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	for i, vm := range vms {
		if n := logins(vm) - before[i]; n != 2 {
			t.Errorf("%s: %d handshakes, want 2: one in plan, one in apply", vm.Name, n)
		}
	}
}
