package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Project layout (ssh_config); Remote execution/Sessions (each hop of a
// ProxyJump gets the same options)
func TestSSHConfigFile(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "sshconfig")
	// Only the file of ssh_config knows the host and its jump host. winch runs
	// the ssh of the system, without the -F of the lab's ssh wrapper.
	config := fmt.Sprintf("Include %s/ssh_config\n"+
		"Host named-hop\n  HostName 127.0.0.1\n  Port %d\n"+
		"Host named named-twin\n  HostName 127.0.0.1\n  Port 22\n  ProxyJump named-hop\n", lab.Dir, vm.HostPort("tcp", 22))
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: sshconfig\ninventory: test\nssh_config: ssh/config\n",
		"ssh/config":            config,
		"inventories/test.yaml": "hosts:\n  named: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /root/named
          content: "x\n"
`,
	})
	path, ok := strings.CutPrefix(lab.PATH, filepath.Join(lab.Dir, "bin")+":")
	if !ok {
		t.Fatalf("the lab's PATH %s does not start with its ssh wrapper", lab.PATH)
	}
	env := []string{"PATH=" + path}
	if r := lab.WinchEnv(t, dir, env, "plan", "site", "--exit-code"); r.Code != 2 {
		t.Errorf("plan: exit %d, want 2 for changes", r.Code)
	}
	if r := lab.WinchEnv(t, dir, env, "apply", "site", "--yes"); r.Code != 0 {
		t.Errorf("apply: exit %d, want 0", r.Code)
	}
	if out := vm.MustRun(t, "cat /root/named"); out != "x\n" {
		t.Errorf("/root/named = %q, want x", out)
	}

	// The check of shared destinations reads the same file.
	if err := os.WriteFile(filepath.Join(dir, "inventories/test.yaml"), []byte("hosts:\n  named: {}\n  named-twin: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := lab.WinchEnv(t, dir, env, "plan", "site"); r.Code != 1 || !strings.Contains(r.Stderr, "host named has the same SSH destination") {
		t.Errorf("plan of two hosts with one destination: exit %d, want 1 and the shared destination", r.Code)
	}
}
