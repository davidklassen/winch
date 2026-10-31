package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Remote execution/Sessions (at a terminal, a host that needs a prompt
// plans as usual, but apply stops before its first change)
func TestPromptedLogin(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "prompt")
	keys := t.TempDir()
	key := filepath.Join(keys, "key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "winch-pass", "-C", "winch-test", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	// Only the new key logs in as root.
	vm.MustRun(t, "install -d -m 700 /root/.ssh && echo '"+strings.TrimSpace(string(pub))+"' > /root/.ssh/authorized_keys")
	conf := filepath.Join(lab.Dir, "hosts", vm.Name+".conf")
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.WriteHost(vm.Name, string(data)+"  IdentityFile "+key+"\n"); err != nil {
		t.Fatal(err)
	}
	// ssh asks the program of SSH_ASKPASS for the passphrase, but not in
	// batch mode.
	askpass := filepath.Join(keys, "askpass")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\necho winch-pass\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"SSH_ASKPASS=" + askpass, "SSH_ASKPASS_REQUIRE=force", "SSH_AUTH_SOCK=", "NO_COLOR=1"}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: prompt\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  prompt:\n    user: root\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /root/prompted
          content: "x\n"
`,
	})
	exists := func() bool {
		return vm.MustRun(t, "test -e /root/prompted && echo yes || true") == "yes\n"
	}

	if r := lab.WinchTerminal(t, dir, env, "plan", "site"); r.Code != 0 || !strings.Contains(r.Stdout, "1 to change") {
		t.Fatalf("plan: exit %d", r.Code)
	}
	const msg = "prompt: failed: the access check cannot log in without a prompt; add the key to the agent with ssh-add"
	if r := lab.WinchTerminal(t, dir, env, "apply", "site", "--yes"); r.Code != 1 || !strings.Contains(r.Stdout, msg) {
		t.Errorf("apply: exit %d, want 1 and %q", r.Code, msg)
	}
	if exists() {
		t.Error("apply changed the host")
	}

	sockDir, err := os.MkdirTemp("", "winch-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "s")
	agent := exec.Command("ssh-agent", "-D", "-a", sock)
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		agent.Process.Kill() //nolint:errcheck // the agent may be gone
		agent.Wait()         //nolint:errcheck // a killed agent exits with an error
	})
	// The agent creates its socket after it starts.
	for start := time.Now(); ; time.Sleep(100 * time.Millisecond) {
		add := exec.Command("ssh-add", key)
		add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock, "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force")
		out, err := add.CombinedOutput()
		if err == nil {
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("ssh-add: %v: %s", err, out)
		}
	}
	env = append(env, "SSH_AUTH_SOCK="+sock)
	if r := lab.WinchTerminal(t, dir, env, "apply", "site", "--yes"); r.Code != 0 {
		t.Errorf("apply with the key in the agent: exit %d, want 0", r.Code)
	}
	if !exists() {
		t.Error("apply with the key in the agent did not change the host")
	}
}
