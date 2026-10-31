package integration

import (
	"fmt"
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
	const msg = "prompt: the access check cannot log in without a prompt; add the key to the agent with ssh-add"
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

// spec: Remote execution/Sessions (the access check of lockout protection
// always uses BatchMode=yes); Running a pipeline/Lockout protection
func TestPromptedJump(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "promptjump")
	keys := t.TempDir()
	key, other := filepath.Join(keys, "key"), filepath.Join(keys, "other")
	for _, k := range []string{key, other} {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "winch-pass", "-C", "winch-test", "-f", k).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v: %s", err, out)
		}
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := os.ReadFile(other + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	// The VM is its own jump host. Only the new key logs in as the user hop.
	vm.MustRun(t, "useradd -m hop && install -d -m 700 -o hop -g hop ~hop/.ssh && echo '"+strings.TrimSpace(string(pub))+"' > ~hop/.ssh/authorized_keys && chown hop:hop ~hop/.ssh/authorized_keys")
	// The program of SSH_ASKPASS writes a line for each question.
	asked := filepath.Join(keys, "asked")
	askpass := filepath.Join(keys, "askpass")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\necho \"$1\" >> "+asked+"\necho winch-pass\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	questions := func() int {
		data, err := os.ReadFile(asked)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		os.Remove(asked)
		return strings.Count(string(data), "\n")
	}
	env := []string{"SSH_ASKPASS=" + askpass, "SSH_ASKPASS_REQUIRE=force", "SSH_AUTH_SOCK=", "NO_COLOR=1"}
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
	questions()
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: promptjump\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  jumped: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - recipe: sshd
`,
		"recipes/sshd/recipe.yaml": `steps:
  - file:
      path: /etc/winch-jump
      content: "x\n"
    notify: reload
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`,
		// The hop then wants the other key, which is not in the agent.
		"pipelines/keys.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - recipe: hopkeys
`,
		"recipes/hopkeys/recipe.yaml": `steps:
  - file:
      path: /home/hop/.ssh/authorized_keys
      content: "` + strings.TrimSpace(string(otherPub)) + `\n"
      owner: hop
      group: hop
      mode: "0600"
    notify: reload
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`,
	})

	t.Cleanup(func() { os.Remove(filepath.Join(lab.Dir, "hosts", "jumped.conf")) })
	// The hop that needs the key is the only hop, or the first of two.
	for _, jump := range []string{"jumped-hop", "jumped-hop,jumped-in"} {
		_, err := lab.WriteHost("jumped", fmt.Sprintf("Host jumped\n  HostName 127.0.0.1\n  Port 22\n  ProxyJump %s\n"+
			"Host jumped-hop\n  HostName 127.0.0.1\n  Port %d\n  User hop\n  IdentityFile %s\n  IdentityFile %s\n"+
			"Host jumped-in\n  HostName 127.0.0.1\n  Port 22\n", jump, vm.HostPort("tcp", 22), key, other))
		if err != nil {
			t.Fatal(err)
		}

		if r := lab.WinchEnv(t, dir, env, "plan", "site"); r.Code != 4 || !strings.Contains(r.Stdout+r.Stderr, "ssh-add") {
			t.Errorf("%s: plan in batch mode: exit %d, want 4 and ssh-add", jump, r.Code)
		}
		if n := questions(); n != 0 {
			t.Errorf("%s: plan in batch mode asked %d questions", jump, n)
		}
		const msg = "jumped: the access check cannot log in without a prompt; add the key to the agent with ssh-add"
		if r := lab.WinchTerminal(t, dir, env, "apply", "site", "--yes"); r.Code != 1 || !strings.Contains(r.Stdout, msg) {
			t.Errorf("%s: apply: exit %d, want 1 and %q", jump, r.Code, msg)
		}
		// Only the session's second login asks.
		if n := questions(); n != 1 {
			t.Errorf("%s: apply asked %d questions, want 1", jump, n)
		}
		if out := vm.MustRun(t, "test -e /etc/winch-jump && echo yes || true"); out != "" {
			t.Errorf("%s: apply changed the host", jump)
		}

		// With the key in the agent, the access checks pass through the hops.
		if r := lab.WinchTerminal(t, dir, append(env, "SSH_AUTH_SOCK="+sock), "apply", "site", "--yes"); r.Code != 0 {
			t.Errorf("%s: apply with the key in the agent: exit %d, want 0", jump, r.Code)
		}
		if n := questions(); n != 0 {
			t.Errorf("%s: apply with the key in the agent asked %d questions", jump, n)
		}
		vm.MustRun(t, "rm /etc/winch-jump")

		// The access check after the change asks nothing on the hop.
		r := lab.WinchTerminal(t, dir, append(env, "SSH_AUTH_SOCK="+sock), "apply", "keys", "--yes")
		if r.Code != 1 || !strings.Contains(r.Stdout, "the access check failed: cannot log in after this change: ") || !strings.Contains(r.Stdout, "; the old files are back") {
			t.Errorf("%s: apply of the other key: exit %d, want 1 and a rollback", jump, r.Code)
		}
		if n := questions(); n != 0 {
			t.Errorf("%s: apply of the other key asked %d questions", jump, n)
		}
		if out := vm.MustRun(t, "cat /home/hop/.ssh/authorized_keys"); out != string(pub) {
			t.Errorf("%s: the old authorized_keys of hop is not back: %q", jump, out)
		}
	}
}
