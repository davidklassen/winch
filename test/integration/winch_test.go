//go:build integration

package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

func project(t *testing.T, inventory string) string {
	return vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": inventory,
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "Managed by winch.\n"
`,
	})
}

// spec: Running a pipeline; Remote execution/Sessions; Remote execution/Helper; CLI/Prompts
func TestWinch(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "winch")
	// The inventory address overrides the host name for SSH.
	dir := project(t, "hosts:\n  web:\n    address: winch\n")
	sending := "web: sending the helper (" + lab.Arch + ")"

	t.Run("apply, then plan shows no changes", func(t *testing.T) {
		vm.MustRun(t, "mkdir -p /var/lib/winch/bin && touch /var/lib/winch/bin/old")
		r := lab.Winch(t, dir, "plan", "site")
		// Debian ships an /etc/motd.
		if r.Code != 0 || !strings.Contains(r.Stdout, "~ file /etc/motd") {
			t.Fatalf("plan: exit %d", r.Code)
		}
		if !strings.Contains(r.Stderr, sending) {
			t.Errorf("the first contact did not send the helper")
		}

		r = lab.Winch(t, dir, "apply", "site")
		if r.Code != 5 || !strings.HasSuffix(r.Stdout, "To apply, run: winch apply site --yes\n") {
			t.Errorf("apply without a terminal: exit %d", r.Code)
		}
		if out := vm.MustRun(t, "cat /etc/motd"); out == "Managed by winch.\n" {
			t.Fatal("apply without --yes changed the host")
		}

		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "web: ~ file /etc/motd") {
			t.Fatalf("apply --yes: exit %d", r.Code)
		}
		if strings.Contains(r.Stderr, "sending the helper") {
			t.Errorf("a second contact sent the helper again")
		}
		if out := vm.MustRun(t, "cat /etc/motd"); out != "Managed by winch.\n" {
			t.Errorf("/etc/motd = %q", out)
		}
		if out := vm.MustRun(t, "ls /var/lib/winch/bin"); len(strings.Fields(out)) != 1 || strings.Contains(out, "old") {
			t.Errorf("/var/lib/winch/bin holds %q, want only the helper", out)
		}

		r = lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || r.Stdout != "1 host: 0 to change, 1 unchanged, 0 unknown\n" {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, "apply", "site")
		if r.Code != 0 {
			t.Errorf("apply with no changes: exit %d", r.Code)
		}
	})

	t.Run("a second session fails on the lock", func(t *testing.T) {
		vm.Session(t)
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 1 || !strings.Contains(r.Stderr, "locked by run test-TestWinch/a_second_session_fails_on_the_lock (test@test, since") {
			t.Errorf("plan during a session: exit %d", r.Code)
		}
	})

	t.Run("a host without passwordless sudo fails", func(t *testing.T) {
		dir := project(t, "hosts:\n  web:\n    address: winch\n    user: nosudo\n")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 1 || !strings.Contains(r.Stderr, "the login user needs passwordless sudo") {
			t.Errorf("plan as nosudo: exit %d", r.Code)
		}
	})
}
