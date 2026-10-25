package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

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
	// The Host block of the lab SSH config matches the host name and sets the
	// port. The address sets only the HostName.
	dir := project(t, "hosts:\n  winch:\n    address: 127.0.0.1\n")
	sending := "winch: sending the helper (" + lab.Arch + ")"

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
		if r.Code != 0 || !strings.Contains(r.Stdout, "winch: ~ file /etc/motd") {
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

	t.Run("the plan leaves out a parent that an earlier step creates", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
			"inventories/test.yaml": "hosts:\n  winch:\n    address: 127.0.0.1\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - dir:
          path: /srv/www
          group: www-data
          mode: "0750"
      - file:
          path: /srv/www/index.html
          content: "hello\n"
`,
		})
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "+ file /srv/www/index.html") {
			t.Fatalf("plan: exit %d", r.Code)
		}
		if strings.Contains(r.Stdout, "create directory /srv/www") {
			t.Errorf("the plan lists /srv/www as a parent:\n%s", r.Stdout)
		}
		if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
			t.Fatalf("apply: exit %d", r.Code)
		}
		if out := vm.MustRun(t, "stat -c '%U:%G %a' /srv/www"); out != "root:www-data 750\n" {
			t.Errorf("/srv/www is %q", out)
		}
		r = lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || r.Stdout != "1 host: 0 to change, 1 unchanged, 0 unknown\n" {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a second session fails on the lock", func(t *testing.T) {
		vm.Session(t)
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 1 || !strings.Contains(r.Stderr, "locked by run test-TestWinch/a_second_session_fails_on_the_lock (test@test, since") {
			t.Fatalf("plan during a session: exit %d", r.Code)
		}
		m := regexp.MustCompile(`helper process (\d+)\); if that run is gone, end it with: sudo kill (\d+)`).FindStringSubmatch(r.Stderr)
		if m == nil || m[1] != m[2] {
			t.Fatalf("lock message without the helper process: %q", r.Stderr)
		}
		if out := vm.MustRun(t, "readlink /proc/"+m[1]+"/exe"); !strings.HasPrefix(out, "/var/lib/winch/bin/") {
			t.Fatalf("process %s is %q, want the helper", m[1], out)
		}
		vm.MustRun(t, "kill "+m[1])
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 {
			t.Errorf("plan after kill: exit %d, stderr %q", r.Code, r.Stderr)
		}
	})

	t.Run("plan and apply wait for another apt run and name it", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
			"inventories/test.yaml": "hosts:\n  winch:\n    address: 127.0.0.1\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - pkg:\n          name: hello\n",
		})
		// The fcntl lock of apt, held for 10 s. /root/locked gets the PID.
		pid := strings.TrimSpace(vm.MustRun(t, quietApt+` && (python3 -c 'import fcntl, os, time; f = open("/var/lib/dpkg/lock-frontend", "w"); fcntl.lockf(f, fcntl.LOCK_EX); open("/root/locked.tmp", "w").write(str(os.getpid())); os.rename("/root/locked.tmp", "/root/locked"); time.sleep(10)' >/dev/null 2>&1 &) && `+
			"timeout 10 sh -c 'until [ -e /root/locked ]; do sleep 0.1; done' && cat /root/locked && rm /root/locked"))
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "+ pkg hello") {
			t.Fatalf("plan: exit %d", r.Code)
		}
		if n := strings.Count(r.Stderr, "winch: waiting for another apt run (pid "+pid+")\n"); n != 1 {
			t.Errorf("stderr has the wait message for pid %s %d times, want once", pid, n)
		}

		// The refresh of apply starts the lock holder, after the check of the
		// step and before the install.
		vm.MustRun(t, `rm -f /root/locked && printf '#!/bin/sh\n(python3 -c '"'"'`+
			`import fcntl, os, time; f = open("/var/lib/dpkg/lock-frontend", "w"); fcntl.lockf(f, fcntl.LOCK_EX); open("/root/locked.tmp", "w").write(str(os.getpid())); os.rename("/root/locked.tmp", "/root/locked"); time.sleep(10)`+
			`'"'"' >/dev/null 2>&1 &)\ntimeout 10 sh -c "until [ -e /root/locked ]; do sleep 0.1; done"\n' > /root/hold-lock && chmod 755 /root/hold-lock && `+
			`echo 'APT::Update::Post-Invoke {"/root/hold-lock";};' > /etc/apt/apt.conf.d/99hold`)
		defer vm.MustRun(t, "rm -f /etc/apt/apt.conf.d/99hold /root/hold-lock /root/locked")
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply: exit %d", r.Code)
		}
		pid = strings.TrimSpace(vm.MustRun(t, "cat /root/locked"))
		if n := strings.Count(r.Stderr, "winch: waiting for another apt run (pid "+pid+")\n"); n != 1 {
			t.Errorf("apply stderr has the wait message for pid %s %d times, want once", pid, n)
		}
	})

	t.Run("a host without passwordless sudo fails", func(t *testing.T) {
		dir := project(t, "hosts:\n  winch:\n    address: 127.0.0.1\n    user: nosudo\n")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 1 || !strings.Contains(r.Stderr, "the login user needs passwordless sudo") {
			t.Errorf("plan as nosudo: exit %d", r.Code)
		}
	})

	t.Run("text from the login shell fails with its cause", func(t *testing.T) {
		vm.MustRun(t, "sed -i '1i echo Welcome' /home/nosudo/.bashrc")
		dir := project(t, "hosts:\n  winch:\n    address: 127.0.0.1\n    user: nosudo\n")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 1 || !strings.Contains(r.Stderr, `the login shell printed "Welcome" before winch started`) {
			t.Errorf("plan with a .bashrc that prints: exit %d", r.Code)
		}
		vm.MustRun(t, "sed -i 1d /home/nosudo/.bashrc")
	})

	t.Run("closing a session with ControlPersist does not wait", func(t *testing.T) {
		// A unix socket path must be short, and the lab directory is long on macOS.
		ctl, err := os.MkdirTemp("/tmp", "winch-")
		if err != nil {
			t.Fatal(err)
		}
		conf := filepath.Join(lab.Dir, "hosts", "winch-mux.conf")
		if err := os.WriteFile(conf, []byte("Host "+vm.Name+"\n  ControlMaster auto\n  ControlPath "+ctl+"/%C\n  ControlPersist 60\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			exec.Command("ssh", "-O", "exit", vm.Name).Run() //nolint:errcheck // the master may be gone
			os.Remove(conf)
			os.RemoveAll(ctl)
		})
		s := vm.Session(t)
		start := time.Now()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("close took %v", d)
		}
		if out, err := exec.Command("ssh", "-O", "check", vm.Name).CombinedOutput(); err != nil {
			t.Errorf("no ssh master runs: %v: %s", err, out)
		}
	})
}
