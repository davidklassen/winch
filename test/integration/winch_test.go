package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/vmtest"
)

func project(t *testing.T, inventory string) string {
	return vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
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
		// Ubuntu has no /etc/motd.
		vm.MustRun(t, "mkdir -p /var/lib/winch/bin && touch -d '31 days ago' /var/lib/winch/bin/old && echo stock > /etc/motd")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "~ file /etc/motd") {
			t.Fatalf("plan: exit %d", r.Code)
		}
		if !strings.Contains(r.Stderr, sending) {
			t.Errorf("the first contact did not send the helper")
		}

		r = lab.Winch(t, dir, "apply", "site")
		if r.Code != 5 || !strings.HasSuffix(r.Stdout, "To apply, run: winch apply site --check "+hashOf(t, r.Stdout)+"\n") {
			t.Errorf("apply without a terminal: exit %d", r.Code)
		}
		if out := vm.MustRun(t, "cat /etc/motd"); out == "Managed by winch.\n" {
			t.Fatal("apply without --yes changed the host")
		}

		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "winch: base: ~ file /etc/motd") {
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
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, "apply", "site")
		if r.Code != 0 {
			t.Errorf("apply with no changes: exit %d", r.Code)
		}
	})

	t.Run("two winch versions keep both helpers", func(t *testing.T) {
		other := otherWinch(t)
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 {
			t.Fatalf("plan: exit %d", r.Code)
		}
		if r := lab.WinchBin(t, other, dir, nil, "plan", "site"); r.Code != 0 || !strings.Contains(r.Stderr, sending) {
			t.Errorf("plan with the other winch: exit %d, did not send its helper", r.Code)
		}
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || strings.Contains(r.Stderr, sending) {
			t.Errorf("plan after the other winch: exit %d, sent the helper again", r.Code)
		}
		if r := lab.WinchBin(t, other, dir, nil, "plan", "site"); r.Code != 0 || strings.Contains(r.Stderr, sending) {
			t.Errorf("second plan with the other winch: exit %d, sent the helper again", r.Code)
		}
		if out := vm.MustRun(t, "ls /var/lib/winch/bin"); len(strings.Fields(out)) != 2 {
			t.Errorf("/var/lib/winch/bin holds %q, want two helpers", out)
		}
	})

	t.Run("the plan leaves out a parent that an earlier step creates", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: test\n",
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
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("the plan fails a cmd as a user that a later step creates", func(t *testing.T) {
		write := func(steps string) string {
			return vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: demo\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  winch:\n    address: 127.0.0.1\n",
				"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n" + steps,
			})
		}
		r := lab.Winch(t, write(`      - cmd:
          command: make install
          user: winch-order
      - user:
          name: winch-order
`), "plan", "site")
		want := "base: user winch-order: an earlier step needs it: base: cmd make install; move this step before it"
		if r.Code == 0 || !strings.Contains(r.Stdout+r.Stderr, want) {
			t.Errorf("plan: exit %d, want the error %q:\n%s%s", r.Code, want, r.Stdout, r.Stderr)
		}
		r = lab.Winch(t, write(`      - user:
          name: winch-order
      - cmd:
          command: "true"
          user: winch-order
          dir: /home/winch-order
      - file:
          path: /home/winch-order/.env
          content: ""
`), "plan", "site")
		if r.Code != 0 {
			t.Errorf("plan in the home of an earlier user: exit %d:\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
	})

	t.Run("plan and apply name a followed link", func(t *testing.T) {
		vm.MustRun(t, "rm -rf /srv/linked && mkdir -p /srv/linked/t && chmod 700 /srv/linked/t && ln -s t /srv/linked/l")
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  winch:\n    address: 127.0.0.1\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - dir:
          path: /srv/linked/l
`,
		})
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "~ dir /srv/linked/l (link to t)\n") {
			t.Fatalf("plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "winch: base: ~ dir /srv/linked/l (link to t)\n") {
			t.Fatalf("apply: exit %d, stdout %q", r.Code, r.Stdout)
		}
		if out := vm.MustRun(t, "readlink /srv/linked/l; stat -c %a /srv/linked/t"); out != "t\n755\n" {
			t.Errorf("after apply: %q", out)
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

	t.Run("a new session of the same run takes over its idle helper", func(t *testing.T) {
		vm.Session(t)
		// The helper's process ID, and the sshd process of its connection.
		ids := strings.Fields(vm.MustRun(t, `pid=$(sed 's/.*"pid":\([0-9]*\).*/\1/' /var/lib/winch/lock); p=$pid
while [ "$p" -gt 1 ]; do
  case "$(cat /proc/$p/comm)" in sshd*) echo "$pid $p"; exit 0;; esac
  p=$(cut -d' ' -f4 /proc/$p/stat)
done
exit 1`))
		// A stopped sshd passes nothing to the helper, as for a connection
		// that died on the controller's side and that sshd has not seen yet.
		vm.MustRun(t, "kill -STOP "+ids[1])
		t.Cleanup(func() { vm.Run(context.Background(), "kill -CONT "+ids[1]) }) //nolint:errcheck // the VM can be gone
		start := time.Now()
		s := vm.Session(t)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("the new session took %v", d)
		}
		if _, err := s.Exec(t.Context(), "true"); err != nil {
			t.Fatalf("exec in the new session: %v", err)
		}
		if out := vm.MustRun(t, "grep -c '\"pid\":"+ids[0]+"}' /var/lib/winch/lock || true"); out != "0\n" {
			t.Errorf("the lock still names the old helper %s", ids[0])
		}
	})

	t.Run("plan and apply wait for another apt run and name it", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  winch:\n    address: 127.0.0.1\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - pkg:\n          name: hello\n",
		})
		pid := strings.TrimSpace(vm.MustRun(t, "(python3 -c '"+lockHolder("/var/lib/dpkg/lock-frontend", 10)+"' >/dev/null 2>&1 &) && "+
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
		vm.MustRun(t, `rm -f /root/locked && printf '#!/bin/sh\n(python3 -c '"'"'`+lockHolder("/var/lib/dpkg/lock-frontend", 10)+`'"'"' >/dev/null 2>&1 &)\ntimeout 10 sh -c "until [ -e /root/locked ]; do sleep 0.1; done"\n' > /root/hold-lock && chmod 755 /root/hold-lock && `+
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

	t.Run("the refresh waits for another apt run that holds the index lock", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  winch:\n    address: 127.0.0.1\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - pkg:\n          name: sl\n",
		})
		// Nothing before the refresh waits for the index lock, so the hold
		// covers the connect and the check.
		pid := strings.TrimSpace(vm.MustRun(t, "(python3 -c '"+lockHolder("/var/lib/apt/lists/lock", 30)+"' >/dev/null 2>&1 &) && "+
			"timeout 10 sh -c 'until [ -e /root/locked ]; do sleep 0.1; done' && cat /root/locked && rm /root/locked"))
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply: exit %d, stderr %q", r.Code, r.Stderr)
		}
		if n := strings.Count(r.Stderr, "winch: waiting for another apt run (pid "+pid+")\n"); n != 1 {
			t.Errorf("stderr has the wait message for pid %s %d times, want once", pid, n)
		}
		if out, err := vm.Run(t.Context(), "dpkg-query -W -f='${db:Status-Abbrev}' sl"); err != nil || out != "ii " {
			t.Errorf("sl is %q, %v; want installed", out, err)
		}
	})

	t.Run("a host without passwordless sudo fails", func(t *testing.T) {
		dir := project(t, "hosts:\n  winch:\n    address: 127.0.0.1\n    user: nosudo\n")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 1 || !strings.Contains(r.Stderr, "the login user needs passwordless sudo: "+osRelease().sudoDenied) {
			t.Errorf("plan as nosudo: exit %d\n%s", r.Code, r.Stderr)
		}
	})

	t.Run("an unsafe state directory fails the host", func(t *testing.T) {
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 {
			t.Fatalf("first plan: exit %d\n%s", r.Code, r.Stderr)
		}
		for _, p := range []string{"/var/lib/winch", "/var/lib/winch/bin"} {
			vm.MustRun(t, "chown nobody "+p)
			r := lab.Winch(t, dir, "plan", "site")
			vm.MustRun(t, "chown root "+p)
			if r.Code != 1 || !strings.Contains(r.Stderr, "winch: "+p+" is not owned by root or can be written by others") {
				t.Errorf("plan with %s owned by nobody: exit %d\n%s", p, r.Code, r.Stderr)
			}
		}
	})

	t.Run("an unsafe entry of the state directory fails the host", func(t *testing.T) {
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 {
			t.Fatalf("first plan: exit %d\n%s", r.Code, r.Stderr)
		}
		job := "/var/lib/winch/rollback/timer.json"
		vm.MustRun(t, `mkdir -p /var/lib/winch/rollback && echo '{"deadline":"2026-01-01T00:00:00Z","restore":[],"downloads":""}' > `+job+` && chown -R nobody /var/lib/winch/rollback`)
		defer vm.MustRun(t, "rm -rf /var/lib/winch/rollback")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 1 || !strings.Contains(r.Stderr, "/var/lib/winch/rollback is not owned by root or can be written by others") {
			t.Errorf("plan with rollback/ owned by nobody: exit %d\n%s", r.Code, r.Stderr)
		}
		if _, err := vm.Run(t.Context(), "test -e "+job); err != nil {
			t.Errorf("the planted rollback job ran: %v", err)
		}
	})

	t.Run("a cut helper is sent again", func(t *testing.T) {
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 {
			t.Fatalf("first plan: exit %d\n%s", r.Code, r.Stderr)
		}
		vm.MustRun(t, "for f in /var/lib/winch/bin/*; do truncate -s 1000 $f; done")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stderr, sending) {
			t.Errorf("plan with a cut helper: exit %d\n%s", r.Code, r.Stderr)
		}
	})

	t.Run("a run as root", func(t *testing.T) {
		vm.MustRun(t, "cp /home/admin/.ssh/authorized_keys /root/.ssh/authorized_keys")
		defer vm.MustRun(t, ": > /root/.ssh/authorized_keys")
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: demo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  winch:\n    address: 127.0.0.1\n    user: root\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /root/root-mark
          content: "x\n"
        then: "pwd > /root/pwd.out"
      - pkg:
          name: figlet
`,
		})
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "+ file /root/root-mark") || !strings.Contains(r.Stdout, "+ pkg figlet") {
			t.Fatalf("plan: exit %d", r.Code)
		}
		if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
			t.Fatalf("apply: exit %d", r.Code)
		}
		if out := vm.MustRun(t, "cat /root/pwd.out; dpkg-query -W -f='${db:Status-Abbrev}' figlet"); out != "/\nii " {
			t.Errorf("after apply: %q, want the then in / and figlet installed", out)
		}
		// sudo logs "root : ..." for a command that root runs through it.
		out := strings.Fields(vm.MustRun(t, "journalctl -q -o cat -u ssh | grep -c 'Accepted publickey for root' || true; journalctl -q -o cat -t sudo | grep -c '^ *root : ' || true"))
		if len(out) != 2 || out[0] == "0" || out[1] != "0" {
			t.Errorf("root logins and sudo calls of root: %q, want some logins and no sudo", out)
		}
		r = lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
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

	t.Run("a session with ControlMaster in the SSH config starts no master", func(t *testing.T) {
		// A unix socket path must be short, and the lab directory is long on macOS.
		ctl, err := os.MkdirTemp("/tmp", "winch-")
		if err != nil {
			t.Fatal(err)
		}
		conf, err := lab.WriteHost("winch-mux", "Host "+vm.Name+"\n  ControlMaster auto\n  ControlPath "+ctl+"/%C\n  ControlPersist 60\n")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			exec.Command("ssh", "-O", "exit", vm.Name).Run() //nolint:errcheck // the master may be gone
			os.Remove(conf)
			os.RemoveAll(ctl)
		})
		if err := vm.Session(t).Close(); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("ssh", "-O", "check", vm.Name).CombinedOutput(); err == nil {
			t.Errorf("an ssh master runs: %s", out)
		}
	})

	t.Run("host commands run in / with C.UTF-8, PATH, HOME, umask 022, and no login variables", func(t *testing.T) {
		// The systemctl in /usr/local/sbin records the environment and the
		// working directory that a module command gets from the helper. Other
		// callers, such as root's user manager, must not overwrite the record.
		const wrapper = "#!/bin/sh\ncase $(readlink /proc/$PPID/exe) in /var/lib/winch/bin/*)\n" +
			"{ xargs -0 -n1 < /proc/$$/environ; echo cwd $(readlink /proc/$$/cwd); } > /root/module.env ;;\nesac\n" +
			"exec /usr/bin/systemctl \"$@\"\n"
		defer vm.MustRun(t, "rm -f /root/.ssh/authorized_keys /etc/sudoers.d/zz-path /usr/local/sbin/systemctl && "+
			"sed -i '/^umask 077; export PATH/d' /home/admin/.bashrc /root/.bashrc")
		// A sudoers without secure_path and with HOME in env_keep passes the
		// login user's PATH and HOME. A strict umask, a short PATH, and
		// LANGUAGE go in .bashrc before the check for an interactive shell, so
		// that ssh commands read them.
		vm.MustRun(t, "cp /home/admin/.ssh/authorized_keys /root/.ssh/authorized_keys && "+
			"printf 'Defaults !secure_path\\nDefaults env_keep += HOME\\n' > /etc/sudoers.d/zz-path && "+
			"printf '"+wrapper+"' > /usr/local/sbin/systemctl && chmod 755 /usr/local/sbin/systemctl && "+
			"sed -i '1i umask 077; export PATH=/usr/bin:/bin LANGUAGE=de' /home/admin/.bashrc /root/.bashrc")
		path := "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		files := map[string][]string{
			"/root/env.out":    {"LC_ALL=C.UTF-8", `LC_CTYPE="C.UTF-8"`, "0022", path, "HOME=/root"},
			"/root/module.env": {"LC_ALL=C.UTF-8", path, "cwd /", "HOME=/root", "USER=root", "LOGNAME=root"},
		}
		for _, user := range []string{"admin", "root"} {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: demo\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  winch:\n    address: 127.0.0.1\n    user: " + user + "\n",
				"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /root/env-mark-` + user + `
          content: "x\n"
        then: "{ env; umask; locale; } > /root/env.out 2>&1"
      - service:
          name: ssh
          running: true
`,
			})
			vm.MustRun(t, "rm -f /root/env.out /root/module.env")
			if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
				t.Fatalf("apply as %s: exit %d", user, r.Code)
			}
			for file, want := range files {
				out := vm.MustRun(t, "cat "+file)
				lines := strings.Split(out, "\n")
				missing := slices.DeleteFunc(slices.Clone(want), func(w string) bool { return slices.Contains(lines, w) })
				bad := slices.ContainsFunc(lines, func(l string) bool {
					name, _, ok := strings.Cut(l, "=")
					return strings.HasPrefix(l, "SUDO_") || l == "LANGUAGE=de" ||
						file == "/root/module.env" && ok && !slices.Contains([]string{"LC_ALL", "PATH", "HOME", "USER", "LOGNAME"}, name)
				})
				if len(missing) > 0 || bad || strings.Contains(out, "Cannot set") {
					t.Errorf("as %s, %s: missing %q, a variable from the login session, or a locale error in:\n%s", user, file, missing, out)
				}
			}
		}
	})
}

// otherWinch builds winch with helpers that have one more byte, so their
// hashes differ from the helpers of WINCH_BIN.
func otherWinch(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	replace := map[string]string{}
	for _, arch := range []string{"amd64", "arm64"} {
		src := filepath.Join(root, "internal/helperbin/bin/helper-linux-"+arch)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(tmp, "helper-"+arch)
		if err := os.WriteFile(dst, append(data, 0), 0o644); err != nil {
			t.Fatal(err)
		}
		replace[src] = dst
	}
	overlay, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "overlay.json"), overlay, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(tmp, "winch")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-overlay", filepath.Join(tmp, "overlay.json"), "-o", bin, "./cmd/winch")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the other winch: %v\n%s", err, out)
	}
	return bin
}

// lockHolder is a Python program that holds the fcntl lock of path. It writes
// its PID to /root/locked when it has the lock.
func lockHolder(path string, seconds int) string {
	return `import fcntl, os, time; f = open("` + path + `", "w"); fcntl.lockf(f, fcntl.LOCK_EX); open("/root/locked.tmp", "w").write(str(os.getpid())); os.rename("/root/locked.tmp", "/root/locked"); time.sleep(` + strconv.Itoa(seconds) + `)`
}
