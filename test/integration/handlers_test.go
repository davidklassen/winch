package integration

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

const appUnit = `cat > /etc/systemd/system/winch-app.service <<'U'
[Service]
ExecStartPre=/bin/sh -c 'echo x >> /root/starts'
ExecStart=/bin/sleep infinity
U
systemctl daemon-reload && systemctl start winch-app`

const handlersPipeline = `stages:
  - name: conf
    hosts: all
    steps:
      - recipe: conf
  - name: apps
    hosts: apps
    steps:
      - recipe: app
`

const confRecipe = `vars:
  conf_break: false
steps:
  - name: Fails on the host with the app
    file:
      path: /etc/hostname/x
      content: x
    when: !expr 'vars.conf_break and host.name == "handlers"'
  - file:
      path: !tpl /srv/{{ .host.name }}/a.conf
      content: "a\n"
    notify: app.restart
`

const appRecipe = `vars:
  app_value: one
  app_then: "true"
steps:
  - file:
      path: /etc/winch-app/1.conf
      content: !tpl "{{ .vars.app_value }}\n"
    notify: restart
  - file:
      path: /etc/winch-app/2.conf
      content: !tpl "{{ .vars.app_value }}\n"
    notify: restart
  # The last step, so that a run killed in its then has no step left to change.
  - file:
      path: /etc/winch-app/3.conf
      content: !tpl "{{ .vars.app_value }}\n"
    then: !expr vars.app_then
    notify: restart
handlers:
  restart:
    - service:
        name: winch-app
        restarted: true
`

const validateRecipe = `vars:
  v_one: a
  v_two: a
  v_check: "true"
steps:
  - file:
      path: /etc/winch-v/1.conf
      content: !tpl "{{ .vars.v_one }}\n"
    then: test -e /root/v-ok
    notify: restart
  - file:
      path: /etc/winch-v/2.conf
      content: !tpl "{{ .vars.v_two }}\n"
      validate: !expr vars.v_check
    then: echo two >> /root/v-then
    notify: [restart, reload]
handlers:
  restart:
    - file:
        path: /etc/winch-v/restarted
        content: "x\n"
  reload:
    - file:
        path: /etc/winch-v/reloaded
        content: "x\n"
`

// spec: Handlers; Steps; Running a pipeline/Failures; Remote execution/State on the host
func TestHandlers(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "handlers")
	vm.MustRun(t, appUnit)
	// A second host without the recipe app. It runs at the same time as the
	// first, so it needs its own VM.
	other := lab.StartVM(t, "handlers-b")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":               "name: hdemo\ninventory: test\n",
		"inventories/test.yaml":    "hosts:\n  handlers: {}\n  handlers-b: {}\ngroups:\n  apps:\n    hosts: [handlers]\n",
		"pipelines/site.yaml":      handlersPipeline,
		"recipes/conf/recipe.yaml": confRecipe,
		"recipes/app/recipe.yaml":  appRecipe,
	})
	starts := func(want string) {
		t.Helper()
		if out := strings.TrimSpace(vm.MustRun(t, "wc -l < /root/starts")); out != want {
			t.Errorf("winch-app started %s times, want %s", out, want)
		}
	}
	const records = "cat /var/lib/winch/handlers/hdemo 2>/dev/null; true"

	t.Run("a notification is dropped on a host without the recipe", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.conf_break=true")
		if r.Code != 1 || !strings.Contains(r.Stdout, "handlers-b: conf: + file /srv/handlers-b/a.conf") {
			t.Fatalf("apply: exit %d, want 1 with a change on handlers-b", r.Code)
		}
		for _, vm := range []*vmtest.VM{vm, other} {
			if out := vm.MustRun(t, records); out != "" {
				t.Errorf("%s: pending handlers = %q, want none", vm.Name, out)
			}
		}
	})

	t.Run("three changed files run the handler once", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || strings.Count(r.Stdout, "! handler app.restart") != 1 {
			t.Fatalf("plan: exit %d, want one handler line", r.Code)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 || strings.Count(r.Stdout, "handlers: app: ~ handler app.restart: service winch-app") != 1 {
			t.Fatalf("apply: exit %d, want one handler run", r.Code)
		}
		starts("2")
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("pending handlers = %q, want none", out)
		}
	})

	t.Run("a killed run leaves the handler pending", func(t *testing.T) {
		cmd := exec.Command(os.Getenv("WINCH_BIN"), "apply", "site", "--yes", "--set", "vars.app_value=two", "--set", "vars.app_then=sleep 10")
		cmd.Dir = dir
		cmd.Env = lab.Env()
		// The kill must reach ssh too, so the connection drops.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		vm.MustRun(t, `timeout 60 sh -c 'until grep -qx app.restart /var/lib/winch/handlers/hdemo 2>/dev/null && grep -qx two /etc/winch-app/3.conf; do sleep 0.2; done'`)
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		cmd.Wait() //nolint:errcheck // the kill fails the run
		// The helper ends after the command of then.
		vm.MustRun(t, `timeout 60 sh -c 'until flock -n /var/lib/winch/lock true; do sleep 0.5; done'`)
		starts("2")

		// Every file has its new content, so only the record runs the handler.
		r := lab.Winch(t, dir, "plan", "site", "--set", "vars.app_value=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "! handler app.restart") || strings.Contains(r.Stdout, "file") {
			t.Fatalf("plan after the kill: exit %d, want only the pending handler", r.Code)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.app_value=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "handlers: app: ~ handler app.restart: service winch-app") {
			t.Fatalf("apply after the kill: exit %d", r.Code)
		}
		starts("3")
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("pending handlers = %q, want none", out)
		}
	})

	t.Run("a failing then fails the step", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.app_value=three", "--set", "vars.app_then=echo broken; exit 7")
		if r.Code != 1 || !strings.Contains(r.Stderr, "handlers: app: failed: file /etc/winch-app/3.conf: then: echo broken; exit 7: exit status 7: broken") {
			t.Fatalf("apply: exit %d, want the then error", r.Code)
		}
		if out := vm.MustRun(t, records); out != "app.restart\n" {
			t.Errorf("pending handlers = %q, want app.restart", out)
		}
		starts("3")
		r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.app_value=three")
		if r.Code != 0 {
			t.Fatalf("apply after the fix: exit %d", r.Code)
		}
		starts("4")
		r = lab.Winch(t, dir, "plan", "site", "--set", "vars.app_value=three")
		if r.Code != 0 || !unchanged(r.Stdout, 2) {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a then that fails once runs at the next run", func(t *testing.T) {
		const then = "if [ -e /root/then-failed ]; then echo x >> /root/then-runs; else touch /root/then-failed; exit 3; fi"
		set := []string{"--set", "vars.app_value=four", "--set", "vars.app_then=" + then}
		r := lab.Winch(t, dir, append([]string{"apply", "site", "--yes"}, set...)...)
		if r.Code != 1 || !strings.Contains(r.Stderr, "then: "+then+": exit status 3") {
			t.Fatalf("apply: exit %d, want the then error\n%s", r.Code, r.Stderr)
		}
		if out := vm.MustRun(t, "cat /var/lib/winch/then/hdemo"); out == "" || strings.Contains(out, "then-failed") {
			t.Errorf("then record = %q, want a record without the command", out)
		}
		r = lab.Winch(t, dir, append([]string{"plan", "site"}, set...)...)
		if r.Code != 0 || !strings.Contains(r.Stdout, "! then: "+then) || strings.Contains(r.Stdout, "file") {
			t.Fatalf("plan after the failure: exit %d, want the pending then\n%s", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, append([]string{"apply", "site", "--yes"}, set...)...)
		if r.Code != 0 || !strings.Contains(r.Stdout, "handlers: app: ! then: "+then) {
			t.Fatalf("apply after the failure: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, "cat /root/then-runs"); out != "x\n" {
			t.Errorf("then ran %q times, want once", out)
		}
		r = lab.Winch(t, dir, append([]string{"plan", "site"}, set...)...)
		if r.Code != 0 || !unchanged(r.Stdout, 2) {
			t.Errorf("third plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a fixed then runs at the next run", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.app_value=five", "--set", "vars.app_then=echox y >> /root/fixed-then")
		if r.Code != 1 || !strings.Contains(r.Stderr, "then: echox y >> /root/fixed-then") {
			t.Fatalf("apply: exit %d, want the then error\n%s", r.Code, r.Stderr)
		}
		fixed := []string{"--set", "vars.app_value=five", "--set", "vars.app_then=echo y >> /root/fixed-then"}
		r = lab.Winch(t, dir, append([]string{"plan", "site"}, fixed...)...)
		if r.Code != 0 || !strings.Contains(r.Stdout, "! then: echo y >> /root/fixed-then") {
			t.Fatalf("plan after the fix: exit %d, want the fixed then as pending\n%s", r.Code, r.Stdout)
		}
		if r = lab.Winch(t, dir, append([]string{"apply", "site", "--yes"}, fixed...)...); r.Code != 0 {
			t.Fatalf("apply after the fix: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, "cat /root/fixed-then"); out != "y\n" {
			t.Errorf("the fixed then wrote %q, want one line", out)
		}
		r = lab.Winch(t, dir, append([]string{"plan", "site"}, fixed...)...)
		if r.Code != 0 || !unchanged(r.Stdout, 2) {
			t.Errorf("third plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a failed validate leaves only the records of earlier runs", func(t *testing.T) {
		vdir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: vdemo\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  handlers: {}\n",
			"pipelines/site.yaml":   "stages:\n  - name: v\n    hosts: all\n    steps:\n      - recipe: v\n",
			"recipes/v/recipe.yaml": validateRecipe,
		})
		vm.MustRun(t, "touch /root/v-ok")
		if r := lab.Winch(t, vdir, "apply", "site", "--yes"); r.Code != 0 {
			t.Fatalf("first apply: exit %d\n%s", r.Code, r.Stderr)
		}
		vm.MustRun(t, "rm /root/v-ok")
		r := lab.Winch(t, vdir, "apply", "site", "--yes", "--set", "vars.v_one=b")
		if r.Code != 1 || !strings.Contains(r.Stderr, "then: test -e /root/v-ok") {
			t.Fatalf("apply: exit %d, want the then error\n%s", r.Code, r.Stderr)
		}
		vm.MustRun(t, "touch /root/v-ok")
		r = lab.Winch(t, vdir, "apply", "site", "--yes", "--set", "vars.v_one=b", "--set", "vars.v_two=b", "--set", "vars.v_check=exit 4")
		if r.Code != 1 || !strings.Contains(r.Stderr, "validate: exit 4") {
			t.Fatalf("apply: exit %d, want the validate error\n%s", r.Code, r.Stderr)
		}
		// The person reverts the template: the step has nothing to change.
		r = lab.Winch(t, vdir, "plan", "site", "--set", "vars.v_one=b")
		if r.Code != 0 || !strings.Contains(r.Stdout, "! handler v.restart") || strings.Contains(r.Stdout, "reload") || strings.Contains(r.Stdout, "! then") {
			t.Errorf("plan after the failed validate: exit %d, want only the handler of the first run\n%s", r.Code, r.Stdout)
		}
		if out := vm.MustRun(t, "cat /var/lib/winch/handlers/vdemo /var/lib/winch/then/vdemo"); out != "v.restart\n" {
			t.Errorf("records = %q, want only v.restart", out)
		}
	})
}

const stageHandlerPipeline = `stages:
  - name: firewall
    hosts: all
    steps:
      - pkg:
          name: nftables
      - file:
          path: /etc/nftables.conf
          content: !tpl |
            #!/usr/sbin/nft -f

            flush ruleset

            table inet filter {
            	chain input {
            		type filter hook input priority filter; policy drop;

            		ct state established,related accept
            		ct state invalid drop
            		iif lo accept
            		tcp dport { {{ join .vars.fw_ports ", " }} } accept
            	}
            }
          mode: "0755"
          validate: nft -c -f /etc/nftables.conf
        notify: reload
      - service:
          name: nftables
          enabled: true
          running: true
      - file:
          path: /etc/winch-motd
          content: !tpl "{{ .vars.fw_motd }}\n"
        notify: motd
      - name: Fails on request
        cmd:
          command: exit 3
        when: !expr vars.fw_break
    handlers:
      reload:
        - service:
            name: nftables
            reloaded: true
          confirm_access: true
      motd:
        - cmd:
            command: echo x >> /root/motd-runs
`

// spec: Pipelines; Handlers; Running a pipeline/Lockout protection
func TestStageHandlers(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "stage-handlers")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: sdemo\ninventory: test\nvars:\n  fw_ports: [22]\n  fw_motd: one\n  fw_break: false\n",
		"inventories/test.yaml": "hosts:\n  stage-handlers: {}\n",
		"pipelines/site.yaml":   stageHandlerPipeline,
	})
	const records = "cat /var/lib/winch/handlers/sdemo 2>/dev/null; true"

	t.Run("a handler with confirm_access reloads nftables", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "stage-handlers: firewall: ~ handler firewall.reload: service nftables") {
			t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, "nft list ruleset"); !strings.Contains(out, "tcp dport 22 accept") {
			t.Fatalf("the ruleset is not in place:\n%s", out)
		}
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("pending handlers = %q, want none", out)
		}
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a rule that drops SSH rolls back the file of the stage", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.fw_ports=[80]")
		if r.Code != 1 || !strings.Contains(r.Stderr, "stage-handlers: firewall: failed: handler firewall.reload: service nftables: no new SSH connection works: ") ||
			!strings.HasSuffix(r.Stderr, "; the old files are back\n") {
			t.Fatalf("apply: exit %d\n%s", r.Code, r.Stderr)
		}
		if out := vm.MustRun(t, "cat /etc/nftables.conf"); !strings.Contains(out, "tcp dport { 22 } accept") {
			t.Errorf("the old /etc/nftables.conf is not back:\n%s", out)
		}
		if out := vm.MustRun(t, "nft list ruleset"); !strings.Contains(out, "tcp dport 22 accept") {
			t.Errorf("the old ruleset is not back:\n%s", out)
		}
		// The handler failed, so the run drops it with the old files back.
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("pending handlers = %q, want none", out)
		}
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("plan after the rollback: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a stopped run leaves the handler pending", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.fw_motd=two", "--set", "vars.fw_break=true")
		if r.Code != 1 || !strings.Contains(r.Stderr, "Fails on request") {
			t.Fatalf("apply: exit %d, want the failed step\n%s", r.Code, r.Stderr)
		}
		if out := vm.MustRun(t, records); out != "site\tfirewall\tmotd\n" {
			t.Errorf("pending handlers = %q, want the motd handler of stage firewall", out)
		}
		if out := vm.MustRun(t, "cat /root/motd-runs 2>/dev/null; true"); out != "x\n" {
			t.Errorf("the motd handler ran %q, want once from the first run", out)
		}
		r = lab.Winch(t, dir, "plan", "site", "--set", "vars.fw_motd=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "! handler firewall.motd") || strings.Contains(r.Stdout, "file") {
			t.Fatalf("plan: exit %d, want only the pending handler\n%s", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.fw_motd=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "stage-handlers: firewall: ~ handler firewall.motd: cmd echo x >> /root/motd-runs") {
			t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, "cat /root/motd-runs"); out != "x\nx\n" {
			t.Errorf("the motd handler ran %q, want twice", out)
		}
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("pending handlers = %q, want none", out)
		}
	})
}
