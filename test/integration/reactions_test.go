package integration

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// winchAppSum is the SHA-256 of the main argument of the restart of
// winch-app.
const winchAppSum = "092289e599b4d39f673b14c70413ff0f7d8745e246bc61e4ac38d6d92319ee15"

const appUnit = `cat > /etc/systemd/system/winch-app.service <<'U'
[Service]
ExecStartPre=/bin/sh -c 'echo x >> /root/starts'
ExecStart=/bin/sleep infinity
U
systemctl daemon-reload && systemctl start winch-app`

const reactionsPipeline = `stages:
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
    when: !expr 'vars.conf_break and host.name == "reactions"'
  - file:
      path: !tpl /srv/{{ host.name }}/a.conf
      content: "a\n"
`

const appRecipe = `vars:
  app_value: one
  app_then: "true"
steps:
  - file:
      path: /etc/winch-app/1.conf
      content: !tpl "{{ vars.app_value }}\n"
  - file:
      path: /etc/winch-app/2.conf
      content: !tpl "{{ vars.app_value }}\n"
  # The last file, so that a run killed in its then has no file left to change.
  - file:
      path: /etc/winch-app/3.conf
      content: !tpl "{{ vars.app_value }}\n"
    then: !expr vars.app_then
  # The change of the conf recipe in an earlier stage counts too.
  - service:
      name: winch-app
      restarted: true
    on_change: [/etc/winch-app, /srv]
`

const validateRecipe = `vars:
  v_one: a
  v_two: a
  v_check: "true"
steps:
  - file:
      path: /etc/winch-v/1.conf
      content: !tpl "{{ vars.v_one }}\n"
    then: test -e /root/v-ok
  - file:
      path: /etc/winch-v/2.conf
      content: !tpl "{{ vars.v_two }}\n"
      validate: !expr vars.v_check
    then: echo two >> /root/v-then
  - file:
      path: /etc/winch-v/restarted
      content: "x\n"
    on_change: [/etc/winch-v/1.conf, /etc/winch-v/2.conf]
  - file:
      path: /etc/winch-v/reloaded
      content: "x\n"
    on_change: [/etc/winch-v/2.conf]
`

// spec: Reactions; Steps; Running a pipeline/Failures; Remote execution/State on the host
func TestReactions(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "reactions")
	vm.MustRun(t, appUnit)
	// A second host without the recipe app. It runs at the same time as the
	// first, so it needs its own VM.
	other := lab.StartVM(t, "reactions-b")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":               "name: hdemo\ninventory: test\n",
		"inventories/test.yaml":    "hosts:\n  reactions: {}\n  reactions-b: {}\ngroups:\n  apps:\n    hosts: [reactions]\n",
		"pipelines/site.yaml":      reactionsPipeline,
		"recipes/conf/recipe.yaml": confRecipe,
		"recipes/app/recipe.yaml":  appRecipe,
	})
	starts := func(want string) {
		t.Helper()
		if out := strings.TrimSpace(vm.MustRun(t, "wc -l < /root/starts")); out != want {
			t.Errorf("winch-app started %s times, want %s", out, want)
		}
	}
	const records = "sed '/^version 1$/d' /var/lib/winch/react/hdemo 2>/dev/null; true"
	// restart is the record of the restart of winch-app.
	const restart = `{"recipe":"app","module":"service","mains":["` + winchAppSum + `"]}` + "\n"

	t.Run("a change on a host without the recipe records nothing", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.conf_break=true")
		if r.Code != 1 || !strings.Contains(r.Stdout, "reactions-b: conf: + file /srv/reactions-b/a.conf") {
			t.Fatalf("apply: exit %d, want 1 with a change on reactions-b", r.Code)
		}
		for _, vm := range []*vmtest.VM{vm, other} {
			if out := vm.MustRun(t, records); out != "" {
				t.Errorf("%s: records = %q, want none", vm.Name, out)
			}
		}
	})

	t.Run("four changed files restart once", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || strings.Count(r.Stdout, "~ service winch-app: restart (/srv/reactions/a.conf changes)") != 1 {
			t.Fatalf("plan: exit %d, want one restart line\n%s", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 || strings.Count(r.Stdout, "reactions: app: ~ service winch-app") != 1 {
			t.Fatalf("apply: exit %d, want one restart\n%s", r.Code, r.Stdout)
		}
		starts("2")
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records = %q, want none", out)
		}
	})

	t.Run("a killed run leaves the restart pending", func(t *testing.T) {
		cmd := exec.Command(os.Getenv("WINCH_BIN"), "apply", "site", "--yes", "--set", "vars.app_value=two", "--set", "vars.app_then=sleep 10")
		cmd.Dir = dir
		cmd.Env = lab.Env()
		// The kill must reach ssh too, so the connection drops.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		vm.MustRun(t, `timeout 60 sh -c 'until grep -q "\"module\":\"service\"" /var/lib/winch/react/hdemo 2>/dev/null && grep -qx two /etc/winch-app/3.conf; do sleep 0.2; done'`)
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		cmd.Wait() //nolint:errcheck // the kill fails the run
		// The helper ends after the command of then.
		vm.MustRun(t, `timeout 60 sh -c 'until flock -n /var/lib/winch/lock true; do sleep 0.5; done'`)
		starts("2")

		// Every file has its new content, so only the record restarts.
		r := lab.Winch(t, dir, "plan", "site", "--set", "vars.app_value=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "! service winch-app: restart (pending from an earlier run)") || strings.Contains(r.Stdout, "file") || strings.Contains(r.Stdout, "then:") {
			t.Fatalf("plan after the kill: exit %d, want only the pending restart\n%s", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.app_value=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "reactions: app: ~ service winch-app") {
			t.Fatalf("apply after the kill: exit %d", r.Code)
		}
		starts("3")
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records = %q, want none", out)
		}
	})

	t.Run("a failing then fails the step", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.app_value=three", "--set", "vars.app_then=echo broken; exit 7")
		if r.Code != 1 || !strings.Contains(r.Stderr, "reactions: app: failed: file /etc/winch-app/3.conf: then: echo broken; exit 7: exit status 7: broken") {
			t.Fatalf("apply: exit %d, want the then error", r.Code)
		}
		if out := vm.MustRun(t, records); !strings.Contains(out, restart) || !strings.Contains(out, `"then":true`) || strings.Count(out, "\n") != 2 {
			t.Errorf("records = %q, want the then and the restart", out)
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
		if out := vm.MustRun(t, records); !strings.Contains(out, `"then":true`) || strings.Contains(out, "then-failed") {
			t.Errorf("records = %q, want a record of the then without the command", out)
		}
		r = lab.Winch(t, dir, append([]string{"plan", "site"}, set...)...)
		if r.Code != 0 || !strings.Contains(r.Stdout, "! then: "+then) || strings.Contains(r.Stdout, "file") {
			t.Fatalf("plan after the failure: exit %d, want the pending then\n%s", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, append([]string{"apply", "site", "--yes"}, set...)...)
		if r.Code != 0 || !strings.Contains(r.Stdout, "reactions: app: ! then: "+then) {
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
			"inventories/test.yaml": "hosts:\n  reactions: {}\n",
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
		if r.Code != 1 || !strings.Contains(r.Stderr, "validate failed, and the old file is back: exit 4") {
			t.Fatalf("apply: exit %d, want the validate error\n%s", r.Code, r.Stderr)
		}
		// The person reverts the template: the step has nothing to change.
		r = lab.Winch(t, vdir, "plan", "site", "--set", "vars.v_one=b")
		if r.Code != 0 || !strings.Contains(r.Stdout, "! file /etc/winch-v/restarted (pending from an earlier run)") || strings.Contains(r.Stdout, "reloaded") || strings.Contains(r.Stdout, "! then") {
			t.Errorf("plan after the failed validate: exit %d, want only the pending step of the first run\n%s", r.Code, r.Stdout)
		}
		if out := vm.MustRun(t, "sed '/^version 1$/d' /var/lib/winch/react/vdemo"); strings.Count(out, "\n") != 1 || !strings.Contains(out, `"module":"file"`) || strings.Contains(out, `"then"`) {
			t.Errorf("records = %q, want only the record of the restarted file", out)
		}
	})

	t.Run("a pending then follows its step", func(t *testing.T) {
		project := func(steps string) string {
			return vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: tdemo\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  reactions: {}\n",
				"pipelines/site.yaml":   "stages:\n  - name: t\n    hosts: all\n    steps:\n" + steps,
			})
		}
		const moved = `      - file:
          path: /root/t/moved
          content: "x\n"
        then: test -e /root/t-ok && echo moved >> /root/t-runs
`
		const loop = `      - file:
          path: !tpl /root/t/{{ item }}
          content: "x\n"
        loop: [a, b]
        then: test -e /root/t-ok && echo loop >> /root/t-runs
`
		const gone = `      - file:
          path: /root/t/gone
          content: "x\n"
        then: test -e /root/t-ok
`
		const added = `      - file:
          path: /root/t/added
          content: "x\n"
`
		const record = "sed '/^version 1$/d' /var/lib/winch/react/tdemo 2>/dev/null; true"
		vm.MustRun(t, "mkdir -p /root/t")
		fails := func(steps string) {
			t.Helper()
			r := lab.Winch(t, project(steps), "apply", "site", "--yes")
			if r.Code != 1 || !strings.Contains(r.Stderr, "then: test -e /root/t-ok") {
				t.Fatalf("apply: exit %d, want the then error\n%s", r.Code, r.Stderr)
			}
			if vm.MustRun(t, record) == "" {
				t.Fatal("no then record after the failed then")
			}
		}
		runs := func(steps, then string) {
			t.Helper()
			vm.MustRun(t, "touch /root/t-ok")
			defer vm.MustRun(t, "rm -f /root/t-ok /root/t-runs")
			dir := project(steps)
			r := lab.Winch(t, dir, "plan", "site")
			if r.Code != 0 || !strings.Contains(r.Stdout, "! then: "+then) {
				t.Fatalf("plan: exit %d, want the pending then\n%s%s", r.Code, r.Stdout, r.Stderr)
			}
			if r = lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
				t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
			}
			if out := vm.MustRun(t, "cat /root/t-runs"); strings.Count(out, "\n") != 1 {
				t.Errorf("then ran %q, want once", out)
			}
			if out := vm.MustRun(t, record); out != "" {
				t.Errorf("then records = %q, want none", out)
			}
		}

		// A step moved below a new step keeps its pending then.
		fails(moved)
		runs(added+moved, "test -e /root/t-ok && echo moved >> /root/t-runs")

		// A loop step without its last element still matches.
		fails(loop)
		runs(strings.Replace(loop, "[a, b]", "[a]", 1), "test -e /root/t-ok && echo loop >> /root/t-runs")

		// A step that is gone gives the note, and apply removes its record.
		fails(gone)
		dir := project(strings.Replace(added, "x\\n", "y\\n", 1))
		r := lab.Winch(t, dir, "plan", "site")
		if want := "reactions: note: a pending then of a file step of stage t matches no step and will not run\n"; r.Code != 0 || r.Stderr != want {
			t.Fatalf("plan: exit %d, stderr %q, want %q", r.Code, r.Stderr, want)
		}
		if r = lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
			t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, record); out != "" {
			t.Errorf("then records = %q, want none", out)
		}
		if r = lab.Winch(t, dir, "plan", "site"); r.Code != 0 || r.Stderr != "" {
			t.Errorf("second plan: exit %d, stderr %q", r.Code, r.Stderr)
		}

		// Apply removes the record also when the host has no change.
		fails(strings.Replace(gone, "/root/t/gone", "/root/t/gone2", 1))
		r = lab.Winch(t, dir, "plan", "site")
		if want := "reactions: note: a pending then of a file step of stage t matches no step and will not run\n"; r.Code != 0 || r.Stderr != want || !strings.Contains(r.Stdout, "0 to change") {
			t.Fatalf("plan: exit %d, stderr %q, want %q\n%s", r.Code, r.Stderr, want, r.Stdout)
		}
		// A plan with only gone records asks nothing.
		if r = lab.Winch(t, dir, "apply", "site"); r.Code != 0 || !strings.Contains(r.Stdout, "0 changed, 1 unchanged") {
			t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, record); out != "" {
			t.Errorf("then records = %q, want none", out)
		}
		if r = lab.Winch(t, dir, "plan", "site"); r.Code != 0 || r.Stderr != "" {
			t.Errorf("third plan: exit %d, stderr %q", r.Code, r.Stderr)
		}
	})
}

const stageReactionsPipeline = `stages:
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
            		tcp dport { {{ join(map(vars.fw_ports, string(#)), ", ") }} } accept
            	}
            }
          mode: "0755"
          validate: nft -c -f /etc/nftables.conf
      - service:
          name: nftables
          enabled: true
          running: true
      - file:
          path: /etc/winch-motd
          content: !tpl "{{ vars.fw_motd }}\n"
      - name: Fails on request
        cmd:
          command: exit 3
        when: !expr vars.fw_break
      - service:
          name: nftables
          reloaded: true
        on_change: [/etc/nftables.conf]
        confirm_access: true
      - cmd:
          command: echo x >> /root/motd-runs
        on_change: [/etc/winch-motd]
`

// spec: Pipelines; Reactions; Running a pipeline/Lockout protection
func TestStageReactions(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "stage-reactions")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: sdemo\ninventory: test\nvars:\n  fw_ports: [22]\n  fw_motd: one\n  fw_break: false\n",
		"inventories/test.yaml": "hosts:\n  stage-reactions: {}\n",
		"pipelines/site.yaml":   stageReactionsPipeline,
	})
	const records = "sed '/^version 1$/d' /var/lib/winch/react/sdemo 2>/dev/null; true"

	t.Run("a reload with confirm_access reloads nftables", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "stage-reactions: firewall: access check passed") {
			t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, "nft list ruleset"); !strings.Contains(out, "tcp dport 22 accept") {
			t.Fatalf("the ruleset is not in place:\n%s", out)
		}
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records = %q, want none", out)
		}
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a rule that drops SSH rolls back the file that the reload reacts to", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.fw_ports=[80]")
		if r.Code != 1 || !strings.Contains(r.Stderr, "stage-reactions: firewall: failed: service nftables: the access check failed: ") ||
			!strings.HasSuffix(r.Stderr, "; the old files are back\n") {
			t.Fatalf("apply: exit %d\n%s", r.Code, r.Stderr)
		}
		if out := vm.MustRun(t, "cat /etc/nftables.conf"); !strings.Contains(out, "tcp dport { 22 } accept") {
			t.Errorf("the old /etc/nftables.conf is not back:\n%s", out)
		}
		if out := vm.MustRun(t, "nft list ruleset"); !strings.Contains(out, "tcp dport 22 accept") {
			t.Errorf("the old ruleset is not back:\n%s", out)
		}
		// The session end drops the record of the reload, with the old files
		// back.
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records = %q, want none", out)
		}
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("plan after the rollback: exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a stopped run leaves the step pending", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.fw_motd=two", "--set", "vars.fw_break=true")
		if r.Code != 1 || !strings.Contains(r.Stderr, "Fails on request") {
			t.Fatalf("apply: exit %d, want the failed step\n%s", r.Code, r.Stderr)
		}
		if out := vm.MustRun(t, records); !strings.Contains(out, `"stage":"firewall","module":"cmd"`) || strings.Count(out, "\n") != 1 {
			t.Errorf("records = %q, want the record of the cmd of stage firewall", out)
		}
		if out := vm.MustRun(t, "cat /root/motd-runs 2>/dev/null; true"); out != "x\n" {
			t.Errorf("the cmd ran %q, want once from the first run", out)
		}
		r = lab.Winch(t, dir, "plan", "site", "--set", "vars.fw_motd=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "! cmd echo x >> /root/motd-runs (pending from an earlier run)") || strings.Contains(r.Stdout, "file") {
			t.Fatalf("plan: exit %d, want only the pending cmd\n%s", r.Code, r.Stdout)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.fw_motd=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "stage-reactions: firewall: ~ cmd echo x >> /root/motd-runs") {
			t.Fatalf("apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, "cat /root/motd-runs"); out != "x\nx\n" {
			t.Errorf("the cmd ran %q, want twice", out)
		}
		if out := vm.MustRun(t, records); out != "" {
			t.Errorf("records = %q, want none", out)
		}
	})
}

// spec: Modules/service and unit (restarted and reloaded); Reactions
func TestRestartAfterStart(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "restart-start")
	vm.MustRun(t, `cat > /etc/systemd/system/winch-hs.service <<'U'
[Service]
ExecStartPre=/bin/sh -c 'echo $$INVOCATION_ID >> /root/invocations'
ExecStart=/bin/sleep infinity
U
systemctl daemon-reload`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: hsdemo\ninventory: test\nvars:\n  hs_value: one\n",
		"inventories/test.yaml": "hosts:\n  restart-start: {}\n",
		"pipelines/site.yaml": `stages:
  - name: app
    hosts: all
    steps:
      - file:
          path: /etc/winch-hs.conf
          content: !tpl "{{ vars.hs_value }}\n"
      - service:
          name: winch-hs
          running: true
      - service:
          name: winch-hs
          restarted: true
        on_change: [/etc/winch-hs.conf]
`,
	})
	invocations := func(want int) {
		t.Helper()
		out := vm.MustRun(t, "cat /root/invocations")
		if ids := strings.Fields(out); len(ids) != want || len(ids) == 2 && ids[0] == ids[1] {
			t.Errorf("winch-hs invocations = %q, want %d different ones", out, want)
		}
	}

	t.Run("a start after the change skips the restart", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 || strings.Count(r.Stdout, "restart-start: app: ~ service winch-hs") != 1 {
			t.Fatalf("apply: exit %d, want a start and no restart\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		invocations(1)
		if out := vm.MustRun(t, "sed '/^version 1$/d' /var/lib/winch/react/hsdemo 2>/dev/null; true"); out != "" {
			t.Errorf("records = %q, want none", out)
		}
	})

	t.Run("a change of a running unit restarts it", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "site", "--set", "vars.hs_value=two")
		if r.Code != 0 || !strings.Contains(r.Stdout, "~ service winch-hs: restart (/etc/winch-hs.conf changes)") {
			t.Fatalf("plan: exit %d, want the restart\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.hs_value=two")
		if r.Code != 0 || strings.Count(r.Stdout, "restart-start: app: ~ service winch-hs") != 1 {
			t.Fatalf("apply: exit %d, want the restart\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		invocations(2)
	})
}
