package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/cmd; Modules (the command rules); Running a pipeline/Plan
func TestCmdModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "cmd")
	reset := "rm -rf /root/out /root/made /root/fixed /tmp/winch-out /srv/winch-c /srv/winch-missing; userdel -r winchc 2>/dev/null; userdel winch-nobody 2>/dev/null; groupdel winchg 2>/dev/null; true"
	user := "useradd -m -s /bin/sh winchc && groupadd winchg && usermod -aG winchg winchc\n"
	vmtest.RunCases(t, vm, "cmd", reset, []vmtest.Case{
		{
			Name:       "without creates",
			Args:       &module.Cmd{Command: "echo ran > /root/out"},
			Want:       module.Result{Status: module.Unknown},
			Unchanged:  "test ! -e /root/out",
			After:      "grep -qx ran /root/out",
			NoConverge: true,
		},
		{
			Name:      "a missing creates",
			Args:      &module.Cmd{Command: "touch /root/made", Creates: "/root/made"},
			Want:      module.Result{Status: module.Change, Action: module.Create},
			Unchanged: "test ! -e /root/made",
			After:     "test -e /root/made",
		},
		{
			Name:         "a command that does not make creates",
			Args:         &module.Cmd{Command: "touch /root/made", Creates: "/root/out"},
			Want:         module.Result{Status: module.Change, Action: module.Create},
			WantApplyErr: "the command did not create /root/out",
			After:        "test -e /root/made",
			FixArgs:      &module.Cmd{Command: "touch /root/fixed", Creates: "/root/fixed"},
		},
		{
			Name:  "creates exists",
			Setup: "touch /root/made",
			Args:  &module.Cmd{Command: "echo ran > /root/out", Creates: "/root/made"},
			Want:  module.Result{Status: module.OK},
			After: "test ! -e /root/out",
		},
		{
			Name:       "the command environment",
			Args:       &module.Cmd{Command: `{ pwd; id -un; echo "$HOME"; umask; echo "$LC_ALL"; wc -c; } > /root/out`},
			Want:       module.Result{Status: module.Unknown},
			After:      `test "$(cat /root/out)" = "$(printf '/\nroot\n/root\n0022\nC.UTF-8\n0')"`,
			NoConverge: true,
		},
		{
			Name:       "user",
			Setup:      user,
			Args:       &module.Cmd{Command: `{ pwd; id -un; id -Gn; echo "$HOME"; echo "$USER"; echo "$LOGNAME"; } > /tmp/winch-out`, User: "winchc"},
			Want:       module.Result{Status: module.Unknown},
			After:      `test "$(cat /tmp/winch-out)" = "$(printf '/\nwinchc\nwinchc winchg\n/home/winchc\nwinchc\nwinchc')" && test "$(stat -c %U /tmp/winch-out)" = winchc`,
			NoConverge: true,
		},
		{
			Name:       "dir",
			Args:       &module.Cmd{Command: "pwd > /root/out", Dir: "/srv"},
			Want:       module.Result{Status: module.Unknown},
			After:      "grep -qx /srv /root/out",
			NoConverge: true,
		},
		{
			Name:       "user and dir",
			Setup:      user + "mkdir /srv/winch-c && chown winchc /srv/winch-c",
			Args:       &module.Cmd{Command: "pwd > out; id -un >> out", User: "winchc", Dir: "/srv/winch-c"},
			Want:       module.Result{Status: module.Unknown},
			After:      `test "$(cat /srv/winch-c/out)" = "$(printf '/srv/winch-c\nwinchc')"`,
			NoConverge: true,
		},
		{
			Name:         "a dir that the user cannot enter",
			Setup:        user + "mkdir -m 0700 /srv/winch-c",
			Args:         &module.Cmd{Command: "true", User: "winchc", Dir: "/srv/winch-c"},
			Want:         module.Result{Status: module.Unknown},
			WantApplyErr: "dir /srv/winch-c: permission denied",
			Fix:          "chmod 0755 /srv/winch-c",
			NoConverge:   true,
		},
		{
			Name:         "a missing user",
			Args:         &module.Cmd{Command: "true", User: "winch-nobody"},
			Want:         module.Result{Status: module.Unknown},
			WantApplyErr: "user winch-nobody does not exist",
			Fix:          "useradd winch-nobody",
			NoConverge:   true,
		},
		{
			Name:         "a missing dir",
			Args:         &module.Cmd{Command: "true", Dir: "/srv/winch-missing"},
			Want:         module.Result{Status: module.Unknown},
			WantApplyErr: "/srv/winch-missing",
			Fix:          "mkdir /srv/winch-missing",
			NoConverge:   true,
		},
		{
			Name:         "a failing command",
			Args:         &module.Cmd{Command: "test -e /root/fixed || { echo the cause; exit 3; }"},
			Want:         module.Result{Status: module.Unknown},
			WantApplyErr: "exit status 3: the cause",
			Fix:          "touch /root/fixed",
			NoConverge:   true,
		},
	})
}

// spec: Modules/assert
func TestAssertModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "assert")
	vmtest.RunCases(t, vm, "assert", "rm -f /root/ran", []vmtest.Case{
		{
			Name:       "a passing assert",
			Args:       &module.Assert{Command: "touch /root/ran", Message: "x"},
			Want:       module.Result{Status: module.OK, Deferred: true},
			Unchanged:  "test ! -e /root/ran",
			After:      "test -e /root/ran",
			NoConverge: true,
		},
		{
			Name:         "a failing assert",
			Args:         &module.Assert{Command: "test -e /root/ran", Message: "the marker is missing"},
			Want:         module.Result{Status: module.OK, Deferred: true},
			WantApplyErr: "the marker is missing",
			Fix:          "touch /root/ran",
			NoConverge:   true,
		},
	})
}

const cmdRecipe = `steps:
  - cmd:
      command: echo built > /root/built
      creates: /root/built
  - cmd:
      command: date >> /root/runs
    notify: restart
handlers:
  restart:
    - cmd:
        command: echo restarted >> /root/handler
`

const gatePipeline = `stages:
  - name: gate
    hosts: all
    steps:
      - file:
          path: /root/gate
          content: "x\n"
      - assert:
          command: test -e /root/open
          message: the gate is closed
      - file:
          path: /root/after
          content: "x\n"
`

// spec: Modules/cmd; Modules/assert; Steps; CLI ("--exit-code"); Modules/reboot
func TestCmdPipeline(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "cmdpipe")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":              "name: cmds\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml":   "hosts:\n  cmdpipe: {}\n",
		"pipelines/site.yaml":     "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: app\n",
		"pipelines/uptime.yaml":   "stages:\n  - name: s\n    hosts: all\n    steps:\n      - cmd:\n          command: uptime\n",
		"pipelines/gate.yaml":     gatePipeline,
		"recipes/app/recipe.yaml": cmdRecipe,
	})

	r := lab.Winch(t, dir, "plan", "site", "--exit-code")
	for _, want := range []string{"+ cmd echo built > /root/built\n", "? cmd date >> /root/runs\n", "! handler app.restart\n", "1 host: 1 to change, 0 unchanged, 0 unknown\n"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("first plan: no %q in %q", want, r.Stdout)
		}
	}
	if r.Code != 2 {
		t.Errorf("first plan: exit %d, want 2", r.Code)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d, stderr %q", r.Code, r.Stderr)
	}
	if out := vm.MustRun(t, "cat /root/built; wc -l < /root/runs; cat /root/handler"); out != "built\n1\nrestarted\n" {
		t.Errorf("after apply: %q", out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if strings.Contains(r.Stdout, "+ cmd") || !strings.Contains(r.Stdout, "? cmd date >> /root/runs\n") {
		t.Errorf("second plan: %q", r.Stdout)
	}

	r = lab.Winch(t, dir, "plan", "uptime", "--exit-code")
	if r.Code != 2 || !strings.HasSuffix(strings.SplitN(r.Stdout, "plan ", 2)[0], "    ? cmd uptime\n\n1 host: 0 to change, 0 unchanged, 1 unknown\n") {
		t.Errorf("a plan with only ? lines: exit %d, stdout %q", r.Code, r.Stdout)
	}

	r = lab.Winch(t, dir, "apply", "gate", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "cmdpipe: gate: failed: assert test -e /root/open: the gate is closed\n") {
		t.Errorf("a failing assert: exit %d, stderr %q", r.Code, r.Stderr)
	}
	if out := vm.MustRun(t, "test -e /root/gate && echo gate; test -e /root/after && echo after; true"); out != "gate\n" {
		t.Errorf("after a failing assert: %q, want only /root/gate", out)
	}
	vm.MustRun(t, "touch /root/open")
	if r := lab.Winch(t, dir, "apply", "gate", "--yes"); r.Code != 0 {
		t.Errorf("a passing assert: exit %d, stderr %q", r.Code, r.Stderr)
	}
	vm.MustRun(t, "test -e /root/after && rm /root/open")
	// Only the assert is left: the host has no change, and apply skips it.
	r = lab.Winch(t, dir, "apply", "gate", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "1 host: 0 to change, 1 unchanged, 0 unknown\n") {
		t.Errorf("a plan with only an assert: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}

// winch-reconf writes its answer to /etc/winch-reconf in its postinst.
const reconfRecipe = `vars:
  reconf_enabled: false
steps:
  - debconf:
      package: winch-reconf
      question: winch-reconf/enabled
      type: boolean
      value: !tpl "{{ .vars.reconf_enabled }}"
    notify: reconfigure
  - pkg:
      name: winch-reconf
handlers:
  reconfigure:
    - cmd:
        command: dpkg-reconfigure -f noninteractive winch-reconf
`

// spec: Modules/debconf (a handler runs dpkg-reconfigure); Steps
func TestCmdHandler(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "cmdhandler")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":                 "name: reconf\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml":      "hosts:\n  cmdhandler: {}\n",
		"pipelines/site.yaml":        "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: reconf\n",
		"recipes/reconf/recipe.yaml": reconfRecipe,
	})
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("first apply: exit %d, stderr %q", r.Code, r.Stderr)
	}
	if out := vm.MustRun(t, "cat /etc/winch-reconf"); out != "false\n" {
		t.Errorf("after the first apply: %q", out)
	}
	r := lab.Winch(t, dir, "plan", "site", "--set", "vars.reconf_enabled=true")
	for _, want := range []string{"~ debconf winch-reconf/enabled\n", "! handler reconf.reconfigure\n"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("plan of the new answer: no %q in %q", want, r.Stdout)
		}
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes", "--set", "vars.reconf_enabled=true"); r.Code != 0 {
		t.Fatalf("second apply: exit %d, stderr %q", r.Code, r.Stderr)
	}
	if out := vm.MustRun(t, "cat /etc/winch-reconf"); out != "true\n" {
		t.Errorf("after the new answer: %q", out)
	}
	if r := lab.Winch(t, dir, "plan", "site", "--set", "vars.reconf_enabled=true"); !unchanged(r.Stdout, 1) {
		t.Errorf("third plan: %q", r.Stdout)
	}
}
