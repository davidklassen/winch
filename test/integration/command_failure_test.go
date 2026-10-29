package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules (commands)
func TestProjectCommandFailure(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "command-failure")
	cases := []struct{ name, steps, health, want string }{
		{"cmd", "      - cmd:\n          command: |\n            false\n            true\n", "", "exit status 1"},
		{"assert", "      - assert:\n          command: |\n            false\n            true\n          message: first check failed\n", "", "first check failed"},
		{"then", "      - file:\n          path: /root/command-file\n          content: new\n        then: |\n          false\n          true\n", "", "exit status 1"},
		{"validate-file", "      - file:\n          path: /root/command-file\n          content: new\n          validate: |\n            false\n            true\n", "", "exit status 1"},
		{"validate-line", "      - line:\n          path: /root/command-file\n          line: new\n          match: ^new$\n          validate: |\n            false\n            true\n", "", "exit status 1"},
		{"validate-link", "      - link:\n          path: /root/command-file\n          target: /etc/hostname\n          validate: |\n            false\n            true\n", "", "exit status 1"},
		{"health", "", "    health:\n      command: |\n        false\n        true\n      stable: 1\n      timeout: 3\n", "did not pass within 3s: exit status 1"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			vm.MustRun(t, "rm -f /root/command-file /root/command-after")
			if tt.name == "validate-line" {
				vm.MustRun(t, "touch /root/command-file")
			}
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: commands\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  command-failure: {}\n",
				"pipelines/site.yaml":   "stages:\n  - name: test\n    hosts: all\n" + tt.health + "    steps:\n      - cmd:\n          command: 'true'\n" + tt.steps + "  - name: after\n    hosts: all\n    steps:\n      - cmd:\n          command: touch /root/command-after\n",
			})
			r := lab.Winch(t, dir, "apply", "site", "--yes")
			if r.Code != 1 || !strings.Contains(r.Stderr, tt.want) {
				t.Errorf("apply: exit %d, stderr %q; want exit 1 and %q", r.Code, r.Stderr, tt.want)
			}
			if out := vm.MustRun(t, "test ! -e /root/command-after && echo stopped; true"); out != "stopped\n" {
				t.Errorf("later stage ran: %q", out)
			}
			if tt.name == "validate-line" {
				vm.MustRun(t, "test ! -s /root/command-file")
			} else if strings.HasPrefix(tt.name, "validate-") {
				vm.MustRun(t, "test ! -e /root/command-file")
			}
		})
	}
}

// spec: Modules (commands); Modules/certbot
func TestCertbotCommandFailure(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "hook-failure")
	startPebble(t, vm)
	for _, hook := range []string{"pre_hook", "post_hook", "deploy_hook"} {
		t.Run(hook, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: hooks\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  hook-failure: {}\n",
				"pipelines/site.yaml":   fmt.Sprintf("stages:\n  - name: test\n    hosts: all\n    steps:\n      - certbot:\n          name: %s\n          domains: [a.example.com]\n          email: admin@example.com\n          %s: |\n            false\n            true\n", hook, hook),
			})
			r := lab.Winch(t, dir, "apply", "site", "--yes")
			want := "Hook '" + strings.ReplaceAll(hook, "_", "-") + "' reported error code 1"
			if r.Code != 1 || !strings.Contains(r.Stderr, want) {
				t.Errorf("apply: exit %d, stderr %q; want exit 1 and %q", r.Code, r.Stderr, want)
			}
			out := vm.MustRun(t, "certbot renew --no-random-sleep-on-renew --cert-name "+hook+" --force-renewal 2>&1")
			if !strings.Contains(out, want) {
				t.Errorf("renewal: no %q in %q", want, out)
			}

		})
	}
}

// spec: Modules (commands); Modules/certbot
func TestCertbotHookShell(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "hook-shell")
	startPebble(t, vm)
	hooks := ""
	for _, hook := range []string{"pre_hook", "post_hook", "deploy_hook"} {
		hooks += fmt.Sprintf("          %s: |\n            if true; then\n              printf \"it's literal: $HOME\\n\" >> /root/%s\n            fi\n", hook, hook)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: hooks\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  hook-shell: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: test\n    hosts: all\n    steps:\n      - certbot:\n          name: a.example.com\n          domains: [a.example.com]\n          email: admin@example.com\n" + hooks,
	})
	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d, stderr %q", r.Code, r.Stderr)
	}
	if r := lab.Winch(t, dir, "plan", "site", "--exit-code"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after issue: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "certbot renew --no-random-sleep-on-renew --cert-name a.example.com --force-renewal >/root/renew.log 2>&1 || { cat /root/renew.log; exit 1; }")
	for _, hook := range []string{"pre_hook", "post_hook", "deploy_hook"} {
		if out := vm.MustRun(t, "cat /root/"+hook); out != "it's literal: /root\nit's literal: /root\n" {
			t.Errorf("%s after issue and renewal: %q", hook, out)
		}
	}
}
