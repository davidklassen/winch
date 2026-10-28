package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/pkg
func TestPkgRemovalInOneRun(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pkgremoval")
	vm.MustRun(t, "apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q exim4-daemon-light hello >/dev/null")
	vm.MustRun(t, installNeedsHello)
	const stage = "stages:\n  - name: packages\n    hosts: all\n    steps:\n"
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: pkgremoval\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  pkgremoval: {}\n",
		"pipelines/postfix.yaml": stage +
			"      - pkg: {name: postfix}\n",
		"pipelines/part.yaml": stage +
			"      - pkg: {name: exim4-daemon-light, absent: true}\n" +
			"      - pkg: {name: postfix}\n",
		"pipelines/late.yaml": stage +
			"      - pkg: {name: postfix}\n" +
			"      - pkg: {name: [exim4-daemon-light, exim4-config, exim4-base], absent: true}\n",
		"pipelines/mail.yaml": stage +
			"      - pkg: {name: [exim4-daemon-light, exim4-config, exim4-base], absent: true}\n" +
			"      - pkg: {name: postfix}\n",
		"pipelines/conflict.yaml": stage +
			"      - pkg: {name: hello, absent: true}\n" +
			"      - pkg: {name: winch-conflict}\n",
	})
	hint := func(n string) string {
		return "apt must remove " + n + "; add a pkg step with name: " + n + " and absent: true before this step"
	}
	t.Run("without the absent step, the check names each removal", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "postfix")
		for _, n := range []string{"exim4-daemon-light", "exim4-config", "exim4-base"} {
			if r.Code == 0 || !strings.Contains(r.Stderr, hint(n)) {
				t.Errorf("plan: exit %d, want %q, stdout %q, stderr %q", r.Code, hint(n), r.Stdout, r.Stderr)
			}
		}
	})
	t.Run("the check names only the removals that no earlier step makes", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "part")
		if r.Code == 0 || strings.Contains(r.Stderr, hint("exim4-daemon-light")) || !strings.Contains(r.Stderr, hint("exim4-config")) || !strings.Contains(r.Stderr, hint("exim4-base")) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	t.Run("a later absent step does not count", func(t *testing.T) {
		r := lab.Winch(t, dir, "plan", "late")
		for _, n := range []string{"exim4-daemon-light", "exim4-config", "exim4-base"} {
			if r.Code == 0 || !strings.Contains(r.Stderr, hint(n)) {
				t.Errorf("plan: exit %d, want %q, stdout %q, stderr %q", r.Code, hint(n), r.Stdout, r.Stderr)
			}
		}
	})
	t.Run("an earlier absent step lets the install converge in one run", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "mail", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, "dpkg-query -W -f='${db:Status-Abbrev}' postfix | grep -q '^ii' && ! dpkg-query -W -f='${db:Status-Abbrev}' exim4-daemon-light | grep -q '^ii'")
		if r := lab.Winch(t, dir, "plan", "mail"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
	t.Run("the packages that an absent step also removes count", func(t *testing.T) {
		r := lab.Winch(t, dir, "apply", "conflict", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "also remove winch-needs-hello") {
			t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, "dpkg-query -W -f='${db:Status-Abbrev}' winch-conflict | grep -q '^ii' && ! dpkg -s hello >/dev/null 2>&1 && ! dpkg -s winch-needs-hello >/dev/null 2>&1")
		if r := lab.Winch(t, dir, "plan", "conflict"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})
}
