package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/file, dir, link (dir purge keeps generated files)
func TestPurgePostmap(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "postmap")
	vm.MustRun(t, "mkdir /etc/winch-maps && touch /etc/winch-maps/stale")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: purge\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  postmap: {}\n",
		"pipelines/site.yaml": `stages:
  - name: maps
    hosts: all
    steps:
      - pkg:
          name: postfix
      - dir:
          path: /etc/winch-maps
          purge: true
          keep: ["*.db"]
      - file:
          path: /etc/winch-maps/virtual
          content: "alice@example.org bob@example.org\n"
        then: postmap /etc/winch-maps/virtual
      - recipe: app
`,
		"recipes/app/recipe.yaml": `steps:
  - file:
      path: /etc/winch-maps/aliases
      content: "carol@example.org dave@example.org\n"
    notify: rebuild
handlers:
  rebuild:
    - cmd:
        command: postmap /etc/winch-maps/aliases
`,
	})
	for run := 1; run <= 4; run++ {
		if run == 4 {
			vm.MustRun(t, "touch /etc/winch-maps/stale")
		}
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply %d: exit %d, stdout %q, stderr %q", run, r.Code, r.Stdout, r.Stderr)
		}
		if got := vm.MustRun(t, "postmap -q alice@example.org /etc/winch-maps/virtual"); got != "bob@example.org\n" {
			t.Fatalf("apply %d: map lookup = %q", run, got)
		}
		if got := vm.MustRun(t, "postmap -q carol@example.org /etc/winch-maps/aliases"); got != "dave@example.org\n" {
			t.Fatalf("apply %d: handler map lookup = %q", run, got)
		}
		vm.MustRun(t, "test ! -e /etc/winch-maps/stale")
		if (run == 2 || run == 3) && !strings.Contains(r.Stdout, "1 host: 0 to change, 1 unchanged") {
			t.Errorf("apply %d did not converge: %s", run, r.Stdout)
		}
		if run == 4 && !strings.Contains(r.Stdout, "remove file /etc/winch-maps/stale") {
			t.Errorf("drift apply did not purge stale file: %s", r.Stdout)
		}
	}
}
