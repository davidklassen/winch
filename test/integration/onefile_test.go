package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Project layout; Modules/service and unit; Modules/repo
func TestOneFileProject(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "onefile")
	key := strings.ReplaceAll(strings.TrimRight(string(vmtest.RepoKey), "\n"), "\n", "\n            ")
	dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": `name: onefile
inventory: test
inventories:
  test:
    hosts:
      onefile: {}
pipelines:
  site:
    stages:
      - name: site
        hosts: all
        steps:
          - recipe: app
recipes:
  app:
    vars:
      app_word: one
    steps:
      - unit:
          name: winch-one.service
          content: !tpl |
            [Service]
            Environment=WORD={{ .vars.app_word }}
            ExecStart=/bin/sleep infinity
      - repo:
          name: winch-signed
          url: ` + signedURL + `
          suite: ` + osRelease().codename + `
          components: [main]
          key_content: |
            ` + key + `
`})
	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if out := vm.MustRun(t, "systemctl show -P Environment winch-one; cmp "+signedAsc+" - <<'EOF'\n"+string(vmtest.RepoKey)+"EOF"); out != "WORD=one\n" {
		t.Errorf("after apply: %q", out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}
