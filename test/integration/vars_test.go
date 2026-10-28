package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Steps (when, loop); Variables; Variables/Sources; Inventory; Templates and expressions
func TestVarsWhenLoop(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "vars")
	// A second host in another group. It runs at the same time as the first,
	// so it needs its own VM.
	relay := lab.StartVM(t, "vars-relay")

	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml": `name: demo
inventory: test
vars:
  relay: false
`,
		"inventories/test.yaml": `hosts:
  vars: {}
  vars-relay: {}
groups:
  relays:
    hosts: [vars-relay]
    vars:
      relay: true
      site_users: [ann, bob]
`,
		"pipelines/site.yaml": `stages:
  - name: site
    hosts: all
    steps:
      - recipe: site
`,
		"recipes/site/recipe.yaml": `vars:
  site_dir: !tpl /srv/{{ .host.short }}
  site_users: [ann]
steps:
  - dir:
      path: !expr vars.site_dir
  - file:
      path: !tpl "{{ .vars.site_dir }}/{{ .item }}"
      content: !tpl "{{ .item }} on {{ .host.name }}\n"
    loop: !expr vars.site_users
  - file:
      path: !tpl "{{ .vars.site_dir }}/relay.conf"
      template: relay.tmpl
    when: !expr vars.relay
`,
		"recipes/site/templates/relay.tmpl": "relay for {{ join .vars.site_users \", \" }}\n",
	})

	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	for path, want := range map[string]string{
		"/srv/vars/ann":              "ann on vars\n",
		"/srv/vars-relay/ann":        "ann on vars-relay\n",
		"/srv/vars-relay/bob":        "bob on vars-relay\n",
		"/srv/vars-relay/relay.conf": "relay for ann, bob\n",
	} {
		host := vm
		if strings.HasPrefix(path, "/srv/vars-relay/") {
			host = relay
		}
		if out := host.MustRun(t, "cat "+path); out != want {
			t.Errorf("%s = %q, want %q", path, out, want)
		}
	}
	if out := vm.MustRun(t, "ls /srv/vars"); out != "ann\n" {
		t.Errorf("/srv/vars holds %q, want only ann", out)
	}

	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 2) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
