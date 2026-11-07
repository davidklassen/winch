package project

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
)

// spec: Templates and expressions/Data; Templates and expressions/Template functions; Variables
func TestMatchInTemplateAndDefault(t *testing.T) {
	files := with(matchFiles, map[string]string{
		"winch.yaml": "name: acme\ninventory: test\nvars:\n  mail_server: false\n  role: !expr 'vars.mail_server ? \"mail\" : \"node\"'\n" +
			"  peer_roles: !expr 'join(map(match(\"all\"), .short + \"=\" + .vars.role), \",\")'\n",
		"pipelines/site.yaml":                "stages:\n  - name: monit\n    hosts: all\n    steps:\n      - recipe: monit\n",
		"recipes/monit/templates/peers.tmpl": "{{ range match \"all\" }}{{ .name }} {{ .vars.role }} {{ .facts.os.codename }}\n{{ end }}{{ .vars.peer_roles }}\n",
	})
	p, err := Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	want := `file {"path":"/etc/monit/peers"} data="mail.acme.com mail trixie\nmonitor.acme.com node trixie\nmail=mail,monitor=node\n"`
	if got := evalSteps(t, p); strings.Count(got, want) != 2 {
		t.Errorf("got %q, want %q on each host", got, want)
	}
}

// spec: Variables
func TestDefaultCycleThroughHosts(t *testing.T) {
	tests := []struct {
		name string
		vars string
		want string
	}{
		{name: "hosts", vars: "  a: !expr 'hosts[0].vars.b'\n  b: !expr 'hosts[0].vars.a'\n",
			want: "winch.yaml:6:3: vars.a: the defaults form a cycle: a → b → a"},
		{name: "self", vars: "  a: !expr 'len(filter(match(\"all\"), .vars.a == \"x\"))'\n",
			want: "winch.yaml:6:3: vars.a: the defaults form a cycle: a → a"},
		{name: "template", vars: "  a: !tpl '{{ range .hosts }}{{ .vars.b }}{{ end }}'\n  b: !expr 'vars.a'\n",
			want: "winch.yaml:6:3: vars.a: the defaults form a cycle: a → b → a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := with(matchFiles, map[string]string{
				"winch.yaml": "name: acme\ninventory: test\nvars:\n  mail_server: false\n  role: node\n" + tt.vars,
			})
			_, err := Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// spec: Templates and expressions/Data
func TestPeerDefaultFails(t *testing.T) {
	const want = "vars.zone has no value on host monitor.acme.com"
	for name, content := range map[string]string{
		"template":   "template: peers.tmpl",
		"expression": `content: !expr 'join(map(match("all"), .vars.role), ",")'`,
	} {
		t.Run(name, func(t *testing.T) {
			files := with(matchFiles, map[string]string{
				"winch.yaml":                         "name: acme\ninventory: test\nvars:\n  mail_server: false\n  role: !expr 'vars.zone + \"x\"'\n",
				"inventories/test.yaml":              "hosts:\n  mail.acme.com:\n    vars:\n      zone: a\n  monitor.acme.com: {}\n",
				"pipelines/site.yaml":                "stages:\n  - name: monit\n    hosts: mail.acme.com\n    steps:\n      - recipe: monit\n",
				"recipes/monit/recipe.yaml":          "steps:\n  - file:\n      path: /etc/monit/peers\n      " + content + "\n",
				"recipes/monit/templates/peers.tmpl": "{{ range match \"all\" }}{{ .vars.role }}{{ end }}\n",
			})
			p, err := Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			if got := evalSteps(t, p); !strings.Contains(got, "error: ") || !strings.Contains(got, want) || strings.Contains(got, "data=") {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

// spec: Templates and expressions/Data; Variables
func TestPeerOwnFacts(t *testing.T) {
	files := with(matchFiles, map[string]string{
		"winch.yaml": "name: acme\ninventory: test\nvars:\n  mail_server: false\n  codename: !expr facts.os.codename\n" +
			"  peer_key: !expr 'match(\"mon\")[0].facts.ssh.ed25519'\n",
		"pipelines/site.yaml":                "stages:\n  - name: monit\n    hosts: all\n    steps:\n      - recipe: monit\n",
		"recipes/monit/templates/peers.tmpl": "",
		"recipes/monit/recipe.yaml":          "steps:\n  - file:\n      path: /x\n      content: !expr 'match(\"mon\")[0].vars.codename + \" \" + vars.peer_key'\n",
	})
	p, err := Load(t.Context(), writeProject(t, files), "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	forky := facts.Facts{OS: facts.OS{ID: "debian", Codename: "forky"}, SSH: facts.SSH{ED25519: "ssh-ed25519 AAAA"}}
	mail := p.Inventory.Hosts[0]
	env, err := p.Start(mail, debian13, map[string]HostFacts{"monitor.acme.com": {Facts: forky}})
	if err != nil {
		t.Fatal(err)
	}
	steps, err := p.Pipeline.Stages[0].Steps[0].Recipe.Steps[0].Eval(env.For(&p.Pipeline.Stages[0].Steps[0]))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(steps[0].Args.(*module.File).Data); got != "forky ssh-ed25519 AAAA" {
		t.Errorf("content = %q, want the codename and the key of monitor.acme.com", got)
	}
}
