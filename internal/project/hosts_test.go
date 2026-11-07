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

// spec: Variables
func TestWholePeerHost(t *testing.T) {
	const step, def, tmpl = "recipes/monit/recipe.yaml:6:16", "winch.yaml:6:9", "recipes/monit/templates/peers.tmpl:1:"
	tests := []struct {
		name string
		// content is the content of a file step, peer a default, and tmpl
		// the template of the step.
		content, peer, tmpl string
		// loop is the loop of the file step.
		loop string
		// at is the start of the load error, or "" when the project loads.
		at string
	}{
		{name: "json of hosts in a step", content: `json(hosts)`, at: step},
		{name: "json of hosts in a default", peer: `json(hosts)`, at: def},
		{name: "json of a host in a step", content: `json(match("mon")[0])`, at: step},
		{name: "json of a host in a default", peer: `json(match("mon")[0])`, at: def},
		{name: "string of match", content: `string(match("mon"))`, at: step},
		{name: "computed key", content: `string(match("mon")[0][item])`, loop: "[vars]", at: step},
		{name: "values", content: `string(len(values(match("mon")[0])))`, at: step},
		{name: "filter", content: `json(filter(hosts, .name != host.name))`, at: step},
		{name: "find", content: `json(find(hosts, .name != host.name))`, at: step},
		{name: "first", content: `json(first(match("mon")))`, at: step},
		{name: "slice", content: `json(hosts[0:1])`, at: step},
		{name: "map to the host", content: `json(map(hosts, #))`, at: step},
		{name: "element in a closure", content: `join(map(hosts, json(#)), ",")`, at: step},
		{name: "let", content: `let h = match("mon")[0]; json(h)`, at: step},
		{name: "conditional", content: `json(true ? hosts : [])`, at: step},
		{name: "array", content: `json([match("mon")[0]])`, at: step},
		{name: "map literal", content: `json({"p": hosts})`, at: step},
		{name: "pipe", content: `hosts | json()`, at: step},
		{name: "template json", tmpl: `{{ json .hosts }}`, at: tmpl + "9"},
		{name: "template print", tmpl: `{{ .hosts }}`, at: tmpl + "4"},
		{name: "template pipe", tmpl: `{{ .hosts | json }}`, at: tmpl + "4"},
		{name: "template dot", tmpl: `{{ range match "mon" }}{{ . }}{{ end }}`, at: tmpl + "27"},
		{name: "template json of dot", tmpl: `{{ range .hosts }}{{ json . }}{{ end }}`, at: tmpl + "27"},
		{name: "template index", tmpl: `{{ json (index (match "mon") 0) }}`, at: tmpl + "10"},
		{name: "template variable", tmpl: `{{ $h := index .hosts 0 }}{{ json $h }}`, at: tmpl + "35"},
		{name: "template range variable", tmpl: `{{ range $h := .hosts }}{{ printf "%v" $h }}{{ end }}`, at: tmpl + "40"},
		{name: "template range over a host", tmpl: `{{ range $k, $v := index .hosts 0 }}{{ $k }}{{ end }}`, at: tmpl + "20"},
		{name: "template with", tmpl: `{{ with index .hosts 0 }}{{ json . }}{{ end }}`, at: tmpl + "34"},
		{name: "template computed key", tmpl: `{{ range .hosts }}{{ index . .name }}{{ end }}`, at: tmpl + "30"},
		{name: "template defined", tmpl: `{{ define "p" }}{{ .name }}{{ end }}{{ range .hosts }}{{ template "p" . }}{{ end }}`, at: tmpl + "71"},
		{name: "template shadowed variable", tmpl: `{{ $h := index .hosts 0 }}{{ range $h := .vars.monit_peers }}{{ end }}{{ json $h }}`, at: tmpl + "79"},
		{name: "reduce", content: `json(reduce(hosts, #acc))`, at: step},
		{name: "element in a nested closure", content: `join(map(hosts, string(len(groupBy(.groups, #)))), ",")`},
		{name: "template if variable", tmpl: `{{ if $h := index .hosts 0 }}{{ json $h }}{{ end }}`, at: tmpl + "38"},
		{name: "template assignment in a body", tmpl: `{{ $h := "" }}{{ if true }}{{ $h = index .hosts 0 }}{{ end }}{{ json $h }}`, at: tmpl + "36"},
		{name: "template assignment in a range", tmpl: `{{ $h := "" }}{{ range $i, $x := .hosts }}{{ $h = $x }}{{ end }}{{ json $h }}`, at: tmpl + "51"},
		{name: "template declaration in a body", tmpl: `{{ $h := index .hosts 0 }}{{ if true }}{{ $h := 1 }}{{ $h }}{{ end }}{{ $h.name }}`},
		{name: "template range assignment", tmpl: `{{ $h := 1 }}{{ range $h = .hosts }}{{ end }}{{ json $h }}`, at: tmpl + "28"},
		{name: "concat", content: `json(concat(hosts, match("mon")))`, at: step},
		{name: "sortBy", content: `json(sortBy(hosts, .name))`, at: step},
		{name: "get by a computed key", content: `string(get(match("mon")[0], item))`, loop: "[vars]", at: step},
		{name: "host or list", content: `string((true ? hosts : hosts[0])[item].name)`, loop: "[vars]", at: step},
		{name: "list in an array", content: `json([hosts])`, at: step},
		{name: "template hosts of the data", tmpl: `{{ range .vars.monit_peers }}{{ json $.hosts }}{{ end }}`, at: tmpl + "39"},
		{name: "last by name", content: `last(hosts).name`},
		{name: "concat by name", content: `join(map(concat(match("mon"), match("all")), .name), ",")`},
		{name: "template assignment that may not run", tmpl: `{{ $h := index .hosts 0 }}{{ if .vars.monit_peers }}{{ $h = "" }}{{ end }}{{ json $h }}`, at: tmpl + "83"},
		{name: "template assignment in an empty range", tmpl: `{{ $h := index .hosts 0 }}{{ range .vars.monit_peers }}{{ $h = "" }}{{ end }}{{ json $h }}`, at: tmpl + "86"},
		{name: "template read before an assignment", tmpl: `{{ $h := "" }}{{ range $i, $x := .hosts }}{{ json $h }}{{ $h = $x }}{{ end }}`, at: tmpl + "64"},
		{name: "name in a step", content: `match("mon")[0].name`},
		{name: "name in a default", peer: `match("mon")[0].name`},
		{name: "variable in a step", content: `string(match("mon")[0].vars.role)`},
		{name: "variable in a default", peer: `string(hosts[0].vars.role)`},
		{name: "len", content: `string(len(hosts))`},
		{name: "map", content: `join(map(hosts, .name), ",")`},
		{name: "let by name", content: `let h = first(match("mon")); h.name`},
		{name: "find by name", content: `find(hosts, .name != host.name)?.address ?? ""`},
		{name: "filter value", peer: `filter(match("all"), .name != host.name)`},
		{name: "template range", tmpl: `{{ range .hosts }}{{ .name }} {{ .vars.role }}{{ end }}`},
		{name: "template chain", tmpl: `{{ (index .hosts 0).name }}`},
		{name: "template len", tmpl: `{{ len (match "mon") }}`},
		{name: "template with by name", tmpl: `{{ with index (match "mon") 0 }}{{ .vars.role }}{{ end }}`},
		{name: "template range variable by name", tmpl: `{{ range $h := match "mon" }}{{ $h.name }}{{ end }}`},
		{name: "template if", tmpl: `{{ if .hosts }}x{{ end }}`},
		{name: "template peers", tmpl: `{{ range .vars.monit_peers }}{{ .name }}{{ end }}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := "!expr '" + tt.content + "'"
			if tt.content == "" {
				content = "x"
			}
			if tt.loop != "" {
				content += "\n    loop: " + tt.loop
			}
			if tt.tmpl != "" {
				content = "x\n  - file:\n      path: /y\n      template: peers.tmpl"
			}
			winch := matchFiles["winch.yaml"]
			if tt.peer != "" {
				winch += "  peer: !expr '" + tt.peer + "'\n"
			}
			files := with(matchFiles, map[string]string{
				"winch.yaml":                         winch,
				"recipes/monit/recipe.yaml":          "vars:\n  monit_peers: []\nsteps:\n  - file:\n      path: /x\n      content: " + content + "\n",
				"recipes/monit/templates/peers.tmpl": tt.tmpl,
			})
			dir := writeProject(t, files)
			_, err := Load(t.Context(), dir, "", "site", nil, Keys{})
			_, verr := Validate(dir, "", nil)
			for what, err := range map[string]error{"Load": err, "Validate": verr} {
				switch {
				case tt.at == "" && err != nil:
					t.Errorf("%s error = %v", what, err)
				case tt.at != "" && (err == nil || !strings.HasPrefix(err.Error(), tt.at) || !strings.Contains(err.Error(), notByName)):
					t.Errorf("%s error = %v, want %s...: %s", what, err, tt.at, notByName)
				}
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
