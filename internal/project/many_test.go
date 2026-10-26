package project

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/secret"
)

var manyProject = map[string]string{
	"winch.yaml": "name: acme\ninventory: inventories/test.yaml\n",
	"inventories/test.yaml": `hosts:
  web1: {}
  web2: {}
  web3: {}
  db1: {}
groups:
  web:
    hosts: [web1, web2, web3]
  db:
    hosts: [db1]
  prod:
    hosts: [db1, web1]
  empty:
    hosts: []
`,
	"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    steps: []\n",
}

func hostNames(hosts []Host) string {
	var out []string
	for _, h := range hosts {
		out = append(out, h.Name)
	}
	return strings.Join(out, ",")
}

// spec: Inventory/Host patterns
func TestPattern(t *testing.T) {
	p, err := Load(writeProject(t, manyProject), "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		pattern string
		want    string
		wantErr string
	}{
		{pattern: "web", want: "web1,web2,web3"},
		{pattern: "web2", want: "web2"},
		{pattern: "all", want: "web1,web2,web3,db1"},
		{pattern: "web,db", want: "web1,web2,web3,db1"},
		{pattern: "db,web1", want: "web1,db1"},
		{pattern: "web & prod", want: "web1"},
		{pattern: "web & !web3", want: "web1,web2"},
		{pattern: "!web3 & web", want: "web1,web2"},
		{pattern: "web & !web3, db", want: "web1,web2,db1"},
		{pattern: "db, web & !web1", want: "web2,web3,db1"},
		{pattern: "all & !web & !db", want: ""},
		{pattern: "  web1 ,web2  ", want: "web1,web2"},
		{pattern: "empty", want: ""},
		{pattern: "empty,web1", want: "web1"},
		{pattern: "", wantErr: "an empty host pattern"},
		{pattern: "  ", wantErr: "an empty host pattern"},
		{pattern: ",", wantErr: `host pattern ",": an empty part`},
		{pattern: "web,,db", wantErr: `host pattern "web,,db": an empty part`},
		{pattern: "web &", wantErr: `host pattern "web &": an empty name`},
		{pattern: "web & !", wantErr: `host pattern "web & !": an empty name`},
		{pattern: "!web", wantErr: `host pattern "!web": the part "!web" needs a host or group without !, such as all & !web`},
		{pattern: "web & !wbe3", wantErr: `unknown host or group "wbe3" in inventories/test.yaml; did you mean "web3"?`},
		{pattern: "!!web", wantErr: `unknown host or group "!web"`},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			hosts, err := p.Inventory.Match(tt.pattern)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := hostNames(hosts); got != tt.want {
				t.Errorf("hosts = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Inventory/Host patterns; Pipelines
func TestStagePattern(t *testing.T) {
	p, err := Load(writeProject(t, with(manyProject, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: web & !web2, db\n    steps: []\n",
	})), "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	if got := hostNames(p.Pipeline.Stages[0].Targets); got != "web1,web3,db1" {
		t.Errorf("targets = %q", got)
	}
	_, err = Load(writeProject(t, with(manyProject, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: a\n    hosts: web & !wbe2\n    steps: []\n",
	})), "", "site", nil, Keys{})
	if err == nil || !strings.Contains(err.Error(), `pipelines/site.yaml:3:12: unknown host or group "wbe2" in inventories/test.yaml; did you mean "web2"?`) {
		t.Errorf("error = %v", err)
	}
}

// spec: Inventory/Host patterns
func TestHostNameCharacters(t *testing.T) {
	tests := []struct {
		inventory string
		want      string
	}{
		{"hosts:\n  \"web,1\": {address: 192.0.2.1}\n", `inventories/test.yaml:2:3: host "web,1": a host name cannot hold ",", "&", "!", or white space; a host pattern could not name it`},
		{"hosts:\n  \"!web\": {address: 192.0.2.1}\n", `host "!web": a host name cannot hold`},
		{"hosts:\n  web1: {}\ngroups:\n  \"a&b\":\n    hosts: [web1]\n", `inventories/test.yaml:4:3: group "a&b": a group name cannot hold ",", "&", "!", or white space; a host pattern could not name it`},
		{"hosts:\n  web1: {}\ngroups:\n  \"a b\":\n    hosts: [web1]\n", `group "a b": a group name cannot hold`},
	}
	for _, tt := range tests {
		t.Run(tt.inventory, func(t *testing.T) {
			_, err := Load(writeProject(t, with(manyProject, map[string]string{"inventories/test.yaml": tt.inventory})), "", "site", nil, Keys{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

const selectPipeline = `stages:
  - name: base
    hosts: all
    steps: []
  - name: web
    hosts: web
    steps: []
  - name: db
    hosts: db
    steps: []
`

// spec: CLI; Inventory/Host patterns
func TestSelect(t *testing.T) {
	tests := []struct {
		name    string
		sel     Selection
		want    string
		wantErr string
	}{
		{name: "nothing", want: "base=web1,web2,web3,db1 web=web1,web2,web3 db=db1 users=web1:,web2:,web3:,db1:"},
		{name: "hosts", sel: Selection{Hosts: "web & !web3"}, want: "base=web1,web2 web=web1,web2 db= users=web1:,web2:,web3:,db1:"},
		{name: "stages", sel: Selection{Stages: "db,base"}, want: "base=web1,web2,web3,db1 web=web1,web2,web3(skipped) db=db1 users=web1:,web2:,web3:,db1:"},
		{name: "hosts and stages", sel: Selection{Hosts: "db1", Stages: "db"}, want: "base=db1(skipped) web=(skipped) db=db1 users=web1:,web2:,web3:,db1:"},
		{name: "users", sel: Selection{Users: []string{"web2=root", "admin"}}, want: "base=web1,web2,web3,db1 web=web1,web2,web3 db=db1 users=web1:admin,web2:root,web3:admin,db1:admin"},
		{name: "unknown stage", sel: Selection{Stages: "base,wbe"}, wantErr: `--stages base,wbe: unknown stage "wbe"; did you mean "web"?`},
		{name: "empty stage", sel: Selection{Stages: "base,"}, wantErr: `--stages base,: an empty stage name`},
		{name: "unknown host", sel: Selection{Hosts: "web4"}, wantErr: `--hosts web4: unknown host or group "web4"`},
		{name: "no host", sel: Selection{Hosts: "db1", Stages: "web"}, wantErr: "--hosts db1 --stages web: no selected stage runs on these hosts"},
		{name: "no host in the hosts", sel: Selection{Hosts: "empty"}, wantErr: "--hosts empty: no selected stage runs on these hosts"},
		{name: "user of an unknown host", sel: Selection{Users: []string{"wbe1=root"}}, wantErr: `--user wbe1=root: unknown host "wbe1"; did you mean "web1"?`},
		{name: "two users", sel: Selection{Users: []string{"web1=root", "web1=admin"}}, wantErr: `--user web1=admin: host web1 has the user root already`},
		{name: "two global users", sel: Selection{Users: []string{"root", "admin"}}, wantErr: `--user admin: the user for all hosts is root already`},
		{name: "empty user", sel: Selection{Users: []string{"web1="}}, wantErr: `--user web1=: an empty user name`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Load(writeProject(t, with(manyProject, map[string]string{"pipelines/site.yaml": selectPipeline})), "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			err = p.Select(tt.sel)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var parts []string
			for _, s := range p.Pipeline.Stages {
				part := s.Name + "=" + hostNames(s.Targets)
				if s.Skipped {
					part += "(skipped)"
				}
				parts = append(parts, part)
			}
			var users []string
			for _, h := range p.Inventory.Hosts {
				users = append(users, h.Name+":"+h.User)
				for _, s := range p.Pipeline.Stages {
					for _, t2 := range s.Targets {
						if t2.Name == h.Name && t2.User != h.User {
							t.Errorf("stage %s: host %s has user %q, the inventory %q", s.Name, h.Name, t2.User, h.User)
						}
					}
				}
			}
			got := strings.Join(parts, " ") + " users=" + strings.Join(users, ",")
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

const stepVarsProject = `stages:
  - name: web
    hosts: web
    steps:
      - recipe: site
        vars:
          site_port: 8080
          site_name: !expr '"web-" + host.short'
  - name: db
    hosts: db
    steps:
      - recipe: site
  - name: after
    hosts: web
    steps:
      - file:
          path: /etc/port
          content: !tpl "{{ .vars.site_port }}\n"
`

var stepVarsFiles = map[string]string{
	"winch.yaml": "name: acme\ninventory: inventories/test.yaml\nvars:\n  domain: acme.com\n",
	"inventories/test.yaml": `hosts:
  web1:
    vars:
      site_port: 81
  db1:
    vars:
      site_name: db
groups:
  web:
    hosts: [web1]
  db:
    hosts: [db1]
`,
	"pipelines/site.yaml": stepVarsProject,
	"recipes/site/recipe.yaml": `vars:
  site_port: 80
  site_name:
  site_url: !tpl "http://{{ .vars.site_name }}.{{ .vars.domain }}:{{ .vars.site_port }}"
  site_other: !expr 'vars.domain + "/x"'
steps:
  - file:
      path: /etc/site
      content: !tpl "{{ .vars.site_url }} host.vars.site_port={{ .host.vars.site_port }} other={{ .host.vars.site_other }}\n"
`,
}

// evalSteps returns the evaluated module steps of every host, stage by stage,
// with the data of each recipe step.
func evalSteps(t *testing.T, p *Project) string {
	t.Helper()
	var b strings.Builder
	for _, s := range p.Pipeline.Stages {
		for _, h := range s.Targets {
			env, err := p.Start(h, debian13)
			if err != nil {
				b.WriteString(h.Name + ": " + err.Error() + "\n")
				continue
			}
			b.WriteString(h.Name + " " + s.Name + "\n")
			for i := range s.Steps {
				st := &s.Steps[i]
				todo := []Step{*st}
				e := env
				if st.Recipe != nil {
					todo, e = st.Recipe.Steps, env.For(st)
				}
				for _, rs := range todo {
					steps, err := rs.Eval(e)
					if err != nil {
						b.WriteString("  error: " + err.Error() + "\n")
						continue
					}
					for _, es := range steps {
						describeStep(&b, "  ", es)
					}
				}
			}
		}
	}
	return b.String()
}

// spec: Variables/Sources; Templates and expressions/Data; Steps
func TestStepVarsSources(t *testing.T) {
	tests := []struct {
		name  string
		set   []string
		files map[string]string
	}{
		{name: "step-vars"},
		{name: "step-vars-set", set: []string{"vars.site_port=9000"}},
		{name: "step-vars-required", files: map[string]string{
			"inventories/test.yaml": "hosts:\n  web1: {}\n  db1:\n    vars:\n      site_name: db\ngroups:\n  web:\n    hosts: [web1]\n  db:\n    hosts: [db1]\n",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Load(writeProject(t, with(stepVarsFiles, tt.files)), "", "site", tt.set, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			golden.Assert(t, filepath.Join("testdata", "many", tt.name+".golden"), []byte(evalSteps(t, p)))
		})
	}
}

// spec: Steps; Variables; Templates and expressions/Data
func TestStepVarsLoad(t *testing.T) {
	tests := []struct {
		name     string
		pipeline string
		winch    string
		want     string
	}{
		{name: "module step", pipeline: "      - file:\n          path: /x\n          content: x\n        vars:\n          site_port: 1\n",
			want: "pipelines/site.yaml:8:9: vars: only a recipe step has vars"},
		{name: "undeclared", pipeline: "      - recipe: site\n        vars:\n          site_prot: 1\n",
			want: `pipelines/site.yaml:7:11: unknown variable "site_prot"; did you mean "site_port"?`},
		{name: "null", pipeline: "      - recipe: site\n        vars:\n          site_port:\n",
			want: `pipelines/site.yaml:7:21: variable "site_port": null is not a value`},
		{name: "not a map", pipeline: "      - recipe: site\n        vars: [a]\n",
			want: `pipelines/site.yaml:6:15: vars: expected a map, got a list`},
		{name: "secret", pipeline: "      - recipe: site\n        vars:\n          site_name: !secret YWdl\n",
			want: `pipelines/site.yaml:7:22: variable "site_name": a recipe step gives no !secret values; put the secret in the inventory`},
		{name: "item", pipeline: "      - recipe: site\n        vars:\n          site_name: !expr item\n",
			want: "item is defined only in a step with loop"},
		{name: "other key", pipeline: "      - recipe: site\n        loop: [a]\n",
			want: `pipelines/site.yaml:6:9: a recipe step has only name, recipe, vars, and when, not "loop"`},
		{name: "match in a default", winch: "name: acme\ninventory: inventories/test.yaml\nvars:\n  domain: acme.com\n  peers: !expr 'match(\"all\")'\n", pipeline: "      - recipe: site\n",
			want: "winch.yaml:5:10: a default cannot use match()"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    steps:\n" + tt.pipeline}
			if tt.winch != "" {
				files["winch.yaml"] = tt.winch
			}
			_, err := Load(writeProject(t, with(stepVarsFiles, files)), "", "site", nil, Keys{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

var matchFiles = map[string]string{
	"winch.yaml": "name: acme\ninventory: inventories/test.yaml\nvars:\n  mail_server: false\n  role: !expr 'vars.mail_server ? \"mail\" : \"node\"'\n",
	"inventories/test.yaml": `hosts:
  mail.acme.com:
    address: 192.0.2.10
    vars:
      mail_server: true
  monitor.acme.com:
    address: 192.0.2.20
groups:
  mon:
    hosts: [monitor.acme.com]
`,
	"pipelines/site.yaml": `stages:
  - name: monit
    hosts: all
    steps:
      - recipe: monit
        vars:
          monit_peers: !expr 'filter(match("all"), .name != host.name)'
      - file:
          path: !tpl /etc/peer-{{ .item.short }}
          content: !tpl "{{ .item.address }} {{ join .item.groups \",\" }}\n"
        loop: !expr 'match("all & !mon")'
        when: !expr 'len(match("mon")) == 1 and match("mon")[0].vars.role == nil'
`,
	"recipes/monit/recipe.yaml": `vars:
  monit_peers:
steps:
  - file:
      path: /etc/monit/peers
      template: peers.tmpl
`,
	"recipes/monit/templates/peers.tmpl": `{{ range .vars.monit_peers -}}
{{ .name }} {{ .short }} {{ .address }} {{ join .groups "," }} mail={{ .vars.mail_server }}
{{ end -}}
`,
}

// spec: Templates and expressions/Data
func TestMatch(t *testing.T) {
	tests := []struct {
		name  string
		set   []string
		files map[string]string
	}{
		{name: "match"},
		{name: "match-set", set: []string{"vars.mail_server=true"}},
		{name: "match-unknown", files: map[string]string{
			"recipes/monit/recipe.yaml": "vars:\n  monit_peers:\nsteps:\n  - file:\n      path: /x\n      content: !expr 'string(len(match(\"mial\")))'\n",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Load(writeProject(t, with(matchFiles, tt.files)), "", "site", tt.set, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			golden.Assert(t, filepath.Join("testdata", "many", tt.name+".golden"), []byte(evalSteps(t, p)))
		})
	}
}

// spec: Variables/Secrets in output; Templates and expressions/Data
func TestMatchSecret(t *testing.T) {
	k := newKey(t)
	files := with(matchFiles, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients: [" + k.id.Recipient().String() + "]\nvars:\n  mail_server: false\n  role: node\n  token: x\n",
		"inventories/test.yaml": "hosts:\n  a:\n    vars:\n      token: {{secret:peer-token-a}}\n  b:\n    vars:\n      token: {{secret:peer-token-b}}\n",
		"pipelines/site.yaml": `stages:
  - name: monit
    hosts: all
    steps:
      - recipe: monit
        vars:
          monit_peers: !expr 'filter(match("all"), .name != host.name)'
          monit_token: !expr 'vars.token + "-x"'
`,
		"recipes/monit/recipe.yaml": `vars:
  monit_peers:
  monit_token:
steps:
  - file:
      path: /etc/monit/peers
      template: peers.tmpl
  - file:
      path: /etc/monit/token
      content: !tpl "{{ .vars.monit_token }}\n"
`,
		"recipes/monit/templates/peers.tmpl": "{{ range .vars.monit_peers }}{{ .name }} {{ .vars.token }}\n{{ end }}",
	})
	keys := k.keys()
	p, err := Load(writeProject(t, k.sealFiles(t, files)), "", "site", nil, keys)
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.Start(p.Inventory.Hosts[0], debian13)
	if err != nil {
		t.Fatal(err)
	}
	st := &p.Pipeline.Stages[0].Steps[0]
	var shown []string
	for _, rs := range st.Recipe.Steps {
		steps, err := rs.Eval(env.For(st))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range steps {
			shown = append(shown, shownLines(s))
			if !s.Secret {
				t.Errorf("step %s does not read a secret", s.Args.Main())
			}
		}
	}
	want := []string{"b (secret)\n", "(secret)-x\n"}
	if !slices.Equal(shown, want) {
		t.Errorf("shown lines = %q, want %q", shown, want)
	}
	if got := keys.Filter.Text("peer-token-b"); got != secret.Mark {
		t.Errorf("filter: %q", got)
	}
}

// spec: Running a pipeline/Health gates
func TestHealthLoad(t *testing.T) {
	tests := []struct{ health, want string }{
		{"      command: x\n      stable: 60\n", "pipelines/site.yaml:5:7: health: stable must be less than timeout (60 seconds); the gate could never pass"},
		{"      command: x\n      stable: 10\n      timeout: 10\n", "stable must be less than timeout (10 seconds)"},
		{"      command: \"\"\n", "command: must not be empty"},
		{"      command: x\n      timeout: 0\n", "timeout: must be 1 or more seconds"},
	}
	for _, tt := range tests {
		_, err := Load(writeProject(t, with(manyProject, map[string]string{
			"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: all\n    health:\n" + tt.health + "    steps: []\n",
		})), "", "site", nil, Keys{})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q: error %v, want %q", tt.health, err, tt.want)
		}
	}
}

// spec: Running a pipeline/Plan; CLI (--stages); Variables
func TestSkippedStageEvaluatesOnlyRequirements(t *testing.T) {
	files := with(stepVarsFiles, map[string]string{
		"pipelines/site.yaml": `stages:
  - name: web
    hosts: web
    steps:
      - recipe: site
        vars:
          site_name: !expr 'string(len(match("mial")))'
      - file:
          path: /x
          content: x
        when: !expr 'vars.domain.nope'
  - name: db
    hosts: db
    steps:
      - recipe: site
`,
	})
	p, err := Load(writeProject(t, files), "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Select(Selection{Stages: "db"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Start(p.Inventory.Hosts[0], debian13); err != nil {
		t.Errorf("web1: %v", err)
	}
}

// spec: Variables ("Null is not a value"); Variables/Sources
func TestStepVarNull(t *testing.T) {
	files := with(stepVarsFiles, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: web\n    steps:\n      - recipe: site\n        vars:\n          site_name: !expr 'nil'\n",
	})
	p, err := Load(writeProject(t, files), "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Start(p.Inventory.Hosts[0], debian13)
	if err == nil || !strings.Contains(err.Error(), `pipelines/site.yaml:7:22: variable "site_name": null is not a value`) {
		t.Errorf("error %v", err)
	}
}

// spec: CLI (--user); Remote execution/Sessions
func TestUserBeatsInventory(t *testing.T) {
	p, err := Load(writeProject(t, with(manyProject, map[string]string{
		"inventories/test.yaml": "hosts:\n  web1:\n    user: deploy\n  web2: {}\ngroups:\n  all:\n    user: ops\n",
	})), "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Select(Selection{Users: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}
	for _, h := range append(p.Inventory.Hosts, p.Pipeline.Stages[0].Targets...) {
		if h.User != "admin" {
			t.Errorf("%s: user %q, want admin", h.Name, h.User)
		}
	}
}

// spec: CLI/Output
func TestNameCharacters(t *testing.T) {
	recipe := "steps:\n  - name: \"%s\"\n    file:\n      path: /etc/motd\n      content: hi\n"
	handler := "steps: []\nhandlers:\n  reload:\n    - name: \"%s\"\n      file:\n        path: /etc/motd\n        content: hi\n"
	stageStep := "stages:\n  - name: web\n    hosts: all\n    steps:\n      - name: \"%s\"\n        file:\n          path: /etc/motd\n          content: hi\n"
	recipeStep := "stages:\n  - name: web\n    hosts: all\n    steps:\n      - name: \"%s\"\n        recipe: tools\n"
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"host with address", map[string]string{"inventories/test.yaml": "hosts:\n  \"web\\e]0;x\\a\": {address: 192.0.2.1}\n"},
			`inventories/test.yaml:2:3: host "web\x1b]0;x\a": a name cannot hold a control or format character`},
		{"host without address", map[string]string{"inventories/test.yaml": "hosts:\n  \"web\\u202Eevil\": {}\n"},
			`inventories/test.yaml:2:3: host "web\u202eevil": a name cannot hold a control or format character`},
		{"group", map[string]string{"inventories/test.yaml": "hosts:\n  web1: {}\ngroups:\n  \"web\\u200B\":\n    hosts: [web1]\n"},
			`inventories/test.yaml:4:3: group "web\u200b": a name cannot hold a control or format character`},
		{"stage", map[string]string{"pipelines/site.yaml": "stages:\n  - name: \"x\\e[2K\"\n    hosts: all\n    steps: []\n"},
			`pipelines/site.yaml:2:5: stage "x\x1b[2K": a name cannot hold a control or format character`},
		{"stage with a line separator", map[string]string{"pipelines/site.yaml": "stages:\n  - name: \"x\\u2028\"\n    hosts: all\n    steps: []\n"},
			`pipelines/site.yaml:2:5: stage "x\u2028": a name cannot hold a control or format character`},
		{"stage with a tab", map[string]string{"pipelines/site.yaml": "stages:\n  - name: \"x\\ty\"\n    hosts: all\n    steps: []\n"},
			`pipelines/site.yaml:2:5: stage "x\ty": a name cannot hold a control or format character`},
		{"stage step", map[string]string{"pipelines/site.yaml": strings.ReplaceAll(stageStep, "%s", `x\e[1A`)},
			`pipelines/site.yaml:5:15: step "x\x1b[1A": a name cannot hold a control or format character`},
		{"recipe step in a stage", map[string]string{
			"pipelines/site.yaml":       strings.ReplaceAll(recipeStep, "%s", `x\u202e`),
			"recipes/tools/recipe.yaml": "steps: []\n",
		}, `pipelines/site.yaml:5:15: step "x\u202e": a name cannot hold a control or format character`},
		{"step of a recipe", map[string]string{
			"pipelines/site.yaml":       strings.ReplaceAll(recipeStep, "%s", "tools"),
			"recipes/tools/recipe.yaml": strings.ReplaceAll(recipe, "%s", `x\n`),
		}, `recipes/tools/recipe.yaml:2:11: step "x\n": a name cannot hold a control or format character`},
		{"step of a handler", map[string]string{
			"pipelines/site.yaml":       strings.ReplaceAll(recipeStep, "%s", "tools"),
			"recipes/tools/recipe.yaml": strings.ReplaceAll(handler, "%s", `x\a`),
		}, `recipes/tools/recipe.yaml:4:13: step "x\a": a name cannot hold a control or format character`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeProject(t, with(manyProject, tt.files)), "", "site", nil, Keys{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
