package project

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/golden"
)

var reactionsProject = map[string]string{
	"winch.yaml": "name: acme\ninventory: test\n",
	"inventories/test.yaml": `hosts:
  web1: {}
  web2: {}
groups:
  web:
    hosts: [web1]
  db:
    hosts: [web2]
`,
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: web
    steps:
      - recipe: nginx
      - recipe: site
      - service:
          name: nginx
          restarted: true
        on_change: /etc/nginx/
  - name: db
    hosts: db
    steps:
      - recipe: db
`,
	"recipes/nginx/recipe.yaml": `steps:
  - pkg:
      name: nginx
  - file:
      path: /etc/nginx/nginx.conf
      content: "events {}\n"
      validate: nginx -t
  - name: Reload
    service:
      name: nginx
      reloaded: true
    on_change: [/etc/nginx, /var/lib/dpkg/status]
`,
	"recipes/site/recipe.yaml": `vars:
  site_pages: [a, b]
steps:
  - file:
      path: !tpl /var/www/{{ item }}.html
      content: hi
    loop: !expr vars.site_pages
    then: !tpl "echo {{ len(vars.site_pages) }}"
  - cmd:
      command: !tpl reindex {{ item }}
    loop: !expr vars.site_pages
    on_change: [!tpl "/var/www/{{ item }}.html"]
`,
	"recipes/db/recipe.yaml": `steps:
  - file:
      path: /etc/db.conf
      content: hi
    then: echo db
`,
}

func reactionFiles(files map[string]string) map[string]string {
	return with(reactionsProject, files)
}

// describeReactions describes the evaluated steps of every recipe and stage
// of p for its first host of each stage, with their then and on_change.
func describeReactions(t *testing.T, p *Project) string {
	t.Helper()
	var b strings.Builder
	for _, s := range p.Pipeline.Stages {
		h := s.Targets[0]
		env, err := p.Start(h, debian13, onDebian13(p))
		if err != nil {
			return err.Error() + "\n"
		}
		fmt.Fprintf(&b, "stage %s on %s\n", s.Name, h.Name)
		for i := range s.Steps {
			st := &s.Steps[i]
			steps := []Step{*st}
			e := env
			if st.Recipe != nil {
				steps, e = st.Recipe.Steps, env.For(st)
			}
			for _, rs := range steps {
				evaluated, err := rs.Eval(e)
				if err != nil {
					fmt.Fprintf(&b, "  %s\n", err)
					continue
				}
				for _, es := range evaluated {
					fmt.Fprintf(&b, "  %s %s on_change=%q then=%q\n", es.Module, es.Args.Main(), es.OnChange, es.Then)
				}
			}
		}
	}
	return b.String()
}

// spec: Steps; Reactions; Modules/service and unit; Project layout
func TestLoadReactions(t *testing.T) {
	nginx := reactionsProject["recipes/nginx/recipe.yaml"]
	site := reactionsProject["recipes/site/recipe.yaml"]
	pl := reactionsProject["pipelines/site.yaml"]
	db := reactionsProject["recipes/db/recipe.yaml"]
	tests := []struct {
		name  string
		files map[string]string
	}{
		{name: "valid"},
		{name: "restarted-without-on-change", files: map[string]string{
			"recipes/db/recipe.yaml": "steps:\n  - service:\n      name: postgresql\n      restarted: true\n",
		}},
		{name: "reloaded-without-on-change-in-stage", files: map[string]string{
			"pipelines/site.yaml": pl + "      - service:\n          name: postgresql\n          reloaded: !expr 'true'\n",
		}},
		{name: "on-change-relative", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "[/etc/nginx, /var/lib/dpkg/status]", "[etc/nginx]", 1),
		}},
		{name: "on-change-empty", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "[/etc/nginx, /var/lib/dpkg/status]", "[]", 1),
		}},
		{name: "on-change-map", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "[/etc/nginx, /var/lib/dpkg/status]", "{path: /etc/nginx}", 1),
		}},
		{name: "on-change-item-without-loop", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "[/etc/nginx, /var/lib/dpkg/status]", "[!expr item]", 1),
		}},
		{name: "on-change-recipe-step", files: map[string]string{
			"pipelines/site.yaml": strings.Replace(pl, "- recipe: site\n", "- recipe: site\n        on_change: [/etc]\n", 1),
		}},
		{name: "then-service", files: map[string]string{
			"recipes/nginx/recipe.yaml": nginx + "    then: echo reloaded\n",
		}},
		{name: "then-cmd-without-path", files: map[string]string{
			"recipes/db/recipe.yaml": db + "  - cmd:\n      command: initdb\n    then: echo done\n",
		}},
		{name: "then-cmd-with-creates", files: map[string]string{
			"recipes/db/recipe.yaml": db + "  - cmd:\n      command: initdb\n      creates: /var/lib/db\n    then: echo done\n",
		}},
		{name: "notify", files: map[string]string{
			"recipes/db/recipe.yaml": db + "    notify: reload\n",
		}},
		{name: "handlers", files: map[string]string{
			"recipes/db/recipe.yaml": db + "handlers:\n  reload:\n    - cmd:\n        command: reload\n",
		}},
		{name: "recipe-step-then", files: map[string]string{
			"pipelines/site.yaml": strings.Replace(pl, "- recipe: site\n", "- recipe: site\n        then: echo hi\n", 1),
		}},
		{name: "then-item-in-loop", files: map[string]string{
			"recipes/site/recipe.yaml": strings.Replace(site, "{{ len(vars.site_pages) }}", "{{ item }}", 1),
		}},
		{name: "then-not-string", files: map[string]string{
			"recipes/db/recipe.yaml": strings.Replace(db, "then: echo db", "then: [echo, db]", 1),
		}},
		{name: "then-empty", files: map[string]string{
			"recipes/db/recipe.yaml": strings.Replace(db, "then: echo db", `then: ""`, 1),
		}},
		{name: "then-item-without-loop", files: map[string]string{
			"recipes/db/recipe.yaml": strings.Replace(db, "then: echo db", "then: !expr item", 1),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, reactionFiles(tt.files))
			p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
			got := ""
			if err != nil {
				got = err.Error() + "\n"
			} else {
				got = describeReactions(t, p)
			}
			golden.Assert(t, filepath.Join("testdata", "reactions", tt.name+".golden"), []byte(got))
		})
	}
}

// spec: Steps; Reactions; Templates and expressions/When they run
func TestOnChangeEvalErrors(t *testing.T) {
	for _, tt := range []struct{ value, want string }{
		{`!expr 'len(host.name)'`, "recipes/db/recipe.yaml:5:16: on_change: expected a path, got the integer 4"},
		{`!expr '["/a", "b"]'`, `recipes/db/recipe.yaml:5:16: on_change: "b" is not an absolute path`},
		{`!expr '[]'`, "recipes/db/recipe.yaml:5:16: on_change: needs at least one path"},
	} {
		t.Run(tt.value, func(t *testing.T) {
			db := reactionsProject["recipes/db/recipe.yaml"]
			dir := writeProject(t, reactionFiles(map[string]string{
				"recipes/db/recipe.yaml": strings.Replace(db, "then: echo db", "on_change: "+tt.value, 1),
			}))
			p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			env, err := p.Start(p.Inventory.Hosts[1], debian13, onDebian13(p))
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Pipeline.Stages[1].Steps[0].Recipe.Steps[0].Eval(env)
			if err == nil || err.Error() != tt.want {
				t.Errorf("error = %v, want %s", err, tt.want)
			}
		})
	}
}

// spec: Steps; Templates and expressions/When they run
func TestThenEvalErrors(t *testing.T) {
	db := reactionsProject["recipes/db/recipe.yaml"]
	dir := writeProject(t, reactionFiles(map[string]string{
		"recipes/db/recipe.yaml": strings.Replace(db, "then: echo db", "then: !expr 'len(host.name)'", 1),
	}))
	p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.Start(p.Inventory.Hosts[1], debian13, onDebian13(p))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Pipeline.Stages[1].Steps[0].Recipe.Steps[0].Eval(env)
	want := "recipes/db/recipe.yaml:5:11: then: expected a string, got the integer 4"
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %s", err, want)
	}
}

// spec: Modules/service and unit; Reactions
func TestReactingServiceEvalError(t *testing.T) {
	nginx := reactionsProject["recipes/nginx/recipe.yaml"]
	dir := writeProject(t, reactionFiles(map[string]string{
		"recipes/nginx/recipe.yaml": strings.Replace(nginx, "      name: nginx\n      reloaded: true\n", "      name: !expr '\"nginx\"'\n", 1),
	}))
	p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.Start(p.Inventory.Hosts[0], debian13, onDebian13(p))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Pipeline.Stages[0].Steps[0].Recipe.Steps[2].Eval(env)
	want := "recipes/nginx/recipe.yaml:10:7: a service step needs running, enabled, reloaded, or restarted"
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %s", err, want)
	}
}

// spec: Steps
func TestThenOfAnEmptyLoop(t *testing.T) {
	db := reactionsProject["recipes/db/recipe.yaml"]
	dir := writeProject(t, reactionFiles(map[string]string{
		"recipes/db/recipe.yaml": strings.Replace(db, "then: echo db", "loop: []\n    then: !expr 'len(host.name)'", 1),
	}))
	p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.Start(p.Inventory.Hosts[1], debian13, onDebian13(p))
	if err != nil {
		t.Fatal(err)
	}
	if steps, err := p.Pipeline.Stages[1].Steps[0].Recipe.Steps[0].Eval(env); err != nil || len(steps) != 0 {
		t.Errorf("Eval = %v, %v; want no steps and no error", steps, err)
	}
}
