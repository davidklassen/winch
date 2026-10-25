package project

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/golden"
)

var handlersProject = map[string]string{
	"winch.yaml": "name: acme\ninventory: inventories/test.yaml\n",
	"inventories/test.yaml": `hosts:
  web1: {}
  web2: {}
groups:
  web:
    hosts: [web1]
  db:
    hosts: [web2]
  nobody:
    hosts: []
`,
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: web
    steps:
      - recipe: nginx
      - recipe: site
      - file:
          path: /etc/motd
          content: hi
        notify: nginx.reload
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
    notify: [reload, restart]
handlers:
  restart:
    - service:
        name: nginx
        restarted: true
      then: echo restarted
  reload:
    - name: Reload
      service:
        name: nginx
        reloaded: true
      when: !expr 'host.name != ""'
`,
	"recipes/site/recipe.yaml": `vars:
  site_pages: [a, b]
steps:
  - file:
      path: !tpl /var/www/{{ .item }}.html
      content: hi
    loop: !expr vars.site_pages
    then: !tpl "echo {{ len .vars.site_pages }}"
    notify: nginx.reload
  - link:
      path: /etc/nginx/sites-enabled/site
      target: /etc/nginx/sites-available/site
      validate: !expr '"nginx -t -c " + "/etc/nginx/nginx.conf"'
    notify: nginx.reload
`,
	"recipes/db/recipe.yaml": `steps:
  - file:
      path: /etc/db.conf
      content: hi
    then: echo db
`,
}

func describeHandlers(p *Project) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, s := range p.Pipeline.Stages {
		fmt.Fprintf(&b, "stage %s\n", s.Name)
		for _, st := range s.Steps {
			describeStep(&b, "  ", st)
			describeNotify(&b, "    ", st)
			if st.Recipe == nil || seen[st.Recipe.Name] {
				continue
			}
			seen[st.Recipe.Name] = true
			for _, rs := range st.Recipe.Steps {
				describeStep(&b, "    ", rs)
				describeNotify(&b, "      ", rs)
			}
			for _, h := range st.Recipe.Handlers {
				fmt.Fprintf(&b, "    handler %s at %s\n", h.FullName(), h.Pos)
				for _, hs := range h.Steps {
					describeStep(&b, "      ", hs)
				}
			}
		}
	}
	return b.String()
}

func describeNotify(b *strings.Builder, indent string, st Step) {
	for _, h := range st.Notify {
		fmt.Fprintf(b, "%snotify %s\n", indent, h.FullName())
	}
}

func handlerFiles(files map[string]string) map[string]string {
	return with(handlersProject, files)
}

// spec: Recipes; Steps; Handlers; Modules/file, dir, link; Modules/service and unit; Project layout
func TestLoadHandlers(t *testing.T) {
	nginx := handlersProject["recipes/nginx/recipe.yaml"]
	site := handlersProject["recipes/site/recipe.yaml"]
	pl := handlersProject["pipelines/site.yaml"]
	tests := []struct {
		name  string
		files map[string]string
	}{
		{name: "valid"},
		{name: "unknown-local-handler", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "[reload, restart]", "[relaod, restart]", 1),
		}},
		{name: "unknown-recipe", files: map[string]string{
			"recipes/site/recipe.yaml": strings.Replace(site, "notify: nginx.reload\n  - link", "notify: ngnix.reload\n  - link", 1),
		}},
		{name: "unknown-other-handler", files: map[string]string{
			"recipes/site/recipe.yaml": strings.Replace(site, "notify: nginx.reload\n  - link", "notify: nginx.relaod\n  - link", 1),
		}},
		{name: "stage-local-name", files: map[string]string{
			"pipelines/site.yaml": strings.Replace(pl, "notify: nginx.reload", "notify: reload", 1),
		}},
		{name: "handler-notify", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "then: echo restarted", "notify: reload", 1),
		}},
		{name: "recipe-step-notify", files: map[string]string{
			"pipelines/site.yaml": strings.Replace(pl, "- recipe: site\n", "- recipe: site\n        notify: nginx.reload\n", 1),
		}},
		{name: "recipe-step-then", files: map[string]string{
			"pipelines/site.yaml": strings.Replace(pl, "- recipe: site\n", "- recipe: site\n        then: echo hi\n", 1),
		}},
		{name: "notify-map", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "[reload, restart]", "{reload: true}", 1),
		}},
		{name: "notify-list-item", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "[reload, restart]", "\n      - reload\n      - [restart]", 1),
		}},
		{name: "notify-tag", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "[reload, restart]", "!expr '\"reload\"'", 1),
		}},
		{name: "bad-handler-name", files: map[string]string{
			"recipes/nginx/recipe.yaml": strings.Replace(nginx, "  reload:\n", "  re.load:\n", 1),
		}},
		{name: "handlers-not-map", files: map[string]string{
			"recipes/db/recipe.yaml": "steps: []\nhandlers: [reload]\n",
		}},
		{name: "handler-without-steps", files: map[string]string{
			"recipes/db/recipe.yaml": "steps: []\nhandlers:\n  reload: []\n",
		}},
		{name: "handler-steps-not-list", files: map[string]string{
			"recipes/db/recipe.yaml": "steps: []\nhandlers:\n  reload:\n    service:\n      name: x\n      reloaded: true\n",
		}},
		{name: "restarted-in-recipe-step", files: map[string]string{
			"recipes/db/recipe.yaml": "steps:\n  - service:\n      name: postgresql\n      restarted: true\n",
		}},
		{name: "reloaded-in-stage", files: map[string]string{
			"pipelines/site.yaml": pl + "      - service:\n          name: postgresql\n          reloaded: !expr 'true'\n",
		}},
		{name: "then-item-in-loop", files: map[string]string{
			"recipes/site/recipe.yaml": strings.Replace(site, "{{ len .vars.site_pages }}", "{{ .item }}", 1),
		}},
		{name: "then-not-string", files: map[string]string{
			"recipes/db/recipe.yaml": strings.Replace(handlersProject["recipes/db/recipe.yaml"], "then: echo db", "then: [echo, db]", 1),
		}},
		{name: "then-empty", files: map[string]string{
			"recipes/db/recipe.yaml": strings.Replace(handlersProject["recipes/db/recipe.yaml"], "then: echo db", `then: ""`, 1),
		}},
		{name: "then-item-without-loop", files: map[string]string{
			"recipes/db/recipe.yaml": strings.Replace(handlersProject["recipes/db/recipe.yaml"], "then: echo db", "then: !expr item", 1),
		}},
		{name: "other-recipe-on-no-host", files: map[string]string{
			"recipes/db/recipe.yaml": handlersProject["recipes/db/recipe.yaml"] + "    notify: nginx.reload\n",
		}},
		{name: "other-recipe-in-another-stage", files: map[string]string{
			"pipelines/site.yaml": pl + "  - name: all\n    hosts: all\n    steps:\n      - file:\n          path: /etc/issue\n          content: hi\n        notify: nginx.reload\n",
		}},
		{name: "stage-without-hosts", files: map[string]string{
			"pipelines/site.yaml": pl + "  - name: nobody\n    hosts: nobody\n    steps:\n      - file:\n          path: /etc/issue\n          content: hi\n        notify: nginx.reload\n",
		}},
		{name: "unused-recipe-unknown-handler", files: map[string]string{
			"recipes/unused/recipe.yaml": "steps:\n  - file:\n      path: /x\n      content: hi\n    notify: nginx.nope\n",
		}},
		{name: "bad-project-name", files: map[string]string{
			"winch.yaml": "name: ../acme\ninventory: inventories/test.yaml\n",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, handlerFiles(tt.files))
			p, err := Load(dir, "", "site", nil)
			got := ""
			if err != nil {
				got = err.Error() + "\n"
			} else {
				got = describeHandlers(p)
			}
			golden.Assert(t, filepath.Join("testdata", "handlers", tt.name+".golden"), []byte(got))
		})
	}
}

// spec: Steps; Handlers
func TestEvalThenAndRuns(t *testing.T) {
	pl := handlersProject["pipelines/site.yaml"]
	dir := writeProject(t, handlerFiles(map[string]string{
		"pipelines/site.yaml": strings.Replace(pl, "      - recipe: site\n", "      - recipe: site\n        when: !expr 'host.name == \"web2\"'\n", 1),
	}))
	p, err := Load(dir, "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	web1 := p.Inventory.Hosts[0]
	env, err := p.Start(web1, debian13)
	if err != nil {
		t.Fatal(err)
	}
	for recipe, want := range map[string]bool{"nginx": true, "site": false, "db": false, "unknown": false} {
		if got := env.Runs(recipe); got != want {
			t.Errorf("Runs(%s) = %v, want %v", recipe, got, want)
		}
	}
	h := p.Pipeline.Stages[0].Steps[0].Recipe.Handlers[0]
	hs, err := h.Steps[0].Eval(env)
	if err != nil || len(hs) != 1 || hs[0].Then != "echo restarted" {
		t.Errorf("handler step = %+v, %v", hs, err)
	}

	// Without the when, site runs on web1.
	p, err = Load(writeProject(t, handlersProject), "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	if env, err = p.Start(web1, debian13); err != nil {
		t.Fatal(err)
	}
	siteSteps := p.Pipeline.Stages[0].Steps[1].Recipe.Steps
	steps, err := siteSteps[0].Eval(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 || steps[0].Then != "echo 2" || steps[1].Then != "echo 2" {
		t.Errorf("then of the loop = %+v, want echo 2 on both elements", steps)
	}
}

// spec: Steps; Templates and expressions/When they run
func TestThenEvalErrors(t *testing.T) {
	db := handlersProject["recipes/db/recipe.yaml"]
	dir := writeProject(t, handlerFiles(map[string]string{
		"recipes/db/recipe.yaml": strings.Replace(db, "then: echo db", "then: !expr 'len(host.name)'", 1),
	}))
	p, err := Load(dir, "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.Start(p.Inventory.Hosts[1], debian13)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Pipeline.Stages[1].Steps[0].Recipe.Steps[0].Eval(env)
	want := "recipes/db/recipe.yaml:5:11: then: expected a string, got the integer 4"
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %s", err, want)
	}
}

// spec: Steps
func TestThenOfAnEmptyLoop(t *testing.T) {
	db := handlersProject["recipes/db/recipe.yaml"]
	dir := writeProject(t, handlerFiles(map[string]string{
		"recipes/db/recipe.yaml": strings.Replace(db, "then: echo db", "loop: []\n    then: !expr 'len(host.name)'", 1),
	}))
	p, err := Load(dir, "", "site", nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.Start(p.Inventory.Hosts[1], debian13)
	if err != nil {
		t.Fatal(err)
	}
	if steps, err := p.Pipeline.Stages[1].Steps[0].Recipe.Steps[0].Eval(env); err != nil || len(steps) != 0 {
		t.Errorf("Eval = %v, %v; want no steps and no error", steps, err)
	}
}
