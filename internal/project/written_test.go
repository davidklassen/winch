package project

import (
	"strings"
	"testing"
)

var writtenProject = map[string]string{
	"winch.yaml": "name: acme\ninventory: test\n",
	"inventories/test.yaml": `hosts:
  web1: {}
  db1: {}
groups:
  web:
    hosts: [web1]
`,
	"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/x/a
          content: a
      - file:
          path: /etc/x/gone
          absent: true
      - file:
          path: /etc/x/never
          content: n
        when: !expr 'false'
      - dir:
          path: !expr item
        loop: [/etc/x/l1, /etc/x/l2]
      - cmd:
          command: touch /etc/x/done
          creates: /etc/x/done
      - recipe: app
        vars:
          app_root: /srv/app
      - recipe: off
        when: !expr 'false'
  - name: db
    hosts: db1
    steps:
      - file:
          path: /etc/x/db
          content: d
    handlers:
      reload:
        - file:
            path: /etc/x/db-handler
            content: h
  - name: late
    hosts: web
    steps:
      - user:
          name: deploy
`,
	"pipelines/other.yaml": `stages:
  - name: dl
    hosts: web1
    steps:
      - download:
          url: https://example.com/a.tgz
          sha256: "0000000000000000000000000000000000000000000000000000000000000000"
          unpack: /opt/a
      - file:
          path: /opt/b
          content: b
        when: !expr 'facts.os.version == "12"'
      - download:
          url: https://example.com/c.tgz
          sha256: "0000000000000000000000000000000000000000000000000000000000000000"
          unpack: /opt/c
        when: !expr 'facts.os.version == "12"'
`,
	"recipes/app/recipe.yaml": `steps:
  - file:
      path: !tpl "{{ .vars.app_root }}/conf"
      content: c
handlers:
  restart:
    - file:
        path: /etc/x/handler
        content: h
`,
	"recipes/off/recipe.yaml": `steps:
  - file:
      path: /etc/x/off
      content: o
`,
}

// spec: Modules/file, dir, link (dir purge: a step for this host in any
// pipeline writes the path; a skipped stage counts; when and absent do not;
// download its unpack directory with everything in it)
func TestWritten(t *testing.T) {
	tests := []struct {
		host  string
		paths string
		trees string
	}{
		{"web1", "/etc/x/a /etc/x/done /etc/x/handler /etc/x/l1 /etc/x/l2 /home/deploy /opt/a /srv/app/conf", "/opt/a"},
		{"db1", "/etc/x/a /etc/x/db /etc/x/db-handler /etc/x/done /etc/x/handler /etc/x/l1 /etc/x/l2 /srv/app/conf", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			p, err := Load(t.Context(), writeProject(t, writtenProject), "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Select(Selection{Stages: "db"}); err != nil {
				t.Fatal(err)
			}
			var h Host
			for _, ih := range p.Inventory.Hosts {
				if ih.Name == tt.host {
					h = ih
				}
			}
			got, err := p.Written(h, debian13)
			if err != nil {
				t.Fatal(err)
			}
			if paths := strings.Join(got.Paths, " "); paths != tt.paths {
				t.Errorf("got  %s\nwant %s", paths, tt.paths)
			}
			if trees := strings.Join(got.Trees, " "); trees != tt.trees {
				t.Errorf("trees %q, want %q", trees, tt.trees)
			}
		})
	}
}

const oldRecipe = "require:\n  - !expr 'facts.os.version == \"12\"'\nsteps: []\n"

// spec: Modules/file, dir, link (dir purge: any pipeline of the project)
func TestOtherPipelineErrorFailsOnlyWritten(t *testing.T) {
	tests := map[string]string{
		"a load error":        "stages: []\n",
		"an unknown group":    "stages:\n  - name: s\n    hosts: monitors\n    steps: []\n",
		"an evaluation error": "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: old\n",
	}
	for name, other := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := Load(t.Context(), writeProject(t, with(writtenProject, map[string]string{"pipelines/other.yaml": other, "recipes/old/recipe.yaml": oldRecipe})), "", "site", nil, Keys{})
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if _, err := p.Written(p.Inventory.Hosts[0], debian13); err == nil || !strings.Contains(err.Error(), "other") {
				t.Errorf("written: error %v, want one about pipeline other", err)
			}
		})
	}
}
