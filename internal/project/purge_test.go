package project

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/yamlx"
)

// spec: Modules/file, dir, link (purge and generated files load warning)
func TestLoadPurgeWarning(t *testing.T) {
	for _, tt := range []struct {
		name, purge, path, content, command string
		want                                bool
	}{
		{"then", "purge: true", "/etc/maps/virtual", "x", "then: postmap /etc/maps/virtual", true},
		{"notify", "purge: true", "/etc/maps/virtual", "x", "notify: app.rebuild", true},
		{"computed content", "purge: true", "/etc/maps/virtual", "!tpl '{{ .host.name }}'", "then: postmap /etc/maps/virtual", true},
		{"kept", "purge: true\n          keep: ['*.db']", "/etc/maps/virtual", "x", "then: postmap /etc/maps/virtual", false},
		{"computed keep", "purge: true\n          keep: !expr '[\"*.db\"]'", "/etc/maps/virtual", "x", "then: postmap /etc/maps/virtual", false},
		{"empty keep", "purge: true\n          keep: []", "/etc/maps/virtual", "x", "then: postmap /etc/maps/virtual", true},
		{"no purge", "purge: false", "/etc/maps/virtual", "x", "then: postmap /etc/maps/virtual", false},
		{"prefix only", "purge: true", "/etc/maps-old/virtual", "x", "then: postmap /etc/maps-old/virtual", false},
		{"no command", "purge: true", "/etc/maps/virtual", "x", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, map[string]string{
				"pipelines/site.yaml":     stage("      - dir:\n          path: /etc/maps\n          " + tt.purge + "\n      - file:\n          path: " + tt.path + "\n          content: " + tt.content + "\n        " + tt.command + "\n      - recipe: app\n"),
				"recipes/app/recipe.yaml": "steps: []\nhandlers:\n  rebuild:\n    - cmd:\n        command: postmap /etc/maps/virtual\n",
			})
			p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			ws, err := Validate(dir, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, warnings := range map[string][]*yamlx.Error{"Load": p.Warnings, "Validate": ws} {
				if tt.want {
					if len(warnings) != 1 || !strings.Contains(warnings[0].Error(), "purge of /etc/maps may remove files made by then or a handler; add keep") {
						t.Errorf("%s warnings = %v, want one purge warning", name, warnings)
					}
				} else if len(warnings) != 0 {
					t.Errorf("%s warnings = %v, want none", name, warnings)
				}
			}
		})
	}
}

// spec: Modules/file, dir, link (purge protects paths for this host in any pipeline)
func TestPurgeWarningScope(t *testing.T) {
	for _, tt := range []struct {
		name, hosts, recipe string
		want                bool
	}{
		{"same host", "web1", "steps:\n  - file:\n      path: /etc/maps/virtual\n      content: x\n    then: postmap /etc/maps/virtual\n", true},
		{"other host", "web2", "steps:\n  - file:\n      path: /etc/maps/virtual\n      content: x\n    then: postmap /etc/maps/virtual\n", false},
		{"handler source", "web1", "steps: []\nhandlers:\n  update:\n    - file:\n        path: /etc/maps/virtual\n        content: x\n      then: postmap /etc/maps/virtual\n", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProject(t, map[string]string{
				"pipelines/site.yaml":     "stages:\n  - name: maps\n    hosts: web1\n    steps:\n      - recipe: app\n",
				"pipelines/purge.yaml":    "stages:\n  - name: purge\n    hosts: " + tt.hosts + "\n    steps:\n      - dir:\n          path: /etc/maps\n          purge: true\n",
				"recipes/app/recipe.yaml": tt.recipe,
			})
			p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
			if err != nil {
				t.Fatal(err)
			}
			ws, err := Validate(dir, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, warnings := range map[string][]*yamlx.Error{"Load": p.Warnings, "Validate": ws} {
				want := 0
				if tt.want {
					want = 1
				}
				if len(warnings) != want {
					t.Errorf("%s warnings = %v, want %d", name, warnings, want)
				}
				if len(warnings) > 0 && warnings[0].Pos.File != "recipes/app/recipe.yaml" {
					t.Errorf("%s warning position = %v, want the source step's recipe", name, warnings[0].Pos)
				}
			}
		})
	}
}

// spec: Modules/file, dir, link (then and notify can generate files after removal)
func TestPurgeWarningAbsent(t *testing.T) {
	for _, module := range []string{"file", "dir", "link", "line"} {
		for _, command := range []string{"then: touch /etc/maps/stamp", "notify: app.rebuild"} {
			t.Run(module+command, func(t *testing.T) {
				extra := ""
				if module == "line" {
					extra = "          match: old\n"
				}
				dir := writeProject(t, map[string]string{
					"pipelines/site.yaml":     stage("      - dir:\n          path: /etc/maps\n          purge: true\n      - " + module + ":\n          path: /etc/maps/old\n          absent: true\n" + extra + "        " + command + "\n      - recipe: app\n"),
					"recipes/app/recipe.yaml": "steps: []\nhandlers:\n  rebuild:\n    - cmd:\n        command: touch /etc/maps/stamp\n",
				})
				p, err := Load(t.Context(), dir, "", "site", nil, Keys{})
				if err != nil {
					t.Fatal(err)
				}
				ws, err := Validate(dir, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				for name, warnings := range map[string][]*yamlx.Error{"Load": p.Warnings, "Validate": ws} {
					if len(warnings) != 1 || !strings.Contains(warnings[0].Error(), "purge of /etc/maps may remove files") {
						t.Errorf("%s warnings = %v, want one purge warning", name, warnings)
					}
				}
			})
		}
	}
}
