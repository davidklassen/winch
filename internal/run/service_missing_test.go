package run_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/service and unit
func TestMissingUnitNoteSelection(t *testing.T) {
	const stop = "      - service: {name: app, running: false}\n"
	const remove = "      - file: {path: /etc/systemd/system/app.service, absent: true}\n"
	stage := func(name, hosts, steps string) string {
		return "  - name: " + name + "\n    hosts: " + hosts + "\n    steps:\n" + steps
	}
	for _, tt := range []struct {
		name, pipeline, selection string
		note                      bool
	}{
		{"missing without removal", stage("services", "web1", stop), "", true},
		{"removal before stop", stage("services", "web1", remove+stop), "", false},
		{"removal after stop", stage("services", "web1", stop+remove), "", false},
		{"removal in earlier stage", stage("files", "web1", remove) + stage("services", "web1", stop), "", false},
		{"removal in later stage", stage("services", "web1", stop) + stage("files", "web1", remove), "", false},
		{"unselected removal", stage("services", "web1", stop) + stage("files", "web1", remove), "services", true},
		{"removal on another host", stage("services", "web1", stop) + stage("files", "web2", remove), "", true},
		{"removal skipped by when", stage("services", "web1", stop+remove+"        when: !expr false\n"), "", true},
		{"another unit", stage("services", "web1", stop+strings.ReplaceAll(remove, "app.service", "other.service")), "", true},
		{"same name outside unit path", stage("services", "web1", stop+strings.ReplaceAll(remove, "/etc/systemd/system", "/tmp")), "", true},
		{"file is written", stage("services", "web1", stop+strings.ReplaceAll(remove, "absent: true", "content: unit")), "", true},
		{"link removal", stage("services", "web1", stop+strings.ReplaceAll(remove, "file:", "link:")), "", false},
		{"parent removal is not explicit", stage("services", "web1", stop+"      - dir: {path: /etc/systemd/system, absent: true}\n"), "", true},
		{"recipe loop removal", stage("services", "web1", stop+"      - recipe: cleanup\n"), "", false},
		{"skipped recipe", stage("services", "web1", stop+"      - recipe: cleanup\n        when: !expr false\n"), "", true},
		{"notified removal handler", stage("services", "web1", stop+"      - recipe: notified\n"), "", false},
		{"unnotified removal handler", stage("services", "web1", stop+"      - recipe: unnotified\n"), "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":                     "name: missing\ninventory: test\n",
				"inventories/test.yaml":          "hosts:\n  web1: {}\n  web2: {}\n",
				"pipelines/site.yaml":            "stages:\n" + tt.pipeline,
				"recipes/cleanup/recipe.yaml":    "steps:\n  - file:\n      path: !expr item\n      absent: true\n    loop: [/etc/systemd/system/app.service]\n",
				"recipes/notified/recipe.yaml":   "steps:\n  - file: {path: /tmp/notify, content: notify}\n    notify: cleanup\nhandlers:\n  cleanup:\n    - file: {path: /etc/systemd/system/app.service, absent: true}\n",
				"recipes/unnotified/recipe.yaml": "steps:\n  - file: {path: /tmp/notify, content: notify}\nhandlers:\n  cleanup:\n    - file: {path: /etc/systemd/system/app.service, absent: true}\n",
			})
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Select(project.Selection{Stages: tt.selection}); err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			h.SetResult("web1", "app", module.Result{Status: module.OK, MissingUnitFiles: []string{"/etc/systemd/system/app.service", "/usr/lib/systemd/system/app.service"}})
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			if len(plan.Failed) > 0 {
				t.Fatal(plan.Failed)
			}
			var out, errOut bytes.Buffer
			plan.Write(plain(&out), plain(&errOut))
			got := strings.Contains(out.String()+errOut.String(), "app.service does not exist")
			if got != tt.note {
				t.Errorf("note = %v, want %v; stdout %q, stderr %q", got, tt.note, out.String(), errOut.String())
			}
		})
	}
}
