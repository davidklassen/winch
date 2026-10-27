package run_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/service and unit
func TestUnitFromLoop(t *testing.T) {
	files := map[string]string{
		"a.service": "[Service]\nType=oneshot\nExecStart=/bin/true\n",
		"a.timer":   "[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n",
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   steps("      - recipe: web\n"),
		"recipes/web/recipe.yaml": `steps:
  - unit:
      name: !expr item
      source: !expr item
    loop: [a.service, a.timer]
`,
		"recipes/web/files/a.service": files["a.service"],
		"recipes/web/files/a.timer":   files["a.timer"],
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	if err := plan.Failed["web1"]; err != nil {
		t.Fatal(err)
	}
	for _, st := range plan.Stages[0].Hosts[0].Steps {
		if !slices.Contains(st.Result.Changes, "daemon-reload") {
			t.Errorf("%s: changes %q have no daemon-reload", st.Address, st.Result.Changes)
		}
	}
	var out, errOut bytes.Buffer
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if err := o.Failed["web1"]; err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		if got, _ := h.File("web1", "/etc/systemd/system/"+name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if again := run.MakePlan(context.Background(), p, h.Connector(), run.Options{}); again.HasChanges() {
		t.Errorf("the second plan has changes")
	}
}

// spec: Modules/service and unit
func TestUnitComputedErrors(t *testing.T) {
	tests := []struct {
		name, item, want string
	}{
		{"a name without a type", "a", `recipes/web/recipe.yaml:3:13: name: "a" needs a unit type, such as .service or .timer`},
		{"a missing source", "b.service", "recipes/web/recipe.yaml:4:15: source: recipes/web/files/b.service does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml":   steps("      - recipe: web\n"),
				"recipes/web/recipe.yaml": `steps:
  - unit:
      name: !expr item
      source: !expr item
    loop: [` + tt.item + `]
`,
			})
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
			if err != nil {
				t.Fatal(err)
			}
			plan := run.MakePlan(context.Background(), p, fakehost.New().Connector(), run.Options{})
			got := ""
			if err := plan.Failed["web1"]; err != nil {
				got = err.Error()
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("error = %q, want %q in it", got, tt.want)
			}
		})
	}
}

// spec: Modules/service and unit
func TestServiceGetsNewUnitFile(t *testing.T) {
	const a, b, c = "[Service]\nExecStart=/a\n", "[Service]\nExecStart=/b\n", "[Service]\nExecStart=/c\n"
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": `stages:
  - name: one
    hosts: all
    steps:
      - recipe: web
  - name: two
    hosts: all
    steps:
      - service:
          name: a
          enabled: true
`,
		"recipes/web/recipe.yaml": `steps:
  - service:
      name: a
      enabled: true
  - unit:
      name: a.service
      source: a.service
  - unit:
      name: b@.service
      source: b@.service
  - unit:
      name: c.service
      source: c.service
  - service:
      name: a
      enabled: true
  - service:
      name: b@one
      enabled: true
  - service:
      name: b@x.y
      enabled: true
  - service:
      name: c.service
      enabled: true
  - service:
      name: b
      enabled: true
`,
		"recipes/web/files/a.service":  a,
		"recipes/web/files/b@.service": b,
		"recipes/web/files/c.service":  c,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetFile("web1", "/etc/systemd/system/c.service", c)
	for _, n := range []string{"a", "b@one", "b@x.y", "c.service", "b"} {
		h.SetResult("web1", n, module.Result{Status: module.OK})
	}
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	if err := plan.Failed["web1"]; err != nil {
		t.Fatal(err)
	}
	want := []string{"a: ", "a: " + a, "b@one: " + b, "b@x.y: " + b, "c.service: ", "b: ", "a: " + a}
	if !slices.Equal(h.ServiceNewFile, want) {
		t.Errorf("new unit files = %q, want %q", h.ServiceNewFile, want)
	}
}
