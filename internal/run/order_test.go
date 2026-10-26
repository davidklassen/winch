package run_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Running a pipeline/Plan; Modules/user and group
func TestOrderUserAfterOwner(t *testing.T) {
	pipeline := `stages:
  - name: files
    hosts: all
    steps:
      - file:
          path: /srv/a
          content: "a\n"
          owner: alice
          group: staff
      - file:
          path: /srv/b
          content: "b\n"
          owner: "1000"
  - name: users
    hosts: all
    steps:
      - group:
          name: staff
      - user:
          name: alice
`
	tests := []orderCase{
		{"both new", "", nil, "users: group staff: an earlier step needs it: files: file /srv/a; move this step before it"},
		{"group exists", "", func(h *fakehost.Hosts) { h.SetGroup("web1", "staff") },
			"users: user alice: an earlier step needs it: files: file /srv/a; move this step before it"},
		{"both exist", "", func(h *fakehost.Hosts) { h.SetGroup("web1", "staff"); h.SetUser("web1", "alice") }, ""},
	}
	tests = append(tests, orderCases...)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := pipeline
			if tt.pipeline != "" {
				pl = tt.pipeline
			}
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml":   pl,
			})
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
			if err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			got := ""
			if err := plan.Failed["web1"]; err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

type orderCase struct {
	name     string
	pipeline string
	setup    func(h *fakehost.Hosts)
	want     string
}

func steps(s string) string {
	return "stages:\n  - name: s\n    hosts: all\n    steps:\n" + s
}

var orderCases = []orderCase{
	{"a user before the group it uses", steps(`      - user:
          name: bob
          group: staff
      - group:
          name: staff
`), nil, "s: group staff: an earlier step needs it: s: user bob; move this step before it"},
	{"a dir before its owner", steps(`      - dir:
          path: /srv/d
          owner: alice
      - user:
          name: alice
`), func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/d") }, "s: user alice: an earlier step needs it: s: dir /srv/d; move this step before it"},
	{"a file group before the user that makes the group", steps(`      - file:
          path: /srv/a
          content: ""
          group: alice
      - user:
          name: alice
`), nil, "s: user alice: an earlier step needs it: s: file /srv/a; move this step before it"},
	{"a file group of an existing group before a new user", steps(`      - file:
          path: /srv/a
          content: ""
          group: alice
      - user:
          name: alice
`), func(h *fakehost.Hosts) { h.SetGroup("web1", "alice") }, ""},
	{"two repo steps for one source", steps(`      - repo:
          name: a
          url: http://x.example/apt
          suite: trixie
          components: [main]
      - repo:
          name: b
          url: http://x.example/apt/
          suite: trixie
          components: [contrib]
`), nil, "s: repo b: the source http://x.example/apt/ trixie is also in s: repo a; use one step"},
	{"two repo steps in two stages", `stages:
  - name: s
    hosts: all
    steps:
      - repo:
          name: a
          url: http://x.example/apt
          suite: trixie
          components: [main]
  - name: t
    hosts: all
    steps:
      - repo:
          name: b
          url: http://x.example/apt
          suite: trixie
          components: [main]
`, nil, "t: repo b: the source http://x.example/apt trixie is also in s: repo a; use one step"},
	{"two repo steps with other suites", steps(`      - repo:
          name: a
          url: http://x.example/apt
          suite: trixie
          components: [main]
      - repo:
          name: b
          url: http://x.example/apt
          suite: trixie-backports
          components: [main]
`), nil, ""},
}

// spec: Modules/repo
func TestRepoGetsRemovedPaths(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml": steps(`      - repo:
          name: a
          url: http://x.example/a
          suite: trixie
          components: [main]
      - file:
          path: /etc/apt/sources.list.d/a.list
          absent: true
      - file:
          path: /etc/apt/sources.list.d/kept.list
          content: ""
      - dir:
          path: /etc/apt/old
          absent: true
      - link:
          path: /etc/apt/sources.list.d/l.list
          absent: true
      - repo:
          name: b
          url: http://x.example/b
          suite: trixie
          components: [main]
`),
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
	want := [][]string{nil, {"/etc/apt/sources.list.d/a.list", "/etc/apt/old", "/etc/apt/sources.list.d/l.list"}}
	if !reflect.DeepEqual(h.RepoRemoved, want) {
		t.Errorf("removed paths = %q, want %q", h.RepoRemoved, want)
	}
}
