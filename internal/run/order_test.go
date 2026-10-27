package run_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
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
		{"a download", `stages:
  - name: files
    hosts: all
    steps:
      - download:
          url: https://example.com/tool
          sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          path: /srv/tool
          owner: alice
  - name: users
    hosts: all
    steps:
      - user:
          name: alice
`, nil, "users: user alice: an earlier step needs it: files: download /srv/tool; move this step before it"},
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

// spec: Running a pipeline/Plan
func TestPlanSameThing(t *testing.T) {
	tests := []struct {
		name     string
		pipeline string
		recipe   string
		want     string
	}{
		{"a step and a handler on one unit", steps(`      - recipe: web
`), `steps:
  - service:
      name: nginx
      running: true
    notify: restart
handlers:
  restart:
    - service:
        name: nginx
        restarted: true
`, ""},
		{"two files on one path", steps(`      - file:
          path: /etc/a
          content: "a\n"
      - file:
          path: /etc/a
          content: "b\n"
`), "", "s: file /etc/a: the path /etc/a is also in s: file /etc/a, with other arguments"},
		{"a file and a dir on one path", steps(`      - file:
          path: /etc/a
          content: "a\n"
      - dir:
          path: /etc/a
`), "", "s: dir /etc/a: the path /etc/a is also in s: file /etc/a, with other arguments"},
		{"a file and a download on one path", steps(`      - file:
          path: /etc/a
          content: "a\n"
      - download:
          url: https://example.com/a
          sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          path: /etc/a
`), "", "s: download /etc/a: the path /etc/a is also in s: file /etc/a, with other arguments"},
		{"a dir and a link removed on one path", steps(`      - dir:
          path: /etc/a
          absent: true
      - link:
          path: /etc/a
          absent: true
`), "", "s: link /etc/a: the path /etc/a is also in s: dir /etc/a, with other arguments"},
		{"a package installed and removed", steps(`      - pkg:
          name: [exim4, curl]
      - pkg:
          name: exim4
          absent: true
`), "", "s: pkg exim4: the package exim4 is also in s: pkg exim4, curl, with other arguments"},
		{"one unit in two forms", steps(`      - service:
          name: nginx
          running: true
      - service:
          name: nginx.service
          running: false
`), "", "s: service nginx.service: the unit nginx.service is also in s: service nginx, with other arguments"},
		{"a user in two stages", `stages:
  - name: s
    hosts: all
    steps:
      - user:
          name: bob
          shell: /bin/sh
  - name: t
    hosts: all
    steps:
      - user:
          name: bob
          shell: /bin/bash
`, "", "t: user bob: the user bob is also in s: user bob, with other arguments"},
		{"a group", steps(`      - group:
          name: staff
      - group:
          name: staff
          gid: 1500
`), "", "s: group staff: the group staff is also in s: group staff, with other arguments"},
		{"two lines with other matches on one path", steps(`      - line:
          path: /etc/redis/redis.conf
          line: port 6380
          match: "^port "
      - line:
          path: /etc/redis/redis.conf
          line: maxmemory 256mb
          match: "^maxmemory "
`), "", ""},
		{"two lines with the same match on one path", steps(`      - line:
          path: /etc/redis/redis.conf
          line: port 6380
          match: "^port "
      - line:
          path: /etc/redis/redis.conf
          line: port 6381
          match: "^port "
`), "", `s: line /etc/redis/redis.conf: the match "^port " in /etc/redis/redis.conf is also in s: line /etc/redis/redis.conf, with other arguments`},
		{"the same match on two paths", steps(`      - line:
          path: /etc/a
          line: port 1
          match: "^port "
      - line:
          path: /etc/b
          line: port 2
          match: "^port "
`), "", ""},
		{"a file and a line on one path", steps(`      - file:
          path: /etc/a
          content: "port 1\n"
      - line:
          path: /etc/a
          line: port 2
          match: "^port "
`), "", "s: line /etc/a: the path /etc/a is also in s: file /etc/a, with other arguments"},
		{"a line and a file on one path", steps(`      - line:
          path: /etc/a
          line: port 2
          match: "^port "
      - file:
          path: /etc/a
          content: "port 1\n"
`), "", "s: file /etc/a: the path /etc/a is also in s: line /etc/a, with other arguments"},
		{"equal steps", steps(`      - file:
          path: /etc/a
          content: "a\n"
      - file:
          path: /etc/a
          content: "a\n"
      - pkg:
          name: [exim4, curl]
      - pkg:
          name: exim4
      - service:
          name: nginx
          running: true
      - service:
          name: nginx.service
          running: true
`), "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml":   tt.pipeline,
			}
			if tt.recipe != "" {
				files["recipes/web/recipe.yaml"] = tt.recipe
			}
			dir := vmtest.WriteProject(t, files)
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
			if err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			h.SetResult("web1", "nginx", module.Result{Status: module.OK})
			h.SetResult("web1", "nginx.service", module.Result{Status: module.OK})
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
