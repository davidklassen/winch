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
				"winch.yaml":            "name: acme\ninventory: test\n",
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
	{"an install that pulls a package that a later step removes", steps(`      - pkg:
          name: mailutils
      - pkg:
          name: postfix
          absent: true
`), func(h *fakehost.Hosts) { h.SetPkgDeps("mailutils", "postfix") }, "s: pkg postfix: s: pkg mailutils also installs postfix, which this step removes; the two steps undo each other on every run"},
	{"an install that pulls a package that an earlier step removes", steps(`      - pkg:
          name: postfix
          absent: true
      - pkg:
          name: mailutils
`), func(h *fakehost.Hosts) { h.SetPkgDeps("mailutils", "postfix") }, "s: pkg mailutils: this step also installs postfix, which s: pkg postfix removes; the two steps undo each other on every run"},
	{"a removal that takes a package that an earlier step installs", steps(`      - pkg:
          name: mailutils
      - pkg:
          name: postfix
          absent: true
`), func(h *fakehost.Hosts) {
		h.SetPkgDeps("mailutils", "postfix")
		h.SetPkg("web1", "mailutils", "postfix")
	}, "s: pkg postfix: this step also removes mailutils, which s: pkg mailutils installs; the two steps undo each other on every run"},
	{"a removal that takes a package that an earlier step installs in this run", steps(`      - pkg:
          name: mailutils
      - pkg:
          name: postfix
          absent: true
`), func(h *fakehost.Hosts) {
		h.SetPkgDeps("mailutils", "postfix")
		h.SetPkg("web1", "postfix")
	}, "s: pkg postfix: this step also removes mailutils, which s: pkg mailutils installs; the two steps undo each other on every run"},
	{"a removal that takes a dependency of a package that an earlier step pulls in", steps(`      - pkg:
          name: mailutils
      - pkg:
          name: libfoo
          absent: true
`), func(h *fakehost.Hosts) {
		h.SetPkgDeps("mailutils", "postfix")
		h.SetPkgDeps("postfix", "libfoo")
		h.SetPkg("web1", "libfoo")
	}, "s: pkg libfoo: this step also removes mailutils, which s: pkg mailutils installs; the two steps undo each other on every run"},
	{"a removal that takes a package that a later step installs", steps(`      - pkg:
          name: postfix
          absent: true
      - pkg:
          name: mailutils
`), func(h *fakehost.Hosts) {
		h.SetPkgDeps("mailutils", "postfix")
		h.SetPkg("web1", "mailutils", "postfix")
	}, "s: pkg mailutils: s: pkg postfix also removes mailutils, which this step installs; the two steps undo each other on every run"},
	{"an install and a removal of unrelated packages", steps(`      - pkg:
          name: mailutils
      - pkg:
          name: exim4
          absent: true
`), func(h *fakehost.Hosts) {
		h.SetPkgDeps("mailutils", "postfix")
		h.SetPkg("web1", "mailutils", "postfix")
	}, ""},
	{"a debconf answer after the install of a dependency", steps(`      - pkg:
          name: mailutils
      - debconf:
          package: postfix
          question: postfix/main_mailer_type
          type: select
          value: Local only
`), func(h *fakehost.Hosts) { h.SetPkgDeps("mailutils", "postfix") }, "s: debconf postfix/main_mailer_type: s: pkg mailutils installs postfix before this step sets the answer; move this step before it"},
	{"a debconf answer after the removal of its package", steps(`      - pkg:
          name: postfix
          absent: true
      - debconf:
          package: postfix
          question: postfix/main_mailer_type
          type: select
          value: Local only
`), func(h *fakehost.Hosts) {
		h.SetPkgDeps("mailutils", "postfix")
		h.SetPkg("web1", "mailutils", "postfix")
	}, ""},
	{"a user before the group it uses", steps(`      - user:
          name: bob
          group: staff
      - group:
          name: staff
`), nil, "s: group staff: an earlier step needs it: s: user bob; move this step before it"},
	{"a user before a group in its groups", steps(`      - user:
          name: bob
          groups: [sudo, docker]
      - group:
          name: docker
`), nil, "s: group docker: an earlier step needs it: s: user bob; move this step before it"},
	{"a user before a group in its add_groups", steps(`      - user:
          name: bob
          add_groups: [docker]
      - group:
          name: docker
`), nil, "s: group docker: an earlier step needs it: s: user bob; move this step before it"},
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
	{"a cmd as a user that a later step creates", steps(`      - cmd:
          command: make install
          user: deploy
      - user:
          name: deploy
`), nil, "s: user deploy: an earlier step needs it: s: cmd make install; move this step before it"},
	{"a cmd as an existing user", steps(`      - cmd:
          command: make install
          user: deploy
      - user:
          name: deploy
`), func(h *fakehost.Hosts) { h.SetUser("web1", "deploy") }, ""},
	{"a cmd with creates that exists, as a new user", steps(`      - cmd:
          command: make install
          creates: /srv/made
          user: deploy
      - user:
          name: deploy
`), func(h *fakehost.Hosts) { h.SetFile("web1", "/srv/made", "") }, ""},
	{"a cmd in a dir that a later step creates", steps(`      - cmd:
          command: make install
          dir: /srv/app
      - dir:
          path: /srv/app
`), func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, "s: dir /srv/app: an earlier step needs it: s: cmd make install; move this step before it"},
	{"a cmd in a dir that a later step creates as a parent", steps(`      - cmd:
          command: make install
          dir: /srv/app
      - file:
          path: /srv/app/config
          content: ""
`), func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, "s: file /srv/app/config: an earlier step needs it: s: cmd make install; move this step before it"},
	{"a cmd in a dir that an earlier step creates", steps(`      - dir:
          path: /srv/app
      - cmd:
          command: make install
          dir: /srv/app
      - file:
          path: /srv/app/config
          content: ""
`), func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, ""},
	{"a cmd in a dir that an earlier cmd creates", steps(`      - cmd:
          command: git clone x /srv/app
          creates: /srv/app/.git
      - cmd:
          command: make install
          dir: /srv/app
      - file:
          path: /srv/app/config
          content: ""
`), func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, ""},
	{"a cmd in the home of an earlier user", steps(`      - user:
          name: deploy
      - cmd:
          command: make install
          user: deploy
          dir: /home/deploy
      - file:
          path: /home/deploy/.env
          content: ""
`), func(h *fakehost.Hosts) { h.RemoveDir("web1", "/home/deploy") }, ""},
	{"a cmd in the unpack dir of an earlier download", steps(`      - download:
          url: https://example.com/app.tar.gz
          sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          unpack: /opt/app
      - cmd:
          command: ./install
          dir: /opt/app
      - file:
          path: /opt/app/config
          content: ""
`), func(h *fakehost.Hosts) { h.RemoveDir("web1", "/opt/app") }, ""},
	{"a cmd in a dir that exists", steps(`      - cmd:
          command: make install
          dir: /srv/app
      - dir:
          path: /srv/app
`), nil, ""},
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
		"winch.yaml":            "name: acme\ninventory: test\n",
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
		{"two unpacks into one directory", steps(`      - download:
          url: https://example.com/a.tgz
          sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          unpack: /opt/a
      - download:
          url: https://example.com/b.tgz
          sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          unpack: /opt/a
`), "", "s: download /opt/a: the unpack directory /opt/a is also in s: download /opt/a, with other arguments"},
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
		{"two add_groups steps for one user", `stages:
  - name: s
    hosts: all
    steps:
      - user:
          name: bob
          add_groups: [docker]
  - name: t
    hosts: all
    steps:
      - user:
          name: bob
          add_groups: [adm]
`, "", ""},
		{"a user step and an add_groups step", steps(`      - user:
          name: bob
          shell: /bin/bash
      - user:
          name: bob
          add_groups: [docker]
`), "", ""},
		{"an add_groups step and a step with add_groups and a shell", steps(`      - user:
          name: bob
          add_groups: [docker]
      - user:
          name: bob
          shell: /bin/bash
          add_groups: [adm]
`), "", ""},
		{"an add_groups step and a groups step", steps(`      - user:
          name: bob
          add_groups: [docker]
      - user:
          name: bob
          groups: [adm]
`), "", "s: user bob: the user bob is also in s: user bob, with other arguments"},
		{"a groups step and an add_groups step", steps(`      - user:
          name: bob
          groups: [adm]
      - user:
          name: bob
          add_groups: [docker]
`), "", "s: user bob: the user bob is also in s: user bob, with other arguments"},
		{"two user steps with add_groups and other fields", steps(`      - user:
          name: bob
          shell: /bin/bash
          add_groups: [docker]
      - user:
          name: bob
          shell: /bin/bash
          add_groups: [adm]
`), "", "s: user bob: the user bob is also in s: user bob, with other arguments"},
		{"a group", steps(`      - group:
          name: staff
      - group:
          name: staff
          gid: 1500
`), "", "s: group staff: the group staff is also in s: group staff, with other arguments"},
		{"a unit and a file on one path", steps(`      - recipe: web
      - file:
          path: /etc/systemd/system/app.service
          content: "[Service]\n"
`), `steps:
  - unit:
      name: app.service
      source: app.service
`, "s: file /etc/systemd/system/app.service: the path /etc/systemd/system/app.service is also in web: unit app.service, with other arguments"},
		{"one unit from two files", steps(`      - recipe: web
`), `steps:
  - unit:
      name: app.service
      source: app.service
  - unit:
      name: app.service
      source: other.service
`, "web: unit app.service: the path /etc/systemd/system/app.service is also in web: unit app.service, with other arguments"},
		{"a unit and a service step on one unit", steps(`      - recipe: web
`), `steps:
  - unit:
      name: nginx.service
      source: app.service
  - service:
      name: nginx
      running: true
`, ""},
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
`), "", `s: line /etc/redis/redis.conf: the match "^port " finds the line of s: line /etc/redis/redis.conf; the two steps change it on every run`},
		{"a match that finds the line of an earlier step", steps(`      - line:
          path: /etc/ssh/sshd_config
          line: Port 22
          match: "^Port "
      - line:
          path: /etc/ssh/sshd_config
          line: Port 2222
          match: "^#?Port "
`), "", `s: line /etc/ssh/sshd_config: the match "^#?Port " finds the line of s: line /etc/ssh/sshd_config; the two steps change it on every run`},
		{"a line that the match of an earlier step finds", steps(`      - line:
          path: /etc/ssh/sshd_config
          line: Port 22
          match: "^Port"
      - line:
          path: /etc/ssh/sshd_config
          line: Port 2222
          match: "^Port 2222"
`), "", `s: line /etc/ssh/sshd_config: the match "^Port" of s: line /etc/ssh/sshd_config finds the line of this step; the two steps change it on every run`},
		{"an absent line that removes the line of an earlier step", steps(`      - line:
          path: /etc/ssh/sshd_config
          line: PermitRootLogin no
          match: "^PermitRootLogin "
      - line:
          path: /etc/ssh/sshd_config
          match: "^PermitRootLogin"
          absent: true
`), "", `s: line /etc/ssh/sshd_config: the match "^PermitRootLogin" finds the line of s: line /etc/ssh/sshd_config; the two steps change it on every run`},
		{"a line that an earlier absent step removes", steps(`      - line:
          path: /etc/ssh/sshd_config
          match: "^PermitRootLogin"
          absent: true
      - line:
          path: /etc/ssh/sshd_config
          line: PermitRootLogin no
          match: "^PermitRootLogin "
`), "", `s: line /etc/ssh/sshd_config: the match "^PermitRootLogin" of s: line /etc/ssh/sshd_config finds the line of this step; the two steps change it on every run`},
		{"a line and an absent step with other matches", steps(`      - line:
          path: /etc/ssh/sshd_config
          line: Port 2222
          match: "^#?Port "
      - line:
          path: /etc/ssh/sshd_config
          match: "^#PermitRootLogin"
          absent: true
`), "", ""},
		{"two equal lines", steps(`      - line:
          path: /etc/a
          line: port 1
          match: "^port "
      - line:
          path: /etc/a
          line: port 1
          match: "^port "
`), "", ""},
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
		{"a debconf answer after the install of its package", steps(`      - pkg:
          name: [curl, postfix]
      - debconf:
          package: postfix
          question: postfix/main_mailer_type
          type: select
          value: Local only
`), "", "s: debconf postfix/main_mailer_type: s: pkg curl, postfix installs postfix before this step sets the answer; move this step before it"},
		{"a debconf answer in a later stage", `stages:
  - name: s
    hosts: all
    steps:
      - pkg:
          name: postfix
  - name: t
    hosts: all
    steps:
      - debconf:
          package: postfix
          question: postfix/main_mailer_type
          type: select
          value: Local only
`, "", "t: debconf postfix/main_mailer_type: s: pkg postfix installs postfix before this step sets the answer; move this step before it"},
		{"a debconf answer before the install of its package", steps(`      - debconf:
          package: postfix
          question: postfix/main_mailer_type
          type: select
          value: Local only
      - pkg:
          name: postfix
`), "", ""},
		{"a debconf answer after the install of another package", steps(`      - pkg:
          name: curl
      - debconf:
          package: postfix
          question: postfix/main_mailer_type
          type: select
          value: Local only
`), "", ""},
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
				"winch.yaml":            "name: acme\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml":   tt.pipeline,
			}
			if tt.recipe != "" {
				files["recipes/web/recipe.yaml"] = tt.recipe
				files["recipes/web/files/app.service"] = "[Service]\nExecStart=/bin/sleep infinity\n"
				files["recipes/web/files/other.service"] = "[Service]\nExecStart=/bin/true\n"
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
