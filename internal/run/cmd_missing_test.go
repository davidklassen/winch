package run_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/run"
)

// spec: Modules/cmd
func TestCmdMissingNote(t *testing.T) {
	const cmdUser = "      - cmd: {command: make install, user: deploy}\n"
	const cmdDir = "      - cmd: {command: make install, dir: /srv/app}\n"
	const pkgThenSteps = "      - pkg: {name: postgresql}\n      - cmd: {command: createdb app, user: postgres}\n" +
		"      - file: {path: /etc/a, content: x, owner: postgres}\n      - file: {path: /etc/b, content: x, owner: postgres}\n"
	missingOwner := func(h *fakehost.Hosts) {
		for _, p := range []string{"/etc/a", "/etc/b"} {
			h.SetResult("web1", p, module.Result{Status: module.Change, Action: module.Create, Changes: []string{"owner postgres, group root, mode 0644"}, Missing: []string{"user postgres"}})
		}
	}
	for _, tt := range []struct {
		name  string
		steps string
		host  func(h *fakehost.Hosts)
		want  string
	}{
		{"a user that does not exist", cmdUser, nil, "web1: warning: user deploy does not exist yet and no user step creates it\n"},
		{"a user that an earlier step creates", "      - user: {name: deploy}\n" + cmdUser, nil, ""},
		{"a user that exists", cmdUser, func(h *fakehost.Hosts) { h.SetUser("web1", "deploy") }, ""},
		{"a dir that does not exist", cmdDir, func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, "web1: warning: dir /srv/app does not exist yet and no dir step creates it\n"},
		{"a dir that an earlier step creates", "      - dir: {path: /srv/app}\n" + cmdDir, func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, ""},
		{"a dir that an earlier step creates as a parent", "      - file: {path: /srv/app/env, content: x}\n" + cmdDir, func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, ""},
		{"a dir that exists", cmdDir, nil, ""},
		{"a cmd that does not run", "      - cmd: {command: make install, user: deploy, creates: /srv/made}\n", func(h *fakehost.Hosts) { h.SetFile("web1", "/srv/made", "") }, ""},
		{"a user and a dir", "      - cmd: {command: make install, user: deploy, dir: /srv/app}\n", func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") },
			"web1: warning: user deploy does not exist yet and no user step creates it\nweb1: warning: dir /srv/app does not exist yet and no dir step creates it\n"},
		{"a user that an earlier pkg step can create", pkgThenSteps, missingOwner,
			"web1: note: user postgres does not exist yet; a package that s#1 pkg postgresql installs can create it\n"},
		{"a pkg step that installs nothing", pkgThenSteps, func(h *fakehost.Hosts) { missingOwner(h); h.SetPkg("web1", "postgresql") },
			"web1: warning: user postgres does not exist yet and no user step creates it\n"},
		{"a pkg step after the cmd", "      - cmd: {command: make install, user: deploy}\n      - pkg: {name: postgresql}\n", nil,
			"web1: warning: user deploy does not exist yet and no user step creates it\n"},
		{"a user after a second pkg step", "      - pkg: {name: postgresql}\n      - cmd: {command: createdb app, user: postgres}\n      - pkg: {name: nginx}\n      - file: {path: /etc/a, content: x, owner: postgres}\n", missingOwner,
			"web1: note: user postgres does not exist yet; a package that s#1 pkg postgresql installs can create it\n"},
		{"an owner that an earlier user step creates", "      - user: {name: postgres}\n      - file: {path: /etc/a, content: x, owner: postgres}\n", missingOwner, ""},
		{"the group of a file", "      - file: {path: /etc/a, content: x, group: lgrp}\n", func(h *fakehost.Hosts) {
			h.SetResult("web1", "/etc/a", module.Result{Status: module.Change, Action: module.Create, Missing: []string{"group lgrp"}})
		}, "web1: warning: group lgrp does not exist yet and no group step creates it\n"},
		{"the owner of a stock file", "      - file: {path: /etc/a, stock: true}\n", missingOwner,
			"web1: warning: user postgres does not exist yet and no user step creates it\n"},
		{"the owner of a file", "      - file: {path: /etc/a, content: x, owner: postgres}\n", missingOwner,
			"web1: warning: user postgres does not exist yet and no user step creates it\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := loadWeb1(t, map[string]string{
				"pipelines/site.yaml": steps(tt.steps),
			})
			h := fakehost.New()
			if tt.host != nil {
				tt.host(h)
			}
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			if len(plan.Failed) > 0 {
				t.Fatal(plan.Failed)
			}
			var errOut bytes.Buffer
			plan.WriteNotes(plain(&errOut))
			if errOut.String() != tt.want {
				t.Errorf("notes = %q, want %q", errOut.String(), tt.want)
			}
		})
	}
}

// spec: Modules/cmd
func TestCmdUnlessMissing(t *testing.T) {
	for _, tt := range []struct{ name, steps string }{
		{"a user that an earlier step creates", "      - user: {name: deploy}\n      - cmd: {command: make install, user: deploy, unless: \"true\"}\n"},
		{"a dir that an earlier step creates", "      - dir: {path: /srv/app}\n      - cmd: {command: make install, dir: /srv/app, unless: \"true\"}\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := loadWeb1(t, map[string]string{"pipelines/site.yaml": steps(tt.steps)})
			h := fakehost.New()
			h.RemoveDir("web1", "/srv/app")
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			if len(plan.Failed) > 0 {
				t.Fatal(plan.Failed)
			}
			var out, errOut bytes.Buffer
			plan.Write(plain(&out), plain(&errOut))
			if want := "    ~ cmd make install\n"; !strings.Contains(out.String(), want) {
				t.Errorf("the plan has no %q:\n%s%s", want, out.String(), errOut.String())
			}
		})
	}
}

// spec: Running a pipeline/Plan
func TestAbsentMissingNote(t *testing.T) {
	const pkg = "      - pkg: {name: nginx}\n"
	const link = "      - link: {path: /etc/nginx/sites-enabled/default, absent: true}\n"
	const file = "      - file: {path: /etc/nginx/sites-enabled/default, absent: true}\n"
	const dir = "      - dir: {path: /etc/nginx/sites-enabled/default, absent: true}\n"
	const note = "web1: note: /etc/nginx/sites-enabled/default does not exist yet; a package that s#1 pkg nginx installs can create it, and apply then removes it\n"
	for _, tt := range []struct {
		name  string
		steps string
		host  func(h *fakehost.Hosts)
		want  string
	}{
		{"a link after a pkg install", pkg + link, nil, note},
		{"a file after a pkg install", pkg + file, nil, note},
		{"a dir after a pkg install", pkg + dir, func(h *fakehost.Hosts) { h.RemoveDir("web1", "/etc/nginx/sites-enabled/default") }, note},
		{"after the last of two pkg installs", "      - pkg: {name: curl}\n" + pkg + link, nil, "web1: note: /etc/nginx/sites-enabled/default does not exist yet; a package that s#2 pkg nginx installs can create it, and apply then removes it\n"},
		{"without a pkg step", link, nil, ""},
		{"a pkg step that installs nothing", pkg + link, func(h *fakehost.Hosts) { h.SetPkg("web1", "nginx") }, ""},
		{"a pkg step after it", link + pkg, nil, ""},
		{"a link that exists", pkg + link, func(h *fakehost.Hosts) {
			h.SetResult("web1", "/etc/nginx/sites-enabled/default", module.Result{Status: module.Change, Action: module.Remove})
		}, ""},
		{"a file that exists", pkg + file, func(h *fakehost.Hosts) { h.SetFile("web1", "/etc/nginx/sites-enabled/default", "x") }, ""},
		{"a dir that exists", pkg + dir, nil, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := loadWeb1(t, map[string]string{"pipelines/site.yaml": steps(tt.steps)})
			h := fakehost.New()
			if tt.host != nil {
				tt.host(h)
			}
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			if len(plan.Failed) > 0 {
				t.Fatal(plan.Failed)
			}
			var errOut bytes.Buffer
			plan.WriteNotes(plain(&errOut))
			if errOut.String() != tt.want {
				t.Errorf("notes = %q, want %q", errOut.String(), tt.want)
			}
		})
	}
}
