package run_test

import (
	"bytes"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/cmd
func TestCmdMissingNote(t *testing.T) {
	const cmdUser = "      - cmd: {command: make install, user: deploy}\n"
	const cmdDir = "      - cmd: {command: make install, dir: /srv/app}\n"
	for _, tt := range []struct {
		name  string
		steps string
		host  func(h *fakehost.Hosts)
		want  string
	}{
		{"a user that does not exist", cmdUser, nil, "web1: note: user deploy does not exist yet and no user step creates it\n"},
		{"a user that an earlier step creates", "      - user: {name: deploy}\n" + cmdUser, nil, ""},
		{"a user that exists", cmdUser, func(h *fakehost.Hosts) { h.SetUser("web1", "deploy") }, ""},
		{"a dir that does not exist", cmdDir, func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, "web1: note: dir /srv/app does not exist yet and no dir step creates it\n"},
		{"a dir that an earlier step creates", "      - dir: {path: /srv/app}\n" + cmdDir, func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, ""},
		{"a dir that an earlier step creates as a parent", "      - file: {path: /srv/app/env, content: x}\n" + cmdDir, func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") }, ""},
		{"a dir that exists", cmdDir, nil, ""},
		{"a cmd that does not run", "      - cmd: {command: make install, user: deploy, creates: /srv/made}\n", func(h *fakehost.Hosts) { h.SetFile("web1", "/srv/made", "") }, ""},
		{"a user and a dir", "      - cmd: {command: make install, user: deploy, dir: /srv/app}\n", func(h *fakehost.Hosts) { h.RemoveDir("web1", "/srv/app") },
			"web1: note: user deploy does not exist yet and no user step creates it\nweb1: note: dir /srv/app does not exist yet and no dir step creates it\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: missing\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml":   steps(tt.steps),
			})
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
			if err != nil {
				t.Fatal(err)
			}
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
