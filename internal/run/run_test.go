package run_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

func load(t *testing.T, web3 string) *project.Project {
	t.Helper()
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n  web3:\n    address: " + web3 + "\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "hello\nworld\n"
  - name: cleanup
    hosts: web2
    steps:
      - file:
          path: /etc/issue
          absent: true
`,
	})
	p, err := project.Load(dir, "", "site")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// spec: Running a pipeline/Plan; CLI/Output
func TestPlanOutput(t *testing.T) {
	tests := []struct {
		name  string
		web3  string
		setup func(h *fakehost.Hosts)
	}{
		{name: "create", web3: "web3"},
		{name: "change", web3: "web3", setup: func(h *fakehost.Hosts) {
			h.SetFile("web1", "/etc/motd", "hello\nthere\n")
			h.SetFile("web2", "/etc/motd", "hello\nthere\n")
			h.SetFile("web3", "/etc/motd", "hello\nworld\n")
			h.SetFile("web2", "/etc/issue", "Debian\n")
		}},
		{name: "no-changes", web3: "web3", setup: func(h *fakehost.Hosts) {
			for _, host := range []string{"web1", "web2", "web3"} {
				h.SetFile(host, "/etc/motd", "hello\nworld\n")
			}
		}},
		{name: "check-fails", web3: "web3", setup: func(h *fakehost.Hosts) {
			h.FailCheck("web2")
		}},
		{name: "unreachable", web3: "unreachable"},
		{name: "fails-in-later-stage", web3: "web3", setup: func(h *fakehost.Hosts) {
			h.SetFile("web2", "/etc/issue", "Debian\n")
			h.FailCheck("web2 /etc/issue")
		}},
		{name: "control-characters", web3: "web3", setup: func(h *fakehost.Hosts) {
			h.SetFile("web1", "/etc/motd", "hello\n\x1b]0;owned\x07\x1b[2Aworld\n")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			plan := run.MakePlan(context.Background(), load(t, tt.web3), h.Connector())
			var out, errOut bytes.Buffer
			plan.Write(&out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "plan", tt.name+".golden"),
				[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
			if h.Applies != 0 {
				t.Errorf("plan applied %d steps", h.Applies)
			}
		})
	}
}

// spec: Running a pipeline/Apply; Running a pipeline/Failures
func TestApply(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *fakehost.Hosts)
	}{
		{name: "all"},
		// web2 has a second stage, which must not run after the failure.
		{name: "one-host-fails", setup: func(h *fakehost.Hosts) { h.FailApply("web2") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			h.SetFile("web3", "/etc/motd", "hello\nworld\n")
			h.SetFile("web2", "/etc/issue", "Debian\n")
			if tt.setup != nil {
				tt.setup(h)
			}
			p := load(t, "web3")
			plan := run.MakePlan(context.Background(), p, h.Connector())
			var out, errOut bytes.Buffer
			ok := run.Apply(context.Background(), plan, h.Connector(), &out, &errOut)
			golden.Assert(t, filepath.Join("testdata", "apply", tt.name+".golden"),
				[]byte("stdout:\n"+out.String()+"stderr:\n"+errOut.String()))
			failed := tt.setup != nil
			if ok == failed {
				t.Errorf("Apply = %v, want %v", ok, !failed)
			}
			if c, _ := h.File("web1", "/etc/motd"); c != "hello\nworld\n" {
				t.Errorf("web1 /etc/motd = %q", c)
			}
			if _, ok := h.File("web2", "/etc/issue"); ok != failed {
				t.Errorf("web2 /etc/issue exists = %v, want %v", ok, failed)
			}
			if h.Open != 0 {
				t.Errorf("%d connections are still open", h.Open)
			}
			again := run.MakePlan(context.Background(), p, h.Connector())
			if again.HasChanges() != (tt.setup != nil) {
				t.Errorf("second plan has changes = %v", again.HasChanges())
			}
		})
	}
}

// spec: Running a pipeline/Failures
func TestHasChangesIgnoresFailedHosts(t *testing.T) {
	h := fakehost.New()
	h.SetFile("web2", "/etc/issue", "Debian\n")
	for _, host := range []string{"web1", "web2", "web3"} {
		h.FailCheck(host + " /etc/issue")
	}
	h.FailCheck("web1")
	h.FailCheck("web3")
	plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector())
	if plan.HasChanges() {
		t.Error("a plan whose changes are all on failed hosts has changes")
	}
}
