package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/vmtest"
)

const twoStages = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "hello\n"
  - name: web
    hosts: web2
    steps:
      - file:
          path: /etc/issue
          content: "web\n"
`

// spec: CLI; CLI/Prompts
func TestSelectionFlags(t *testing.T) {
	t.Run("--hosts", func(t *testing.T) {
		h := fakehost.New()
		r := winch(t, writeProject(t, twoStages), h, false, "", "apply", "site", "--yes", "--hosts", "web2")
		if r.code != exitOK || h.Connects["web1"] != 0 {
			t.Errorf("exit %d, connects of web1 %d", r.code, h.Connects["web1"])
		}
		if _, ok := h.File("web2", "/etc/issue"); !ok {
			t.Error("web2 did not run the stage web")
		}
	})
	t.Run("--stages", func(t *testing.T) {
		h := fakehost.New()
		r := winch(t, writeProject(t, twoStages), h, false, "", "apply", "site", "--yes", "--stages", "web")
		if r.code != exitOK || h.Connects["web1"] != 0 {
			t.Errorf("exit %d, connects of web1 %d", r.code, h.Connects["web1"])
		}
		if _, ok := h.File("web2", "/etc/motd"); ok {
			t.Error("the stage base ran")
		}
	})
	t.Run("--user", func(t *testing.T) {
		h := fakehost.New()
		r := winch(t, writeProject(t, twoStages), h, false, "", "plan", "site", "--user", "web1=root", "--user", "deploy")
		if r.code != exitOK || h.Users["web1"] != "root" || h.Users["web2"] != "deploy" {
			t.Errorf("exit %d, users %q", r.code, h.Users)
		}
	})
	t.Run("an unknown name is exit 3", func(t *testing.T) {
		for _, args := range [][]string{{"--hosts", "web3"}, {"--stages", "wbe"}, {"--user", "web3=root"}} {
			h := fakehost.New()
			r := winch(t, writeProject(t, twoStages), h, false, "", append([]string{"plan", "site"}, args...)...)
			if r.code != exitInvalid || len(h.Connects) != 0 {
				t.Errorf("%q: exit %d, connects %v", args, r.code, h.Connects)
			}
		}
	})
	t.Run("the command that applies the plan keeps the selection", func(t *testing.T) {
		h := fakehost.New()
		args := []string{"apply", "site", "--hosts", "web2 & !web1", "--stages", "base,web", "--user", "web2=root"}
		r := winch(t, writeProject(t, twoStages), h, false, "", args...)
		want := "To apply, run: winch apply site --hosts 'web2 & !web1' --stages base,web --user web2=root --check "
		if r.code != exitConfirm || !strings.Contains(r.out, want) {
			t.Errorf("exit %d, stdout %q", r.code, r.out)
		}
		r = winch(t, writeProject(t, twoStages), h, false, "", append(args, "--json")...)
		if !strings.Contains(r.out, `"command":"winch apply site --hosts 'web2 \u0026 !web1' --stages base,web --user web2=root --json --check `) {
			t.Errorf("stdout %q", r.out)
		}
	})
}

// spec: Remote execution/Sessions; CLI
func TestBatch(t *testing.T) {
	tests := []struct {
		name     string
		terminal bool
		args     []string
		batch    bool
	}{
		{name: "terminal", terminal: true, batch: false},
		{name: "no terminal", terminal: false, batch: true},
		{name: "--batch", terminal: true, args: []string{"--batch"}, batch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			r := winch(t, writeProject(t, motd), h, tt.terminal, "n\n", append([]string{"apply", "site"}, tt.args...)...)
			if len(h.Batch) == 0 || slices.Contains(h.Batch, !tt.batch) {
				t.Errorf("batch %v, want %v", h.Batch, tt.batch)
			}
			if tt.terminal && !strings.Contains(r.err, "Apply these changes? [y/N]") {
				t.Errorf("no question: stderr %q", r.err)
			}
		})
	}
}

// spec: Pipelines; Running a pipeline/Health gates; CLI/JSON output
func TestJSONHealth(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   strings.Replace(motd, "    hosts: all\n", "    hosts: all\n    health:\n      command: systemctl is-active nginx\n", 1),
	})
	r := winch(t, dir, fakehost.New(), false, "", "plan", "site", "--json")
	want := `{"type":"planned","time":"2026-10-26T12:00:00Z","host":"web1","address":"web1:base#health","stage":"base","health":"systemctl is-active nginx","status":"ok"}`
	if !strings.Contains(r.out, want+"\n") {
		t.Errorf("stdout %s\nwant %s", r.out, want)
	}
}

// spec: CLI (--hosts, --stages); Inventory/Host patterns
func TestEmptySelection(t *testing.T) {
	for _, flag := range []string{"--hosts", "--stages"} {
		h := fakehost.New()
		r := winch(t, writeProject(t, twoStages), h, false, "", "apply", "site", "--yes", flag, "")
		if r.code != exitInvalid || len(h.Connects) != 0 {
			t.Errorf("%s '': exit %d, connects %v", flag, r.code, h.Connects)
		}
	}
}

// spec: Running a pipeline/Health gates; CLI/JSON output
func TestJSONHealthApply(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   strings.Replace(motd, "    hosts: all\n", "    hosts: all\n    health:\n      command: check\n", 1),
	})
	r := winch(t, dir, fakehost.New(), false, "", "apply", "site", "--yes", "--json")
	want := `{"type":"applied","time":"2026-10-26T12:00:00Z","host":"web1","address":"web1:base#health","stage":"base","health":"check","status":"ok"}`
	if !strings.Contains(r.out, want+"\n") {
		t.Errorf("stdout %s\nwant %s", r.out, want)
	}
	h := fakehost.New()
	h.FailCommand("web1", "check")
	r = winch(t, dir, h, false, "", "apply", "site", "--yes", "--json")
	want = `{"type":"applied","time":"2026-10-26T12:00:00Z","host":"web1","address":"web1:base#health","stage":"base","health":"check","status":"failed","error":"did not pass within 1m0s: exit status 1"}`
	if r.code != exitFailed || !strings.Contains(r.out, want+"\n") {
		t.Errorf("exit %d, stdout %s\nwant %s", r.code, r.out, want)
	}
}
