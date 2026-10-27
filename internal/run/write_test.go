package run

import (
	"errors"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

// spec: Modules/file, dir, link
func TestWriteStepNamesLink(t *testing.T) {
	st := project.Step{Module: "dir", Args: &module.Dir{Path: "/var/run"}}
	res := module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mode 0700 → 0755"}, Link: "/run\x1b[2A"}
	var b color.Text
	writeStep(&b, "    ", st, res)
	want := "    ~ dir /var/run (link to /run?[2A)\n        mode 0700 → 0755\n"
	if b.String() != want {
		t.Errorf("writeStep = %q, want %q", b.String(), want)
	}
}

// spec: CLI/Output
func TestHostErrorControlCharacters(t *testing.T) {
	err := "base: failed: file /tmp/x: then: exit status 1: one\n\x1b[2K\x1b[1Atwo\tz\u202E\r"
	want := "web1: base: failed: file /tmp/x: then: exit status 1: one\n?[2K?[1Atwo\tz??\n"
	var out, errOut strings.Builder
	w := func(b *strings.Builder) *color.Writer { return color.NewWriter(b, secret.NewFilter().Parts, false) }
	Text(w(&out), w(&errOut)).Host(HostEvent{Phase: "apply", Host: "web1", Status: "failed", Error: err})
	if errOut.String() != want {
		t.Errorf("apply error = %q, want %q", errOut.String(), want)
	}
	p := &Plan{Hosts: []project.Host{{Name: "web1"}}, Failed: map[string]error{"web1": errors.New(err)}}
	out.Reset()
	errOut.Reset()
	p.Write(w(&out), w(&errOut))
	if errOut.String() != want {
		t.Errorf("plan error = %q, want %q", errOut.String(), want)
	}
}

// spec: CLI/Output
func TestCommand(t *testing.T) {
	tests := []struct{ cmd, want string }{
		{"newaliases", " newaliases"},
		{"newaliases\n", " newaliases"},
		{"a\nb\n", "\n  a\n  b"},
		{"a\n\nb\x1b", "\n  a\n\n  b?"},
	}
	for _, tt := range tests {
		if got := command(tt.cmd, "  "); got != tt.want {
			t.Errorf("command(%q) = %q, want %q", tt.cmd, got, tt.want)
		}
	}
}
