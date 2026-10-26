package run

import (
	"errors"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
)

// spec: Modules/file, dir, link
func TestWriteStepNamesLink(t *testing.T) {
	st := project.Step{Module: "dir", Args: &module.Dir{Path: "/var/run"}}
	res := module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mode 0700 → 0755"}, Link: "/run\x1b[2A"}
	var b strings.Builder
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
	Text(&out, &errOut).Host(HostEvent{Phase: "apply", Host: "web1", Status: "failed", Error: err})
	if errOut.String() != want {
		t.Errorf("apply error = %q, want %q", errOut.String(), want)
	}
	p := &Plan{Hosts: []project.Host{{Name: "web1"}}, Failed: map[string]error{"web1": errors.New(err)}}
	out.Reset()
	errOut.Reset()
	p.Write(&out, &errOut)
	if errOut.String() != want {
		t.Errorf("plan error = %q, want %q", errOut.String(), want)
	}
}
