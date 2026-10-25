package run

import (
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
