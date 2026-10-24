package integration

import (
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/file, dir, link
func TestLinkModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "link")
	vmtest.RunCases(t, vm, "link", "rm -rf /tmp/w && mkdir /tmp/w", []vmtest.Case{
		{
			Name:      "create with parents",
			Args:      &module.Link{Path: "/tmp/w/a/l", Target: new("/etc/hostname")},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/a (owner root, group root, mode 0755)", "target /etc/hostname"}},
			Unchanged: `[ ! -e /tmp/w/a ]`,
			After:     `[ "$(readlink /tmp/w/a/l)" = /etc/hostname ] && [ "$(stat -c '%U %G %a' /tmp/w/a)" = "root root 755" ]`,
		},
		{
			Name:  "ok",
			Setup: `ln -s /etc/hostname /tmp/w/l`,
			Args:  &module.Link{Path: "/tmp/w/l", Target: new("/etc/hostname")},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "change the target",
			Setup:     `ln -s /etc/hostname /tmp/w/l`,
			Args:      &module.Link{Path: "/tmp/w/l", Target: new("/etc/hosts")},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"target /etc/hostname → /etc/hosts"}},
			Unchanged: `[ "$(readlink /tmp/w/l)" = /etc/hostname ]`,
			After:     `[ "$(readlink /tmp/w/l)" = /etc/hosts ] && [ -f /etc/hostname ]`,
		},
		{
			Name:  "a target that does not exist",
			Args:  &module.Link{Path: "/tmp/w/l", Target: new("/tmp/w/nothing")},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"target /tmp/w/nothing"}},
			After: `[ -L /tmp/w/l ] && [ "$(readlink /tmp/w/l)" = /tmp/w/nothing ]`,
		},
		{
			Name:  "a relative target",
			Args:  &module.Link{Path: "/tmp/w/l", Target: new("../hostname")},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"target ../hostname"}},
			After: `[ "$(readlink /tmp/w/l)" = ../hostname ]`,
		},
		{
			Name:      "absent removes",
			Setup:     `ln -s /etc/hostname /tmp/w/l`,
			Args:      &module.Link{Path: "/tmp/w/l", Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove},
			Unchanged: `[ -L /tmp/w/l ]`,
			After:     `[ ! -L /tmp/w/l ] && [ -f /etc/hostname ]`,
		},
		{
			Name: "absent when missing is ok",
			Args: &module.Link{Path: "/tmp/w/l", Absent: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:    "absent on a file fails",
			Setup:   `touch /tmp/w/f`,
			Args:    &module.Link{Path: "/tmp/w/f", Absent: true},
			WantErr: "/tmp/w/f is a file, not a symbolic link",
		},
		{
			Name:    "a file at path fails",
			Setup:   `echo keep > /tmp/w/f`,
			Args:    &module.Link{Path: "/tmp/w/f", Target: new("/etc/hostname")},
			WantErr: "/tmp/w/f is a file, not a symbolic link",
		},
		{
			Name:    "absent on a directory fails",
			Setup:   `mkdir /tmp/w/d`,
			Args:    &module.Link{Path: "/tmp/w/d", Absent: true},
			WantErr: "/tmp/w/d is a directory, not a symbolic link",
		},
		{
			Name:    "a directory at path fails",
			Setup:   `mkdir /tmp/w/d`,
			Args:    &module.Link{Path: "/tmp/w/d", Target: new("/etc/hostname")},
			WantErr: "/tmp/w/d is a directory, not a symbolic link",
		},
	})
}
