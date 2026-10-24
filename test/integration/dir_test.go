//go:build integration

package integration

import (
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/file, dir, link
func TestDirModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "dir")
	attrs := "owner root, group root, mode 0755"
	vmtest.RunCases(t, vm, "dir", "rm -rf /tmp/w && mkdir /tmp/w", []vmtest.Case{
		{
			Name:      "create with parents",
			Args:      &module.Dir{Path: "/tmp/w/a/b"},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/a (owner root, group root, mode 0755)", attrs}},
			Unchanged: `[ ! -e /tmp/w/a ]`,
			After:     `[ "$(stat -c '%F %U %G %a' /tmp/w/a /tmp/w/a/b | sort -u)" = "directory root root 755" ]`,
		},
		{
			Name:  "ok",
			Setup: `mkdir /tmp/w/d`,
			Args:  &module.Dir{Path: "/tmp/w/d"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "owner and mode",
			Setup:     `mkdir /tmp/w/d && chown admin:admin /tmp/w/d && chmod 700 /tmp/w/d`,
			Args:      &module.Dir{Path: "/tmp/w/d"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner admin → root", "group admin → root", "mode 0700 → 0755"}},
			Unchanged: `[ "$(stat -c '%U %G %a' /tmp/w/d)" = "admin admin 700" ]`,
			After:     `[ "$(stat -c '%U %G %a' /tmp/w/d)" = "root root 755" ]`,
		},
		{
			Name:  "given owner group mode",
			Args:  &module.Dir{Path: "/tmp/w/d", Owner: "admin", Group: "adm", Mode: "2750"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"owner admin, group adm, mode 2750"}},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/d)" = "admin adm 2750" ]`,
		},
		{
			Name:  "parents get the default owner and mode",
			Args:  &module.Dir{Path: "/tmp/w/a/b", Owner: "admin", Mode: "0700"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/a (owner root, group root, mode 0755)", "owner admin, group root, mode 0700"}},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/a)" = "root root 755" ] && [ "$(stat -c '%U %G %a' /tmp/w/a/b)" = "admin root 700" ]`,
		},
		{
			Name:         "owner that does not exist yet",
			Args:         &module.Dir{Path: "/tmp/w/d", Owner: "later"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{`owner later, group root, mode 0755; user "later" does not exist yet`}},
			WantApplyErr: `user "later" does not exist`,
		},
		{
			Name:    "absent on a symbolic link fails",
			Setup:   `mkdir /tmp/w/d && ln -s /tmp/w/d /tmp/w/l`,
			Args:    &module.Dir{Path: "/tmp/w/l", Absent: true},
			WantErr: "/tmp/w/l is a symbolic link, not a directory",
		},
		{
			Name:      "absent removes the content",
			Setup:     `mkdir -p /tmp/w/d/x && touch /tmp/w/d/x/f`,
			Args:      &module.Dir{Path: "/tmp/w/d", Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove its content"}},
			Unchanged: `[ -f /tmp/w/d/x/f ]`,
			After:     `[ ! -e /tmp/w/d ]`,
		},
		{
			Name:  "absent removes an empty directory",
			Setup: `mkdir /tmp/w/d`,
			Args:  &module.Dir{Path: "/tmp/w/d", Absent: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove},
			After: `[ ! -e /tmp/w/d ]`,
		},
		{
			Name: "absent when missing is ok",
			Args: &module.Dir{Path: "/tmp/w/d", Absent: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "absent when a parent is a file is ok",
			Setup: `touch /tmp/w/f`,
			Args:  &module.Dir{Path: "/tmp/w/f/d", Absent: true},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "absent on a file fails",
			Setup:   `touch /tmp/w/f`,
			Args:    &module.Dir{Path: "/tmp/w/f", Absent: true},
			WantErr: "/tmp/w/f is a file, not a directory",
		},
		{
			Name:    "a file at path fails",
			Setup:   `touch /tmp/w/f`,
			Args:    &module.Dir{Path: "/tmp/w/f"},
			WantErr: "/tmp/w/f is a file, not a directory",
		},
		{
			Name:    "a symbolic link at path fails",
			Setup:   `ln -s /tmp /tmp/w/l`,
			Args:    &module.Dir{Path: "/tmp/w/l"},
			WantErr: "/tmp/w/l is a symbolic link, not a directory",
		},
		{
			Name:    "a file as parent fails",
			Setup:   `touch /tmp/w/f`,
			Args:    &module.Dir{Path: "/tmp/w/f/d"},
			WantErr: "/tmp/w/f is a file, not a directory",
		},
	})
}
