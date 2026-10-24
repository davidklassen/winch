//go:build integration

package integration

import (
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/file, dir, link
func TestFileModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "file")
	attrs := "owner root, group root, mode 0644"
	vmtest.RunCases(t, vm, "file", "rm -rf /tmp/w && mkdir /tmp/w", []vmtest.Case{
		{
			Name:      "create",
			Args:      &module.File{Path: "/tmp/w/sub/create", Content: new("hello\n")},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/sub (owner root, group root, mode 0755)", attrs}, Old: new("")},
			Unchanged: `[ ! -e /tmp/w/sub ]`,
			After:     `[ "$(cat /tmp/w/sub/create)" = hello ] && [ "$(stat -c '%U %G %a' /tmp/w/sub/create)" = "root root 644" ]`,
		},
		{
			Name:  "ok",
			Setup: `printf 'hello\n' > /tmp/w/f`,
			Args:  &module.File{Path: "/tmp/w/f", Content: new("hello\n")},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "change content",
			Setup:     `printf 'hello\n' > /tmp/w/f`,
			Args:      &module.File{Path: "/tmp/w/f", Content: new("bye\n")},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Old: new("hello\n")},
			Unchanged: `[ "$(cat /tmp/w/f)" = hello ]`,
			After:     `[ "$(cat /tmp/w/f)" = bye ]`,
		},
		{
			Name:  "empty content",
			Args:  &module.File{Path: "/tmp/w/empty", Content: new("")},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{attrs}, Old: new("")},
			After: `[ -f /tmp/w/empty ] && [ ! -s /tmp/w/empty ]`,
		},
		{
			Name:  "binary content",
			Setup: `printf 'a\000b' > /tmp/w/bin`,
			Args:  &module.File{Path: "/tmp/w/bin", Content: new("text\n")},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"content (binary or larger than 1 MiB)"}},
			After: `[ "$(cat /tmp/w/bin)" = text ]`,
		},
		{
			Name:      "owner and mode",
			Setup:     `printf 'x\n' > /tmp/w/f && chown admin:admin /tmp/w/f && chmod 600 /tmp/w/f`,
			Args:      &module.File{Path: "/tmp/w/f", Content: new("x\n")},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner admin → root", "group admin → root", "mode 0600 → 0644"}},
			Unchanged: `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "admin admin 600" ]`,
			After:     `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "root root 644" ]`,
		},
		{
			Name:  "given owner group mode",
			Args:  &module.File{Path: "/tmp/w/f", Content: new("x\n"), Owner: "admin", Group: "adm", Mode: "0640"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"owner admin, group adm, mode 0640"}, Old: new("")},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "admin adm 640" ]`,
		},
		{
			Name:  "setuid mode",
			Args:  &module.File{Path: "/tmp/w/f", Content: new("x\n"), Mode: "4755"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"owner root, group root, mode 4755"}, Old: new("")},
			After: `[ "$(stat -c '%a' /tmp/w/f)" = 4755 ]`,
		},
		{
			Name:      "parent directories",
			Args:      &module.File{Path: "/tmp/w/a/b/c", Content: new("x\n")},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/a (owner root, group root, mode 0755)", "create directory /tmp/w/a/b (owner root, group root, mode 0755)", attrs}, Old: new("")},
			Unchanged: `[ ! -e /tmp/w/a ]`,
			After:     `[ "$(stat -c '%U %G %a' /tmp/w/a /tmp/w/a/b | sort -u)" = "root root 755" ]`,
		},
		{
			Name:  "symlink replaced by a file",
			Setup: `printf 'target\n' > /tmp/w/target && ln -s /tmp/w/target /tmp/w/link`,
			Args:  &module.File{Path: "/tmp/w/link", Content: new("x\n")},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"replace the symbolic link to /tmp/w/target", attrs}, Old: new("")},
			After: `[ -f /tmp/w/link ] && [ ! -L /tmp/w/link ] && [ "$(cat /tmp/w/target)" = target ]`,
		},
		{
			Name:      "absent removes",
			Setup:     `printf 'x\n' > /tmp/w/f`,
			Args:      &module.File{Path: "/tmp/w/f", Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove},
			Unchanged: `[ -f /tmp/w/f ]`,
			After:     `[ ! -e /tmp/w/f ]`,
		},
		{
			Name: "absent when missing is ok",
			Args: &module.File{Path: "/tmp/w/missing", Absent: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "absent when a parent is a file is ok",
			Setup: `printf 'x\n' > /tmp/w/f`,
			Args:  &module.File{Path: "/tmp/w/f/x", Absent: true},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "absent on a directory fails",
			Setup:   `mkdir /tmp/w/d`,
			Args:    &module.File{Path: "/tmp/w/d", Absent: true},
			WantErr: "/tmp/w/d is a directory, not a file",
		},
		{
			Name:    "absent on a symbolic link fails",
			Setup:   `ln -s /etc/hostname /tmp/w/link`,
			Args:    &module.File{Path: "/tmp/w/link", Absent: true},
			WantErr: "/tmp/w/link is a symbolic link, not a file",
		},
		{
			Name:    "a directory at path fails",
			Setup:   `mkdir /tmp/w/d`,
			Args:    &module.File{Path: "/tmp/w/d", Content: new("x\n")},
			WantErr: "/tmp/w/d is a directory, not a file",
		},
		{
			Name:    "a file as parent fails",
			Setup:   `printf 'x\n' > /tmp/w/f`,
			Args:    &module.File{Path: "/tmp/w/f/x", Content: new("x\n")},
			WantErr: "/tmp/w/f is a file, not a directory",
		},
		{
			Name:    "a dangling symbolic link as parent fails",
			Setup:   `ln -s /tmp/w/nothing /tmp/w/link`,
			Args:    &module.File{Path: "/tmp/w/link/x", Content: new("x\n")},
			WantErr: "/tmp/w/link is a symbolic link to a missing target",
		},
		{
			Name:         "owner that does not exist yet",
			Setup:        `printf 'x\n' > /tmp/w/f`,
			Args:         &module.File{Path: "/tmp/w/f", Content: new("x\n"), Owner: "later"},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner root → later (does not exist yet)"}},
			WantApplyErr: `user "later" does not exist`,
		},
	})
}
