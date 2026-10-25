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
			Name:      "change the target from one directory to another",
			Setup:     `mkdir /tmp/w/a /tmp/w/b && ln -s /tmp/w/a /tmp/w/l`,
			Args:      &module.Link{Path: "/tmp/w/l", Target: new("/tmp/w/b")},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"target /tmp/w/a → /tmp/w/b"}},
			Unchanged: `[ "$(readlink /tmp/w/l)" = /tmp/w/a ]`,
			After:     `[ "$(readlink /tmp/w/l)" = /tmp/w/b ] && [ -z "$(ls -A /tmp/w/a)$(ls -A /tmp/w/b)" ]`,
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
		{
			Name:    "a FIFO at path fails",
			Setup:   "mkfifo /tmp/w/p",
			Args:    &module.Link{Path: "/tmp/w/p", Target: new("/etc/hostname")},
			WantErr: "/tmp/w/p is a named pipe, not a symbolic link",
		},
		{
			Name:    "a socket at path fails",
			Setup:   mksock,
			Args:    &module.Link{Path: "/tmp/w/s", Absent: true},
			WantErr: "/tmp/w/s is a socket, not a symbolic link",
		},
		{
			Name:    "a link in a user's home fails",
			Setup:   `rm -rf /home/admin/w && ln -s /tmp/w /home/admin/w`,
			Args:    &module.Link{Path: "/home/admin/w/l", Target: new("/etc/hostname")},
			WantErr: "/home/admin/w is a symbolic link in /home/admin, which a user other than root can write",
		},
		{
			Name:         "a link put in a user's home before apply fails",
			Setup:        `rm -rf /home/admin/w && mkdir /home/admin/w && chown admin: /home/admin/w`,
			Args:         &module.Link{Path: "/home/admin/w/l", Target: new("/etc/hostname")},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"target /etc/hostname"}},
			BeforeApply:  `rm -rf /home/admin/w && ln -s /tmp/w /home/admin/w`,
			WantApplyErr: "/home/admin/w is a symbolic link in /home/admin, which a user other than root can write",
			After:        `[ ! -e /tmp/w/l ] && [ ! -L /tmp/w/l ]`,
		},
		{
			Name:    "a link in /tmp fails",
			Setup:   `rm -f /tmp/wl && ln -s /tmp/w /tmp/wl`,
			Args:    &module.Link{Path: "/tmp/wl/l", Target: new("/etc/hostname")},
			WantErr: "/tmp/wl is a symbolic link in /tmp, which a user other than root can write",
		},
		{
			Name:  "a path under /var/run works",
			Setup: `rm -rf /run/w`,
			Args:  &module.Link{Path: "/var/run/w/l", Target: new("/etc/hostname")},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /var/run/w (owner root, group root, mode 0755)", "target /etc/hostname"}},
			After: `[ -L /run/w/l ]`,
		},
		{
			Name:    "absent through a link in a user's home fails",
			Setup:   `rm -rf /home/admin/w && ln -s /tmp/w /home/admin/w && ln -s /etc/hostname /tmp/w/l`,
			Args:    &module.Link{Path: "/home/admin/w/l", Absent: true},
			WantErr: "/home/admin/w is a symbolic link in /home/admin, which a user other than root can write",
		},
		{
			Name:  "a path with spaces and shell characters",
			Args:  &module.Link{Path: oddDir, Target: new(oddDir + " $x")},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"target " + oddDir + " $x"}},
			After: `[ "$(readlink ` + vmtest.Quote(oddDir) + `)" = ` + vmtest.Quote(oddDir+" $x") + " ] && [ ! -e /tmp/pwn ]",
		},
	})
}
