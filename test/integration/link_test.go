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
	reset := "grep -o ' /tmp/w/[^ ]*' /proc/self/mounts | sort -r | xargs -r umount\n[ ! -d /tmp/w ] || find /tmp/w \\( -type f -o -type d \\) -exec chattr -ia {} +\nrm -rf /tmp/w /tmp/wsrc && mkdir /tmp/w"
	vmtest.RunCases(t, vm, "link", reset, []vmtest.Case{
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
			Name:      "a target with a newline gives one change line",
			Setup:     `ln -s "$(printf 'a\nb')" /tmp/w/l`,
			Args:      &module.Link{Path: "/tmp/w/l", Target: new("/etc/hosts")},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"target a?b → /etc/hosts"}},
			Unchanged: `[ "$(readlink /tmp/w/l)" = "$(printf 'a\nb')" ]`,
			After:     `[ "$(readlink /tmp/w/l)" = /etc/hosts ]`,
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
			Name:  "absent when a parent is a file is ok",
			Setup: `touch /tmp/w/f`,
			Args:  &module.Link{Path: "/tmp/w/f/l", Absent: true},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "absent on a file fails",
			Setup:   `touch /tmp/w/f`,
			Args:    &module.Link{Path: "/tmp/w/f", Absent: true},
			WantErr: "/tmp/w/f is a file, not a symbolic link",
		},
		{
			Name:    "a file at path fails and names replace",
			Setup:   `echo keep > /tmp/w/f`,
			Args:    &module.Link{Path: "/tmp/w/f", Target: new("/etc/hostname")},
			WantErr: "/tmp/w/f is a file; add replace: true to remove it",
		},
		{
			Name:      "replace a file",
			Setup:     `echo keep > /tmp/w/f`,
			Args:      &module.Link{Path: "/tmp/w/f", Target: new("/etc/hostname"), Replace: true},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /tmp/w/f", "target /etc/hostname"}},
			Unchanged: `[ "$(cat /tmp/w/f)" = keep ]`,
			After:     `[ "$(readlink /tmp/w/f)" = /etc/hostname ]`,
		},
		{
			Name:    "absent on a directory fails",
			Setup:   `mkdir /tmp/w/d`,
			Args:    &module.Link{Path: "/tmp/w/d", Absent: true},
			WantErr: "/tmp/w/d is a directory, not a symbolic link",
		},
		{
			Name:    "a directory at path fails and names replace",
			Setup:   `mkdir /tmp/w/d && touch /tmp/w/d/a /tmp/w/d/b /tmp/w/d/c`,
			Args:    &module.Link{Path: "/tmp/w/d", Target: new("/etc/hostname")},
			WantErr: "/tmp/w/d is a directory with 3 files; add replace: true to remove it",
		},
		{
			Name:      "replace a directory with files",
			Setup:     `mkdir -p /tmp/w/d/x && touch /tmp/w/d/a /tmp/w/d/x/b && ln -s /etc /tmp/w/d/l`,
			Args:      &module.Link{Path: "/tmp/w/d", Target: new("/tmp"), Replace: true},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove directory /tmp/w/d: 3 files, 1 directory", "target /tmp"}},
			Unchanged: `[ -f /tmp/w/d/x/b ]`,
			After:     `[ "$(readlink /tmp/w/d)" = /tmp ] && [ -d /etc/apt ]`,
		},
		{
			Name:  "replace an empty directory",
			Setup: `mkdir /tmp/w/d`,
			Args:  &module.Link{Path: "/tmp/w/d", Target: new("/tmp"), Replace: true},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove directory /tmp/w/d: 0 files, 0 directories", "target /tmp"}},
			After: `[ "$(readlink /tmp/w/d)" = /tmp ]`,
		},
		{
			Name:  "a link that is already right in an immutable directory is ok",
			Setup: `mkdir /tmp/w/d && ln -s /etc/hostname /tmp/w/d/l && chattr +i /tmp/w/d`,
			Args:  &module.Link{Path: "/tmp/w/d/l", Target: new("/etc/hostname")},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "replace an immutable file fails",
			Setup:   `touch /tmp/w/f && chattr +i /tmp/w/f`,
			Args:    &module.Link{Path: "/tmp/w/f", Target: new("/etc/hostname"), Replace: true},
			WantErr: "/tmp/w/f is immutable; chattr -i changes it",
		},
		{
			Name:    "replace a directory with an append-only directory fails",
			Setup:   `mkdir -p /tmp/w/d/x && touch /tmp/w/d/x/b && chattr +a /tmp/w/d/x`,
			Args:    &module.Link{Path: "/tmp/w/d", Target: new("/tmp"), Replace: true},
			WantErr: "/tmp/w/d/x is append-only; chattr -a changes it",
		},
		{
			Name:    "replace a tree with a mount point fails",
			Setup:   `mkdir -p /tmp/w/d/x/m && mount -t tmpfs tmpfs /tmp/w/d/x/m && touch /tmp/w/d/x/m/f`,
			Args:    &module.Link{Path: "/tmp/w/d", Target: new("/tmp"), Replace: true},
			WantErr: "/tmp/w/d/x/m is a mount point",
		},
		{
			Name:         "replace keeps a mount put in the tree before apply",
			Setup:        `mkdir -p /tmp/w/d/m`,
			Args:         &module.Link{Path: "/tmp/w/d", Target: new("/tmp"), Replace: true},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove directory /tmp/w/d: 0 files, 1 directory", "target /tmp"}},
			BeforeApply:  `mount -t tmpfs tmpfs /tmp/w/d/m && touch /tmp/w/d/m/f`,
			WantApplyErr: "/tmp/w/d/m is a mount point",
			After:        `[ -f /tmp/w/d/m/f ]`,
			Fix:          "umount /tmp/w/d/m",
		},
		{
			Name:    "a directory with a mount point fails without replace",
			Setup:   `mkdir -p /tmp/w/d/m && mount -t tmpfs tmpfs /tmp/w/d/m && touch /tmp/w/d/m/f`,
			Args:    &module.Link{Path: "/tmp/w/d", Target: new("/tmp")},
			WantErr: "/tmp/w/d/m is a mount point",
		},
		{
			Name:    "replace a file that is a mount point fails",
			Setup:   `echo keep > /tmp/w/f && echo src > /tmp/wsrc && mount --bind /tmp/wsrc /tmp/w/f`,
			Args:    &module.Link{Path: "/tmp/w/f", Target: new("/tmp"), Replace: true},
			WantErr: "/tmp/w/f is a mount point",
		},
		{
			Name:         "replace a file keeps it when validate fails",
			Setup:        `echo keep > /tmp/w/f`,
			Args:         &module.Link{Path: "/tmp/w/f", Target: new("/etc/hostname"), Replace: true, Validation: new("test -e /tmp/w/valid")},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /tmp/w/f", "target /etc/hostname"}, Validates: true},
			WantApplyErr: "validate",
			After:        `[ ! -L /tmp/w/f ] && [ "$(cat /tmp/w/f)" = keep ] && [ -z "$(ls -A /tmp/w | grep -v '^f$')" ]`,
			Fix:          "touch /tmp/w/valid",
		},
		{
			Name:         "replace a directory keeps it when validate fails",
			Setup:        `mkdir -p /tmp/w/d/x && echo keep > /tmp/w/d/x/f`,
			Args:         &module.Link{Path: "/tmp/w/d", Target: new("/tmp"), Replace: true, Validation: new("test -e /tmp/w/valid")},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove directory /tmp/w/d: 1 file, 1 directory", "target /tmp"}, Validates: true},
			WantApplyErr: "validate",
			After:        `[ ! -L /tmp/w/d ] && [ "$(cat /tmp/w/d/x/f)" = keep ] && [ -z "$(ls -A /tmp/w | grep -v '^d$')" ]`,
			Fix:          "touch /tmp/w/valid",
		},
		{
			Name:  "replace a directory with validate",
			Setup: `mkdir -p /tmp/w/d/x && echo keep > /tmp/w/d/x/f`,
			Args:  &module.Link{Path: "/tmp/w/d", Target: new("/tmp"), Replace: true, Validation: new("[ -L /tmp/w/d ]")},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove directory /tmp/w/d: 1 file, 1 directory", "target /tmp"}, Validates: true},
			After: `[ "$(readlink /tmp/w/d)" = /tmp ] && [ -z "$(ls -A /tmp/w | grep -v '^d$')" ]`,
		},
		{
			Name:    "replace on a FIFO fails",
			Setup:   "mkfifo /tmp/w/p",
			Args:    &module.Link{Path: "/tmp/w/p", Target: new("/etc/hostname"), Replace: true},
			WantErr: "/tmp/w/p is a named pipe, not a symbolic link",
		},
		{
			Name:    "a FIFO at path fails",
			Setup:   "mkfifo /tmp/w/p",
			Args:    &module.Link{Path: "/tmp/w/p", Target: new("/etc/hostname")},
			WantErr: "/tmp/w/p is a named pipe, not a symbolic link",
		},
		{
			Name:    "a socket at path fails",
			Setup:   mksock("/tmp/w/s"),
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
			Fix:          "rm /home/admin/w && mkdir /home/admin/w && chown admin: /home/admin/w",
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
			Name:  "a path with spaces, shell characters, and UTF-8",
			Args:  &module.Link{Path: oddDir, Target: new(oddDir + " $x")},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"target " + oddDir + " $x"}},
			After: `[ "$(readlink ` + vmtest.Quote(oddDir) + `)" = ` + vmtest.Quote(oddDir+" $x") + " ] && [ ! -e /tmp/pwn ]",
		},
	})
}
