package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// winch-stock ships the conffile /etc/winch-stock.conf ("stock"), the file
// /etc/winch-stock.d/README, and /usr/share/winch-stock/example.conf.
const (
	installStock = "dpkg -s winch-stock >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -q winch-stock >/dev/null"
	stockConf    = "/etc/winch-stock.conf"
)

// spec: Modules/file, dir, link (stock, copy_from, the defaults from the
// source, the no-follow rule); Running a pipeline/Plan
func TestStockModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "stock")
	vm.MustRun(t, "apt-get update -q >/dev/null")
	reset := "rm -rf /tmp/w && mkdir /tmp/w\n" + installStock + "\napt-mark unhold winch-stock >/dev/null" + "\nprintf 'stock\\n' > " + stockConf + " && chown root:root " + stockConf + " && chmod 644 " + stockConf
	stockArgs := &module.File{Path: stockConf, Stock: true}
	vmtest.RunCases(t, vm, "file", reset, []vmtest.Case{
		{
			Name: "stock ok",
			Args: stockArgs,
			Want: module.Result{Status: module.OK},
		},
		{
			Name:      "stock restores an edited conffile and its mode",
			Setup:     "echo edited >> " + stockConf + " && chown admin " + stockConf + " && chmod 600 " + stockConf,
			Args:      stockArgs,
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"content of winch-stock 1", "owner admin → root", "mode 0600 → 0644"}},
			Unchanged: `grep -q edited ` + stockConf,
			After:     `[ "$(cat ` + stockConf + `)" = stock ] && [ "$(stat -c '%U %G %a' ` + stockConf + `)" = "root root 644" ]`,
		},
		{
			Name:  "stock with a given group and mode",
			Args:  &module.File{Path: stockConf, Stock: true, Group: "adm", Mode: "0640"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"group root → adm", "mode 0644 → 0640"}},
			After: `[ "$(stat -c '%U %G %a' ` + stockConf + `)" = "root adm 640" ]`,
		},
		{
			Name:      "stock downloads an archive that is not in the cache",
			Setup:     "rm -f /var/cache/apt/archives/winch-stock_*.deb && echo edited >> " + stockConf,
			Args:      stockArgs,
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"content of winch-stock 1"}},
			Unchanged: `grep -q edited ` + stockConf,
			After:     `[ -f /var/cache/apt/archives/winch-stock_1_all.deb ] && [ "$(cat ` + stockConf + `)" = stock ]`,
		},
		{
			Name:      "stock creates a missing file",
			Setup:     "rm " + stockConf,
			Args:      stockArgs,
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content of winch-stock 1", "owner root, group root, mode 0644"}},
			Unchanged: `[ ! -e ` + stockConf + ` ]`,
			After:     `[ "$(cat ` + stockConf + `)" = stock ]`,
		},
		{
			Name:         "stock of a package that is not installed",
			Setup:        "DEBIAN_FRONTEND=noninteractive apt-get purge -y -q winch-stock >/dev/null",
			Args:         stockArgs,
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content of the package that ships " + stockConf + " (no installed package ships it yet)", "owner, group, and mode from the package"}},
			WantApplyErr: "no installed package ships " + stockConf,
			After:        `[ ! -e ` + stockConf + ` ]`,
			Fix:          installStock,
		},
		{
			Name:      "stock of a held package",
			Setup:     "apt-mark hold winch-stock >/dev/null && echo edited >> " + stockConf,
			Args:      stockArgs,
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"content of winch-stock 1"}},
			Unchanged: `grep -q edited ` + stockConf,
			After:     `[ "$(cat ` + stockConf + `)" = stock ]`,
		},
		{
			Name:         "stock of a package that is removed but not purged",
			Setup:        "DEBIAN_FRONTEND=noninteractive apt-get remove -y -q winch-stock >/dev/null && echo edited >> " + stockConf,
			Args:         stockArgs,
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"content of the package that ships " + stockConf + " (no installed package ships it yet)", "owner, group, and mode from the package"}},
			WantApplyErr: "no installed package ships " + stockConf,
			After:        `grep -q edited ` + stockConf,
			Fix:          "DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o Dpkg::Options::=--force-confold winch-stock >/dev/null",
		},
		{
			Name:      "stock takes the mode of the archive",
			Setup:     "dpkg -s monit >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -q monit >/dev/null; chmod 644 /etc/monit/monitrc",
			Args:      &module.File{Path: "/etc/monit/monitrc", Stock: true},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mode 0644 → 0600"}},
			Unchanged: `[ "$(stat -c '%a' /etc/monit/monitrc)" = 644 ]`,
			After:     `[ "$(stat -c '%a' /etc/monit/monitrc)" = 600 ]`,
		},
		{
			Name:         "stock of a path that no package ships",
			Args:         &module.File{Path: "/tmp/w/f", Stock: true},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content of the package that ships /tmp/w/f (no installed package ships it yet)", "owner, group, and mode from the package"}},
			WantApplyErr: "no installed package ships /tmp/w/f",
			FixArgs:      stockArgs,
		},
		{
			Name:  "copy_from creates with the mode of the source and root as owner",
			Setup: `printf 'src\n' > /tmp/w/src && chown nobody:nogroup /tmp/w/src && chmod 640 /tmp/w/src`,
			Args:  &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/src", "owner root, group root, mode 0640"}},
			After: `[ "$(cat /tmp/w/f)" = src ] && [ "$(stat -c '%U %G %a' /tmp/w/f)" = "root root 640" ]`,
		},
		{
			Name:  "copy_from with a given owner",
			Setup: `printf 'src\n' > /tmp/w/src && chown nobody:nogroup /tmp/w/src && chmod 640 /tmp/w/src`,
			Args:  &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src", Owner: "admin"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/src", "owner admin, group root, mode 0640"}},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "admin root 640" ]`,
		},
		{
			Name:  "copy_from drops the setuid and setgid bits of the source",
			Setup: `printf 'src\n' > /tmp/w/src && chown nobody:nogroup /tmp/w/src && chmod 6755 /tmp/w/src`,
			Args:  &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/src", "owner root, group root, mode 0755"}},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "root root 755" ]`,
		},
		{
			Name:  "copy_from with a given setuid mode",
			Setup: `printf 'src\n' > /tmp/w/src && chown nobody:nogroup /tmp/w/src && chmod 4755 /tmp/w/src`,
			Args:  &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src", Mode: "4755"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/src", "owner root, group root, mode 4755"}},
			After: `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "root root 4755" ]`,
		},
		{
			Name:  "copy_from ok",
			Setup: `printf 'src\n' > /tmp/w/src && cp -p /tmp/w/src /tmp/w/f`,
			Args:  &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "copy_from changes the content",
			Setup:     `printf 'new\n' > /tmp/w/src && printf 'old\n' > /tmp/w/f`,
			Args:      &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"content from /tmp/w/src"}},
			Unchanged: `[ "$(cat /tmp/w/f)" = old ]`,
			After:     `[ "$(cat /tmp/w/f)" = new ]`,
		},
		{
			Name:  "copy_from a link copies its target",
			Setup: `printf 'target\n' > /tmp/w/t && chmod 600 /tmp/w/t && ln -s t /tmp/w/src`,
			Args:  &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/src", "owner root, group root, mode 0600"}},
			After: `[ -f /tmp/w/f ] && [ ! -L /tmp/w/f ] && [ "$(cat /tmp/w/f)" = target ] && [ "$(stat -c '%a' /tmp/w/f)" = 600 ]`,
		},
		{
			Name:      "copy_from takes the mode of the source on every run, not its owner",
			Setup:     `printf 'src\n' > /tmp/w/src && cp /tmp/w/src /tmp/w/f && chown nobody:nogroup /tmp/w/src && chmod 600 /tmp/w/src`,
			Args:      &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mode 0644 → 0600"}},
			Unchanged: `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "root root 644" ]`,
			After:     `[ "$(stat -c '%U %G %a' /tmp/w/f)" = "root root 600" ]`,
		},
		{
			Name:         "copy_from below a link to a missing target",
			Setup:        `ln -s /tmp/w/later /tmp/w/l`,
			Args:         &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/l/src"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/l/src (does not exist yet)", "owner root, group root, mode from /tmp/w/l/src"}},
			WantApplyErr: "/tmp/w/l/src does not exist",
			Fix:          `mkdir /tmp/w/later && printf 'src\n' > /tmp/w/later/src`,
		},
		{
			Name:         "copy_from a missing source",
			Args:         &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/src (does not exist yet)", "owner root, group root, mode from /tmp/w/src"}},
			WantApplyErr: "/tmp/w/src does not exist",
			After:        `[ ! -e /tmp/w/f ]`,
			Fix:          `printf 'src\n' > /tmp/w/src`,
		},
		{
			Name:         "copy_from a missing source with a given mode",
			Args:         &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src", Mode: "0600"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/src (does not exist yet)", "owner root, group root, mode 0600"}},
			WantApplyErr: "/tmp/w/src does not exist",
			Fix:          `printf 'src\n' > /tmp/w/src`,
		},
		{
			Name:         "copy_from a missing source with a given owner",
			Args:         &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src", Owner: "admin"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"content from /tmp/w/src (does not exist yet)", "owner admin, group root, mode from /tmp/w/src"}},
			WantApplyErr: "/tmp/w/src does not exist",
			Fix:          `printf 'src\n' > /tmp/w/src`,
		},
		{
			Name:    "copy_from a named pipe fails",
			Setup:   `mkfifo /tmp/w/src`,
			Args:    &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src"},
			WantErr: "/tmp/w/src is a named pipe, not a file",
		},
		{
			Name:    "copy_from a device fails",
			Args:    &module.File{Path: "/tmp/w/f", CopyFrom: "/dev/zero"},
			WantErr: "/dev/zero is a character device, not a file",
		},
		{
			Name:      "copy_from through a link in a user's home fails",
			Setup:     `printf 'src\n' > /tmp/w/src && rm -rf /home/admin/w && ln -s /tmp/w /home/admin/w`,
			Args:      &module.File{Path: "/tmp/w/f", CopyFrom: "/home/admin/w/src"},
			WantErr:   "/home/admin/w is a symbolic link in /home/admin, which a user other than root can write",
			Unchanged: `[ ! -e /tmp/w/f ]`,
		},
		{
			Name:      "copy_from a link in a user's home fails",
			Setup:     `printf 'src\n' > /tmp/w/src && rm -rf /home/admin/s && ln -s /tmp/w/src /home/admin/s`,
			Args:      &module.File{Path: "/tmp/w/f", CopyFrom: "/home/admin/s"},
			WantErr:   "/home/admin/s is a symbolic link in /home/admin, which a user other than root can write",
			Unchanged: `[ ! -e /tmp/w/f ]`,
		},
		{
			Name:         "copy_from with a failing validate keeps the old file",
			Setup:        `printf 'bad\n' > /tmp/w/src && printf 'old\n' > /tmp/w/f`,
			Args:         &module.File{Path: "/tmp/w/f", CopyFrom: "/tmp/w/src", Validation: new("grep -q good /tmp/w/f")},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"content from /tmp/w/src"}},
			WantApplyErr: "grep -q good /tmp/w/f",
			After:        `[ "$(cat /tmp/w/f)" = old ]`,
			Fix:          `printf 'good\n' > /tmp/w/src`,
		},
	})
}

// spec: Modules/file, dir, link (dir purge, flags, mount points, the
// no-follow rule)
func TestPurgeModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "purge")
	vm.MustRun(t, "apt-get update -q >/dev/null && "+installStock)
	attrs := "owner root, group root, mode 0755"
	reset := "[ ! -d /tmp/w ] || find /tmp/w -depth -mindepth 1 -type d -exec mountpoint -q {} \\; -exec umount {} \\;\n[ ! -e /tmp/w ] || find /tmp/w \\( -type f -o -type d \\) -exec chattr -ia {} +\nrm -rf /tmp/w && mkdir /tmp/w && mkdir /tmp/w/d"
	vmtest.RunCases(t, vm, "dir", reset, []vmtest.Case{
		{
			Name:      "removes an unknown file and keeps a written one",
			Setup:     `touch /tmp/w/d/a /tmp/w/d/keep`,
			Args:      &module.Dir{Path: "/tmp/w/d", Purge: true, Keep: []string{"/tmp/w/d/keep"}},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /tmp/w/d/a"}},
			Unchanged: `[ -e /tmp/w/d/a ]`,
			After:     `[ ! -e /tmp/w/d/a ] && [ -e /tmp/w/d/keep ]`,
		},
		{
			Name:  "ok when only written entries are there",
			Setup: `touch /tmp/w/d/keep`,
			Args:  &module.Dir{Path: "/tmp/w/d", Purge: true, Keep: []string{"/tmp/w/d/keep"}},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:      "removes a directory with its content and links without following them",
			Setup:     `mkdir -p /tmp/w/d/sub/x /tmp/w/t && touch /tmp/w/d/sub/f /tmp/w/d/sub/x/g /tmp/w/t/h && ln -s /tmp/w/t /tmp/w/d/dl && ln -s /tmp/w/t/h /tmp/w/d/l`,
			Args:      &module.Dir{Path: "/tmp/w/d", Purge: true},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove symbolic link /tmp/w/d/dl", "remove symbolic link /tmp/w/d/l", "remove directory /tmp/w/d/sub: 2 files, 1 directory"}},
			Unchanged: `[ -f /tmp/w/d/sub/x/g ]`,
			After:     `[ -z "$(ls -A /tmp/w/d)" ] && [ -f /tmp/w/t/h ]`,
		},
		{
			Name:  "keeps the parent of a written path, and names with a common prefix go",
			Setup: `mkdir -p /tmp/w/d/sub /tmp/w/d/site2 && touch /tmp/w/d/site /tmp/w/d/site.bak /tmp/w/d/sub/a /tmp/w/d/sub/b`,
			Args:  &module.Dir{Path: "/tmp/w/d", Purge: true, Keep: []string{"/tmp/w/d/site", "/tmp/w/d/sub/a"}},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /tmp/w/d/site.bak", "remove directory /tmp/w/d/site2: 0 files, 0 directories"}},
			After: `[ -e /tmp/w/d/site ] && [ -e /tmp/w/d/sub/a ] && [ -e /tmp/w/d/sub/b ] && [ ! -e /tmp/w/d/site.bak ] && [ ! -e /tmp/w/d/site2 ]`,
		},
		{
			Name:  "keeps a file that a package owns",
			Setup: `touch /etc/winch-stock.d/unknown`,
			Args:  &module.Dir{Path: "/etc/winch-stock.d", Purge: true},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /etc/winch-stock.d/unknown"}},
			After: `[ -f /etc/winch-stock.d/README ] && [ ! -e /etc/winch-stock.d/unknown ]`,
		},
		{
			Name:  "keeps the enable links of units",
			Setup: enableSSH + " && touch /etc/systemd/system/multi-user.target.wants/junk",
			Args:  &module.Dir{Path: "/etc/systemd/system/multi-user.target.wants", Purge: true},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /etc/systemd/system/multi-user.target.wants/junk"}},
			After: `[ -L /etc/systemd/system/multi-user.target.wants/ssh.service ] && [ ! -e /etc/systemd/system/multi-user.target.wants/junk ]`,
		},
		{
			Name:  "keeps the links and the wants directories in /etc/systemd/system",
			Setup: enableSSH + " && touch /etc/systemd/system/junk.service",
			Args:  &module.Dir{Path: "/etc/systemd/system", Purge: true},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /etc/systemd/system/junk.service"}},
			After: `[ -L /etc/systemd/system/sshd.service ] && [ -d /etc/systemd/system/multi-user.target.wants ] && [ ! -e /etc/systemd/system/junk.service ]`,
		},
		{
			Name:      "a link at path is followed",
			Setup:     `mkdir /tmp/w/t && touch /tmp/w/t/a && ln -s t /tmp/w/l`,
			Args:      &module.Dir{Path: "/tmp/w/l", Purge: true},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /tmp/w/l/a"}, Link: "t"},
			Unchanged: `[ -e /tmp/w/t/a ]`,
			After:     `[ ! -e /tmp/w/t/a ] && [ -L /tmp/w/l ]`,
		},
		{
			Name:  "a missing directory is created",
			Args:  &module.Dir{Path: "/tmp/w/new", Purge: true},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{attrs}},
			After: `[ -d /tmp/w/new ]`,
		},
		{
			Name:      "an immutable entry fails",
			Setup:     `touch /tmp/w/d/a && chattr +i /tmp/w/d/a`,
			Args:      &module.Dir{Path: "/tmp/w/d", Purge: true},
			WantErr:   "/tmp/w/d/a is immutable; chattr -i changes it",
			Unchanged: `[ -e /tmp/w/d/a ]`,
		},
		{
			Name:      "an append-only purge directory fails",
			Setup:     `touch /tmp/w/d/a && chattr +a /tmp/w/d`,
			Args:      &module.Dir{Path: "/tmp/w/d", Purge: true},
			WantErr:   "/tmp/w/d is append-only; chattr -a changes it",
			Unchanged: `[ -e /tmp/w/d/a ]`,
		},
		{
			Name:      "a mount point in an entry fails",
			Setup:     `mkdir -p /tmp/w/d/x/m && mount -t tmpfs tmpfs /tmp/w/d/x/m && touch /tmp/w/d/x/m/f`,
			Args:      &module.Dir{Path: "/tmp/w/d", Purge: true},
			WantErr:   "/tmp/w/d/x/m is a mount point",
			Unchanged: `[ -e /tmp/w/d/x/m/f ]`,
		},
		{
			Name:      "a purge path behind a link in a user's home fails",
			Setup:     `touch /tmp/w/d/a && rm -rf /home/admin/w && ln -s /tmp/w/d /home/admin/w`,
			Args:      &module.Dir{Path: "/home/admin/w", Purge: true},
			WantErr:   "/home/admin/w is a symbolic link in /home/admin, which a user other than root can write",
			Unchanged: `[ -e /tmp/w/d/a ]`,
		},
		{
			Name:         "a link put in a user's home before apply fails",
			Setup:        `touch /tmp/w/d/b && rm -rf /home/admin/w && mkdir -p /home/admin/w/d && touch /home/admin/w/d/a`,
			Args:         &module.Dir{Path: "/home/admin/w/d", Purge: true},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove file /home/admin/w/d/a"}},
			BeforeApply:  `rm -rf /home/admin/w && ln -s /tmp/w /home/admin/w`,
			WantApplyErr: "/home/admin/w is a symbolic link in /home/admin, which a user other than root can write",
			After:        `[ -e /tmp/w/d/b ]`,
			Fix:          "rm /home/admin/w && mkdir -p /home/admin/w/d && touch /home/admin/w/d/a",
		},
	})
}

const purgePipeline = `stages:
  - name: base
    hosts: all
    steps:
      - dir:
          path: /etc/w
          purge: true
      - file:
          path: /etc/w/base
          content: base
      - cmd:
          command: touch /etc/w/done
          creates: /etc/w/done
  - name: late
    hosts: all
    steps:
      - file:
          path: /etc/w/late
          content: late
`

// spec: Modules/file, dir, link (dir purge: any pipeline, a skipped stage,
// the creates path of a cmd)
func TestPurgePipeline(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "purgepipe")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: purge\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  purgepipe: {}\n",
		"pipelines/site.yaml":   purgePipeline,
		"pipelines/other.yaml":  "stages:\n  - name: s\n    hosts: all\n    steps:\n      - file:\n          path: /etc/w/other\n          content: other\n",
	})
	vm.MustRun(t, "mkdir /etc/w && touch /etc/w/late /etc/w/other /etc/w/unknown")
	r := lab.Winch(t, dir, "plan", "site", "--stages", "base")
	for _, want := range []string{"~ dir /etc/w\n", "remove file /etc/w/unknown\n", "+ file /etc/w/base\n", "+ cmd touch /etc/w/done\n"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("first plan: no %q in %q", want, r.Stdout)
		}
	}
	for _, kept := range []string{"/etc/w/late", "/etc/w/other"} {
		if strings.Contains(r.Stdout, "remove file "+kept) {
			t.Errorf("first plan removes %s: %q", kept, r.Stdout)
		}
	}
	if r := lab.Winch(t, dir, "apply", "site", "--stages", "base", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d, stderr %q", r.Code, r.Stderr)
	}
	if out := vm.MustRun(t, "ls /etc/w | tr '\\n' ' '"); out != "base done late other " {
		t.Errorf("after apply: %q", out)
	}
	if r := lab.Winch(t, dir, "plan", "site", "--stages", "base", "--exit-code"); r.Code != 0 {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
