package integration

import (
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/line
func TestLineModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "line")
	reset := "[ ! -d /tmp/w ] || find /tmp/w -type f -exec chattr -ia {} +\nrm -rf /tmp/w && mkdir /tmp/w"
	port := func(l string) *module.Line { return &module.Line{Path: "/tmp/w/f", Line: l, Match: "^port "} }
	vmtest.RunCases(t, vm, "line", reset, []vmtest.Case{
		{
			Name:      "replace a matching line",
			Setup:     `printf 'bind 127.0.0.1\nport 6379\ndaemonize no\n' > /tmp/w/f && chown nobody:nogroup /tmp/w/f && chmod 640 /tmp/w/f`,
			Args:      port("port 6380"),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Old: new("port 6379\n")},
			Unchanged: `[ "$(cat /tmp/w/f)" = "$(printf 'bind 127.0.0.1\nport 6379\ndaemonize no')" ]`,
			After:     `printf 'bind 127.0.0.1\nport 6380\ndaemonize no\n' | cmp - /tmp/w/f && [ "$(stat -c '%U %G %a' /tmp/w/f)" = "nobody nogroup 640" ]`,
		},
		{
			Name:  "ok",
			Setup: `printf 'bind 127.0.0.1\nport 6380\n' > /tmp/w/f`,
			Args:  port("port 6380"),
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "add a missing line",
			Setup: `printf 'bind 127.0.0.1\n' > /tmp/w/f`,
			Args:  port("port 6380"),
			Want:  module.Result{Status: module.Change, Action: module.Modify, Old: new("")},
			After: `printf 'bind 127.0.0.1\nport 6380\n' | cmp - /tmp/w/f`,
		},
		{
			Name:  "add after a last line without a newline",
			Setup: `printf 'bind 127.0.0.1' > /tmp/w/f`,
			Args:  port("port 6380"),
			Want:  module.Result{Status: module.Change, Action: module.Modify, Old: new("")},
			After: `printf 'bind 127.0.0.1\nport 6380\n' | cmp - /tmp/w/f`,
		},
		{
			Name:  "add to an empty file",
			Setup: `touch /tmp/w/f`,
			Args:  port("port 6380"),
			Want:  module.Result{Status: module.Change, Action: module.Modify, Old: new("")},
			After: `printf 'port 6380\n' | cmp - /tmp/w/f`,
		},
		{
			Name:  "replace a last line without a newline",
			Setup: `printf 'bind 127.0.0.1\nport 6379' > /tmp/w/f`,
			Args:  port("port 6380"),
			Want:  module.Result{Status: module.Change, Action: module.Modify, Old: new("port 6379\n")},
			After: `printf 'bind 127.0.0.1\nport 6380' | cmp - /tmp/w/f`,
		},
		{
			Name:      "more than one match fails",
			Setup:     `printf 'port 1\nbind 127.0.0.1\nport 2\n' > /tmp/w/f`,
			Args:      port("port 6380"),
			WantErr:   `/tmp/w/f has 2 lines that match "^port ": lines 1, 3`,
			Unchanged: `[ "$(cat /tmp/w/f)" = "$(printf 'port 1\nbind 127.0.0.1\nport 2')" ]`,
		},
		{
			Name:      "remove with absent",
			Setup:     `printf 'port 1\nbind 127.0.0.1\nport 2\n' > /tmp/w/f`,
			Args:      &module.Line{Path: "/tmp/w/f", Match: "^port ", Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Old: new("port 1\nport 2\n")},
			Unchanged: `[ "$(grep -c ^port /tmp/w/f)" = 2 ]`,
			After:     `printf 'bind 127.0.0.1\n' | cmp - /tmp/w/f`,
		},
		{
			Name:  "absent without a match is ok",
			Setup: `printf 'bind 127.0.0.1\n' > /tmp/w/f`,
			Args:  &module.Line{Path: "/tmp/w/f", Match: "^port ", Absent: true},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name: "absent without the file is ok",
			Args: &module.Line{Path: "/tmp/w/f", Match: "^port ", Absent: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "absent on a large file shows no old lines",
			Setup: `yes 'port 1' | head -c 1100000 > /tmp/w/f`,
			Args:  &module.Line{Path: "/tmp/w/f", Match: "^port ", Absent: true},
			Want:  module.Result{Status: module.Change, Action: module.Modify, OldReason: "larger than 1 MiB"},
			After: `[ ! -s /tmp/w/f ]`,
		},
		{
			Name:  "a line that is not UTF-8 shows no old line",
			Setup: `printf 'port \351\n' > /tmp/w/f`,
			Args:  port("port 6380"),
			Want:  module.Result{Status: module.Change, Action: module.Modify, OldReason: "not UTF-8"},
			After: `printf 'port 6380\n' | cmp - /tmp/w/f`,
		},
		{
			Name: "absent without the parent is ok",
			Args: &module.Line{Path: "/tmp/w/d/f", Match: "^port ", Absent: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:         "a missing file is a change, and apply fails",
			Args:         port("port 6380"),
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"/tmp/w/f does not exist yet"}, Old: new("")},
			WantApplyErr: "/tmp/w/f does not exist; line does not create a file",
			After:        `[ ! -e /tmp/w/f ]`,
			Fix:          "touch /tmp/w/f",
		},
		{
			Name:    "a directory fails",
			Setup:   `mkdir /tmp/w/f`,
			Args:    port("port 6380"),
			WantErr: "/tmp/w/f is a directory, not a file",
		},
		{
			Name:    "a symbolic link fails",
			Setup:   `printf 'port 1\n' > /tmp/w/g && ln -s g /tmp/w/f`,
			Args:    port("port 6380"),
			WantErr: "/tmp/w/f is a symbolic link, not a file",
		},
		{
			Name:      "an immutable file fails",
			Setup:     `printf 'port 1\n' > /tmp/w/f && chattr +i /tmp/w/f`,
			Args:      port("port 6380"),
			WantErr:   "/tmp/w/f is immutable; chattr -i changes it",
			Unchanged: `[ "$(cat /tmp/w/f)" = "port 1" ]`,
		},
		{
			Name:         "validate keeps the old file when it fails",
			Setup:        `printf 'Port 22\n' > /tmp/w/f`,
			Args:         &module.Line{Path: "/tmp/w/f", Line: "Port none", Match: "^Port ", Validation: new("sshd -t -f /tmp/w/f")},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Old: new("Port 22\n"), Validates: true},
			WantApplyErr: "validate",
			After:        `printf 'Port 22\n' | cmp - /tmp/w/f && [ -z "$(ls -A /tmp/w | grep -v '^f$')" ]`,
			FixArgs:      &module.Line{Path: "/tmp/w/f", Line: "Port 2222", Match: "^Port ", Validation: new("sshd -t -f /tmp/w/f")},
		},
		{
			Name:  "validate",
			Setup: `printf 'Port 22\n' > /tmp/w/f`,
			Args:  &module.Line{Path: "/tmp/w/f", Line: "Port 2222", Match: "^Port ", Validation: new("sshd -t -f /tmp/w/f")},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Old: new("Port 22\n"), Validates: true},
			After: `printf 'Port 2222\n' | cmp - /tmp/w/f`,
		},
		{
			Name:         "validate with absent keeps the old file when it fails",
			Setup:        `printf 'Port 22\nPort 23\n' > /tmp/w/f`,
			Args:         &module.Line{Path: "/tmp/w/f", Match: "^Port 22", Absent: true, Validation: new("grep -q '^Port 22' /tmp/w/f")},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Old: new("Port 22\n"), Validates: true},
			WantApplyErr: "validate",
			After:        `printf 'Port 22\nPort 23\n' | cmp - /tmp/w/f && [ -z "$(ls -A /tmp/w | grep -v '^f$')" ]`,
			FixArgs:      &module.Line{Path: "/tmp/w/f", Match: "^Port 22", Absent: true, Validation: new("grep -q '^Port 23' /tmp/w/f")},
		},
		{
			Name:  "an immutable file that is already right is ok",
			Setup: `printf 'port 6380\n' > /tmp/w/f && chattr +i /tmp/w/f`,
			Args:  port("port 6380"),
			Want:  module.Result{Status: module.OK},
		},
	})
}
