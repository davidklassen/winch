package integration

import (
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/file, dir, link
func TestValidate(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "validate")
	attrs := "owner root, group root, mode 0644"
	// Only the file of the case is left in /tmp/w: no backup, no temporary file.
	alone := ` && [ "$(ls -A /tmp/w)" = f ]`
	// Each module gets its own session, which ends with its subtest.
	t.Run("file", func(t *testing.T) {
		vmtest.RunCases(t, vm, "file", "rm -rf /tmp/w /tmp/ran && mkdir /tmp/w", fileCases(attrs, alone))
	})
	t.Run("link", func(t *testing.T) { vmtest.RunCases(t, vm, "link", "rm -rf /tmp/w && mkdir /tmp/w", linkCases(alone)) })
}

func fileCases(attrs, alone string) []vmtest.Case {
	return []vmtest.Case{
		{
			Name:  "validate passes",
			Setup: `printf 'old\n' > /tmp/w/f`,
			Args:  &module.File{Path: "/tmp/w/f", Data: []byte("new\n"), Validation: new("grep -qx new /tmp/w/f")},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Old: new("old\n")},
			After: `[ "$(cat /tmp/w/f)" = new ]` + alone,
		},
		{
			Name:         "validate fails and the old file stays",
			Setup:        `printf 'old\n' > /tmp/w/f && chown admin:admin /tmp/w/f && chmod 600 /tmp/w/f`,
			Args:         &module.File{Path: "/tmp/w/f", Data: []byte("new\n"), Validation: new("test -e /tmp/w/valid || { echo bad config >&2; exit 1; }")},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner admin → root", "group admin → root", "mode 0600 → 0644"}, Old: new("old\n")},
			WantApplyErr: "validate: test -e /tmp/w/valid || { echo bad config >&2; exit 1; }: exit status 1: bad config",
			After:        `[ "$(cat /tmp/w/f)" = old ] && [ "$(stat -c '%U %G %a' /tmp/w/f)" = "admin admin 600" ]` + alone,
			Fix:          "touch /tmp/w/valid",
		},
		{
			Name:         "validate fails on a create and the parents go too",
			Args:         &module.File{Path: "/tmp/w/new/sub/f", Data: []byte("new\n"), Validation: new("test -e /tmp/w/valid")},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/new (owner root, group root, mode 0755)", "create directory /tmp/w/new/sub (owner root, group root, mode 0755)", attrs}, Old: new("")},
			WantApplyErr: "validate: test -e /tmp/w/valid: exit status 1",
			Fix:          "touch /tmp/w/valid",
			After:        `[ -z "$(ls -A /tmp/w)" ]`,
		},
		{
			Name:  "a mode change runs no validate",
			Setup: `printf 'new\n' > /tmp/w/f && chmod 600 /tmp/w/f`,
			Args:  &module.File{Path: "/tmp/w/f", Data: []byte("new\n"), Validation: new("touch /tmp/ran")},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mode 0600 → 0644"}},
			After: `[ ! -e /tmp/ran ]`,
		},
		{
			Name:  "validate sees the final owner and mode",
			Args:  &module.File{Path: "/tmp/w/f", Data: []byte("new\n"), Owner: "admin", Mode: "0640", Validation: new(`[ "$(stat -c '%U %G %a' /tmp/w/f)" = "admin root 640" ] && grep -qx new /tmp/w/f`)},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"owner admin, group root, mode 0640"}, Old: new("")},
			After: `[ "$(cat /tmp/w/f)" = new ]` + alone,
		},
		{
			Name:         "validate fails and the symbolic link comes back",
			Setup:        `ln -s /etc/hostname /tmp/w/f`,
			Args:         &module.File{Path: "/tmp/w/f", Data: []byte("new\n"), Validation: new("test -e /tmp/w/valid")},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"replace the symbolic link to /etc/hostname", attrs}, Old: new("")},
			WantApplyErr: "validate: test -e /tmp/w/valid: exit status 1",
			Fix:          "touch /tmp/w/valid",
			After:        `[ "$(readlink /tmp/w/f)" = /etc/hostname ]` + alone,
		},
	}
}

func linkCases(alone string) []vmtest.Case {
	return []vmtest.Case{
		{
			Name:  "validate passes",
			Setup: `ln -s /a /tmp/w/f`,
			Args:  &module.Link{Path: "/tmp/w/f", Target: new("/b"), Validation: new(`[ "$(readlink /tmp/w/f)" = /b ]`)},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"target /a → /b"}},
			After: `[ "$(readlink /tmp/w/f)" = /b ]` + alone,
		},
		{
			Name:         "validate fails and the old target stays",
			Setup:        `ln -s /a /tmp/w/f`,
			Args:         &module.Link{Path: "/tmp/w/f", Target: new("/b"), Validation: new("test -e /tmp/w/valid")},
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"target /a → /b"}},
			WantApplyErr: "validate: test -e /tmp/w/valid: exit status 1",
			Fix:          "touch /tmp/w/valid",
			After:        `[ "$(readlink /tmp/w/f)" = /a ]` + alone,
		},
		{
			Name:         "validate fails on a create",
			Args:         &module.Link{Path: "/tmp/w/new/f", Target: new("/b"), Validation: new("test -e /tmp/w/valid")},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create directory /tmp/w/new (owner root, group root, mode 0755)", "target /b"}},
			WantApplyErr: "validate: test -e /tmp/w/valid: exit status 1",
			Fix:          "touch /tmp/w/valid",
			After:        `[ -z "$(ls -A /tmp/w)" ]`,
		},
	}
}
