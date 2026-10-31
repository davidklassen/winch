package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// fakeKey returns an authorized_keys line with a blob of type ssh-ed25519
// whose data is the byte b, repeated.
func fakeKey(b byte, comment string) string {
	blob := binary.BigEndian.AppendUint32(nil, 11)
	blob = append(blob, "ssh-ed25519"...)
	blob = binary.BigEndian.AppendUint32(blob, 32)
	blob = append(blob, strings.Repeat(string(b), 32)...)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + comment
}

// keyLine is the plan form of an authorized_keys line without options.
func keyLine(line string) string {
	f := strings.Fields(line)
	blob, _ := base64.StdEncoding.DecodeString(f[1])
	sum := sha256.Sum256(blob)
	return strings.Join(append([]string{f[0], "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])}, f[2:]...), " ")
}

// Fake crypt hashes: the module only compares them.
const (
	hash1 = "$6$wtsalt1$fakehash1"
	hash2 = "$6$wtsalt2$fakehash2"
)

func keys(k ...string) *[]string {
	if k == nil {
		k = []string{}
	}
	return &k
}

// spec: Modules/user and group
func TestUserModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "user")
	reset := `chattr -ia /etc/passwd /etc/shadow /etc/group /etc/gshadow
systemctl stop wt-sleep 2>/dev/null || true
for u in wtalice wtbob wtsvc Debian-wt; do pkill -9 -u $u; userdel $u 2>/dev/null; done
sed -i '/^wtbob:/d' /etc/passwd /etc/shadow
sed -i 's|:/home/admin/:|:/home/admin:|' /etc/passwd
for g in wtalice wtbob wtsvc wtgrp wtnew wtother Debian-wt; do groupdel $g 2>/dev/null; done
gpasswd -d admin wtalice 2>/dev/null
gpasswd -d admin sudo 2>/dev/null
chattr -R -ia /home/wtalice 2>/dev/null
rm -rf /home/wtalice /home/wtbob /home/Debian-wt /srv/w /var/lib/wtsvc /opt/wt /root/.ssh /etc/ssh/sshd_config.d/wt.conf
sed -i '/ one$/d' /home/admin/.ssh/authorized_keys
true`
	k1, k2, k3 := fakeKey('1', "one"), fakeKey('2', "two"), fakeKey('3', "three")
	admin := strings.TrimSpace(vmtest.PublicKey)
	create := func(changes ...string) module.Result {
		return module.Result{Status: module.Change, Action: module.Create, Changes: changes}
	}
	change := func(changes ...string) module.Result {
		return module.Result{Status: module.Change, Action: module.Modify, Changes: changes}
	}
	addK1 := change("create directory /home/wtalice/.ssh (owner wtalice, group wtalice, mode 0700)",
		"create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)", "add key "+keyLine(k1))
	vmtest.RunCases(t, vm, "user", reset, []vmtest.Case{
		{
			Name:      "create with defaults",
			Args:      &module.User{Name: "wtalice"},
			Want:      create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/sh"),
			Unchanged: `! getent passwd wtalice && [ ! -e /home/wtalice ]`,
			After:     `[ "$(getent passwd wtalice | cut -d: -f6,7)" = /home/wtalice:/bin/sh ] && [ "$(id -gn wtalice)" = wtalice ] && [ "$(stat -c '%U %G %a' /home/wtalice)" = "wtalice wtalice 700" ] && [ -f /home/wtalice/.profile ]`,
		},
		{
			Name:  "create with every value",
			Setup: `groupadd -g 2100 wtgrp`,
			Args:  &module.User{Name: "wtbob", UID: "2100", Group: "wtgrp", Home: "/srv/w/a/bob", Shell: "/bin/bash"},
			Want: create("uid 2100", "group wtgrp",
				"create directory /srv/w (owner root, group root, mode 0755)", "create directory /srv/w/a (owner root, group root, mode 0755)",
				"home /srv/w/a/bob (owner wtbob, group wtgrp, mode 0700, files from /etc/skel)", "shell /bin/bash"),
			After: `[ "$(getent passwd wtbob)" = "wtbob:x:2100:2100::/srv/w/a/bob:/bin/bash" ] && [ "$(stat -c '%U %G %a' /srv/w /srv/w/a/bob)" = "root root 755
wtbob wtgrp 700" ]`,
		},
		{
			Name:  "a system user without home",
			Args:  &module.User{Name: "wtsvc", System: true},
			Want:  create("group wtsvc (new)", "system user", "home /nonexistent (not created)", "shell /usr/sbin/nologin"),
			After: `[ "$(getent passwd wtsvc | cut -d: -f6,7)" = /nonexistent:/usr/sbin/nologin ] && [ "$(id -u wtsvc)" -lt 1000 ] && [ ! -e /nonexistent ]`,
		},
		{
			Name:  "a system user with home",
			Args:  &module.User{Name: "wtsvc", System: true, Home: "/var/lib/wtsvc"},
			Want:  create("group wtsvc (new)", "system user", "home /var/lib/wtsvc (owner wtsvc, group wtsvc, mode 0700)", "shell /usr/sbin/nologin"),
			After: `[ "$(stat -c '%U %G %a' /var/lib/wtsvc)" = "wtsvc wtsvc 700" ] && [ -z "$(ls -A /var/lib/wtsvc)" ]`,
		},
		{
			Name:  "a home that is a link",
			Setup: `mkdir -p /srv/w/real && ln -s real /srv/w/link`,
			Args:  &module.User{Name: "wtalice", Home: "/srv/w/link"},
			Want:  create("group wtalice (new)", "home /srv/w/link exists (owner root, group root, mode 0755)", "shell /bin/sh"),
		},
		{
			Name:  "an empty shell field is /bin/sh",
			Setup: `useradd -m -s /bin/bash wtalice && usermod -s '' wtalice && [ -z "$(getent passwd wtalice | cut -d: -f7)" ]`,
			Args:  &module.User{Name: "wtalice", Shell: "/bin/sh"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a uid that the user shares with another user",
			Setup: `useradd -u 2400 wtbob && useradd -o -u 2400 -m wtalice`,
			Args:  &module.User{Name: "wtalice", UID: "2400"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a uid with a leading zero",
			Setup: `useradd -u 2400 -m wtalice`,
			Args:  &module.User{Name: "wtalice", UID: "02400"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "the uid of the login user",
			Args:    &module.User{Name: "admin", UID: "2999"},
			WantErr: "admin is the login user of this session; log in as another user to change its uid",
		},
		{
			Name:    "the shell of the login user",
			Args:    &module.User{Name: "admin", Shell: "/usr/sbin/nologin"},
			WantErr: "admin is the login user of this session; log in as another user to change its shell",
		},
		{
			Name:    "the home of the login user",
			Args:    &module.User{Name: "admin", Home: "/srv/admin"},
			WantErr: "admin is the login user of this session; log in as another user to change its home",
		},
		{
			Name:  "a group with the user's name exists",
			Setup: `groupadd -g 2150 wtalice`,
			Args:  &module.User{Name: "wtalice"},
			Want:  create("group wtalice", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/sh"),
			After: `[ "$(id -g wtalice)" = 2150 ]`,
		},
		{
			Name:  "the home exists",
			Setup: `mkdir -p /srv/w/home`,
			Args:  &module.User{Name: "wtalice", Home: "/srv/w/home"},
			Want:  create("group wtalice (new)", "home /srv/w/home exists (owner root, group root, mode 0755)", "shell /bin/sh"),
			After: `[ "$(stat -c '%U %G %a' /srv/w/home)" = "root root 755" ]`,
		},
		{
			Name:         "a group that does not exist yet",
			Args:         &module.User{Name: "wtalice", Group: "wtnew"},
			Want:         create("group wtnew (does not exist yet)", "home /home/wtalice (owner wtalice, group wtnew, mode 0700, files from /etc/skel)", "shell /bin/sh"),
			WantApplyErr: "group 'wtnew' does not exist",
			Fix:          "groupadd wtnew",
			After:        `! getent passwd wtalice`,
		},
		{
			Name:  "a shell that does not exist yet",
			Args:  &module.User{Name: "wtalice", Shell: "/opt/wt/sh"},
			Want:  create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /opt/wt/sh (does not exist yet)"),
			After: `[ "$(getent passwd wtalice | cut -d: -f7)" = /opt/wt/sh ]`,
		},
		{
			Name:    "a shell that is not an executable file",
			Args:    &module.User{Name: "wtalice", Shell: "/etc/passwd"},
			WantErr: "shell /etc/passwd is not an executable file",
		},
		{
			Name:    "a change to a shell that is a directory",
			Setup:   `useradd -m -U wtalice`,
			Args:    &module.User{Name: "wtalice", Shell: "/usr/bin"},
			WantErr: "shell /usr/bin is not an executable file",
		},
		{
			Name:         "a uid change with a running process",
			Setup:        `useradd -m -U -u 2200 wtalice && systemd-run --uid=wtalice --unit=wt-sleep sleep 600 && timeout 10 sh -c 'until pgrep -x -u wtalice sleep; do sleep 0.1; done'`,
			Args:         &module.User{Name: "wtalice", UID: "2300"},
			Want:         change("uid 2200 → 2300, also of the files in the home; other files keep the old uid", "processes of wtalice run (sleep); usermod fails while they run"),
			WantApplyErr: "usermod: user wtalice is currently used by process",
			Fix:          "systemctl stop wt-sleep",
			After:        `[ "$(id -u wtalice)" = 2200 ]`,
		},
		{
			Name:         "a home change with a running process",
			Setup:        `useradd -m -U wtalice && systemd-run --uid=wtalice --unit=wt-sleep sleep 600 && timeout 10 sh -c 'until pgrep -x -u wtalice sleep; do sleep 0.1; done'`,
			Args:         &module.User{Name: "wtalice", Home: "/srv/w/alice"},
			Want:         change("home /home/wtalice → /srv/w/alice", "create directory /srv/w (owner root, group root, mode 0755)", "create home /srv/w/alice (owner wtalice, group wtalice, mode 0700)", "processes of wtalice run (sleep); usermod fails while they run"),
			WantApplyErr: "usermod: user wtalice is currently used by process",
			Fix:          "systemctl stop wt-sleep",
			After:        `[ "$(getent passwd wtalice | cut -d: -f6)" = /home/wtalice ]`,
		},
		{
			Name:      "an immutable key file",
			Setup:     `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && echo '` + k1 + `' | install -o wtalice -g wtalice -m 600 /dev/stdin /home/wtalice/.ssh/authorized_keys && chattr +i /home/wtalice/.ssh/authorized_keys`,
			Args:      &module.User{Name: "wtalice", AuthorizedKeys: keys(k2)},
			WantErr:   "/home/wtalice/.ssh/authorized_keys is immutable; chattr -i changes it",
			Unchanged: `[ "$(cat /home/wtalice/.ssh/authorized_keys)" = "` + k1 + `" ]`,
		},
		{
			Name:    "an immutable key file with another mode",
			Setup:   `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && echo '` + k1 + `' | install -o wtalice -g wtalice -m 644 /dev/stdin /home/wtalice/.ssh/authorized_keys && chattr +i /home/wtalice/.ssh/authorized_keys`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "/home/wtalice/.ssh/authorized_keys is immutable; chattr -i changes it",
		},
		{
			Name:    "an append-only ~/.ssh",
			Setup:   `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && chattr +a /home/wtalice/.ssh`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "/home/wtalice/.ssh is append-only; chattr -a changes it",
		},
		{
			Name:    "an immutable ~/.ssh with another mode",
			Setup:   `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 755 /home/wtalice/.ssh && echo '` + k1 + `' | install -o wtalice -g wtalice -m 600 /dev/stdin /home/wtalice/.ssh/authorized_keys && chattr +i /home/wtalice/.ssh`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "/home/wtalice/.ssh is immutable; chattr -i changes it",
		},
		{
			Name:  "immutable keys that are as the step declares",
			Setup: `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && echo '` + k1 + `' | install -o wtalice -g wtalice -m 600 /dev/stdin /home/wtalice/.ssh/authorized_keys && chattr +i /home/wtalice/.ssh/authorized_keys /home/wtalice/.ssh`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "defaults do not change an existing user",
			Setup: `useradd -M -d /home/wtalice -s /bin/bash -g users wtalice && mkdir /home/wtalice`,
			Args:  &module.User{Name: "wtalice"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name: "keys of root change only the keys",
			Args: &module.User{Name: "root", AuthorizedKeys: keys(k1)},
			Want: change("create directory /root/.ssh (owner root, group root, mode 0700)", "create file /root/.ssh/authorized_keys (owner root, group root, mode 0600)", "add key "+keyLine(k1)),
			After: `[ "$(getent passwd root)" = "root:x:0:0:root:/root:/bin/bash" ] && [ "$(stat -c '%U %G %a' /root/.ssh /root/.ssh/authorized_keys)" = "root root 700
root root 600" ] && [ "$(cat /root/.ssh/authorized_keys)" = "` + k1 + `" ]`,
		},
		{
			Name:  "keys of the login user",
			Args:  &module.User{Name: "admin", AuthorizedKeys: keys(admin, k1)},
			Want:  change("changes the keys of the login user admin", "add key "+keyLine(k1)),
			After: `printf '%s\n%s\n' '` + admin + `' '` + k1 + `' | cmp - /home/admin/.ssh/authorized_keys`,
		},
		{
			Name:  "change uid, group, home, and shell",
			Setup: `groupadd wtgrp && useradd -m -U -u 2200 -s /bin/sh wtalice`,
			Args:  &module.User{Name: "wtalice", UID: "2300", Group: "wtgrp", Home: "/srv/w/alice", Shell: "/bin/bash"},
			Want: change("uid 2200 → 2300, also of the files in the home; other files keep the old uid", "group wtalice → wtgrp, also of the files in the home", "home /home/wtalice → /srv/w/alice",
				"create directory /srv/w (owner root, group root, mode 0755)", "create home /srv/w/alice (owner wtalice, group wtgrp, mode 0700)",
				"shell /bin/sh → /bin/bash"),
			After:     `[ "$(getent passwd wtalice | cut -d: -f3,6,7)" = "2300:/srv/w/alice:/bin/bash" ] && [ "$(id -gn wtalice)" = wtgrp ] && [ "$(stat -c '%U %G %a' /srv/w/alice)" = "wtalice wtgrp 700" ]`,
			WantState: module.State{MovedUsers: []string{"wtalice"}},
		},
		{
			Name:    "a uid of another user",
			Setup:   `useradd -u 2400 wtbob`,
			Args:    &module.User{Name: "wtalice", UID: "2400"},
			WantErr: "uid 2400 belongs to user wtbob",
		},
		{
			Name:  "an existing user without a home",
			Setup: `useradd -M -d /home/wtalice -U wtalice`,
			Args:  &module.User{Name: "wtalice"},
			Want:  change("create home /home/wtalice (owner wtalice, group wtalice, mode 0700)"),
			After: `[ "$(stat -c '%U %G %a' /home/wtalice)" = "wtalice wtalice 700" ]`,
		},
		{
			Name:  "create with groups, password, and comment",
			Setup: `groupadd wtgrp && groupadd wtother`,
			Args:  &module.User{Name: "wtalice", Groups: &[]string{"wtother", "wtgrp"}, Password: hash1, Comment: "Alice Smith"},
			Want: create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/sh",
				"groups wtother, wtgrp", `comment "Alice Smith"`, "set password"),
			After: `[ "$(id -nG wtalice)" = "wtalice wtgrp wtother" ] && [ "$(getent passwd wtalice | cut -d: -f5)" = "Alice Smith" ] && [ "$(getent shadow wtalice | cut -d: -f2)" = '` + hash1 + `' ]`,
		},
		{
			Name:         "a new user in a group that does not exist yet",
			Setup:        `groupadd wtgrp`,
			Args:         &module.User{Name: "wtalice", Groups: &[]string{"wtgrp", "wtnew"}},
			Want:         create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/sh", "groups wtgrp, wtnew (does not exist yet)"),
			WantApplyErr: "group 'wtnew' does not exist",
			Fix:          "groupadd wtnew",
			After:        `! getent passwd wtalice`,
		},
		{
			Name:  "change groups",
			Setup: `groupadd wtgrp && groupadd wtother && groupadd wtnew && useradd -m -U -G wtgrp,wtother wtalice`,
			Args:  &module.User{Name: "wtalice", Groups: &[]string{"wtother", "wtnew"}},
			Want:  change("add to group wtnew", "remove from group wtgrp"),
			After: `[ "$(id -nG wtalice)" = "wtalice wtother wtnew" ]`,
		},
		{
			Name:  "no groups",
			Setup: `groupadd wtgrp && useradd -m -U -G wtgrp wtalice`,
			Args:  &module.User{Name: "wtalice", Groups: &[]string{}},
			Want:  change("remove from group wtgrp"),
			After: `[ "$(id -nG wtalice)" = wtalice ]`,
		},
		{
			Name:  "groups in another order",
			Setup: `groupadd wtgrp && groupadd wtother && useradd -m -U -G wtgrp,wtother wtalice`,
			Args:  &module.User{Name: "wtalice", Groups: &[]string{"wtother", "wtgrp"}},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "add_groups keeps the other groups",
			Setup: `groupadd wtgrp && useradd -m -U -G adm wtalice`,
			Args:  &module.User{Name: "wtalice", AddGroups: &[]string{"wtgrp"}},
			Want:  change("add to group wtgrp"),
			After: `[ "$(id -nG wtalice)" = "wtalice adm wtgrp" ]`,
		},
		{
			Name:  "create with a shell and add_groups",
			Setup: `groupadd wtgrp`,
			Args:  &module.User{Name: "wtalice", Shell: "/bin/bash", AddGroups: &[]string{"wtgrp"}},
			Want:  create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/bash", "groups wtgrp"),
			After: `[ "$(id -nG wtalice)" = "wtalice wtgrp" ]`,
		},
		{
			Name:         "add_groups on a missing user",
			Setup:        `groupadd wtgrp`,
			Args:         &module.User{Name: "wtalice", AddGroups: &[]string{"wtgrp"}},
			Want:         change("user does not exist yet", "add to group wtgrp"),
			WantApplyErr: "user wtalice does not exist",
			Fix:          "useradd -m -U -G adm wtalice",
			After:        `! getent passwd wtalice`,
		},
		{
			Name:  "add_groups to the login user",
			Setup: `groupadd wtgrp && gpasswd -a admin sudo`,
			Args:  &module.User{Name: "admin", AddGroups: &[]string{"wtgrp"}},
			Want:  change("changes the groups of the login user admin", "add to group wtgrp"),
			After: `[ "$(id -nG admin)" = "admin sudo wtgrp" ]`,
		},
		{
			Name:  "add a group to the login user",
			Setup: `groupadd wtgrp`,
			Args:  &module.User{Name: "admin", Groups: &[]string{"admin", "wtgrp"}},
			Want:  change("changes the groups of the login user admin", "add to group wtgrp"),
			After: `[ "$(id -nG admin)" = "admin wtgrp" ]`,
		},
		{
			Name:      "the primary group of the login user",
			Setup:     `groupadd wtgrp`,
			Args:      &module.User{Name: "admin", Group: "wtgrp"},
			WantErr:   "admin is the login user of this session; log in as another user to change its group",
			Unchanged: `[ "$(id -gn admin)" = admin ]`,
		},
		{
			Name:      "remove a group from the login user",
			Setup:     `gpasswd -a admin sudo`,
			Args:      &module.User{Name: "admin", Groups: &[]string{"admin"}},
			WantErr:   "admin is the login user of this session; log in as another user to change its groups",
			Unchanged: `[ "$(id -nG admin)" = "admin sudo" ]`,
		},
		{
			Name:         "a group that does not exist yet in groups",
			Setup:        `useradd -m -U wtalice`,
			Args:         &module.User{Name: "wtalice", Groups: &[]string{"wtnew"}},
			Want:         change("add to group wtnew (does not exist yet)"),
			WantApplyErr: "group 'wtnew' does not exist",
			Fix:          "groupadd wtnew",
			After:        `[ "$(id -nG wtalice)" = wtalice ]`,
		},
		{
			Name:  "change groups, comment, and password",
			Setup: `groupadd wtgrp && useradd -m -U -c Alice -p '` + hash1 + `' wtalice`,
			Args:  &module.User{Name: "wtalice", Groups: &[]string{"wtgrp"}, Comment: "Alice Smith", Password: hash2},
			Want:  change("add to group wtgrp", `comment "Alice" → "Alice Smith"`, "change password"),
			After: `[ "$(id -nG wtalice)" = "wtalice wtgrp" ] && [ "$(getent passwd wtalice | cut -d: -f5)" = "Alice Smith" ] && [ "$(getent shadow wtalice | cut -d: -f2)" = '` + hash2 + `' ]`,
		},
		{
			Name:    "a password that is not a crypt hash",
			Setup:   `useradd -m -U wtalice`,
			Args:    &module.User{Name: "wtalice", Password: "hunter2"},
			WantErr: "password is not a crypt hash, such as one from mkpasswd -m yescrypt, or \"!\" or \"*\"",
		},
		{
			Name:  "change password",
			Setup: `useradd -m -U -p '` + hash1 + `' wtalice`,
			Args:  &module.User{Name: "wtalice", Password: hash2},
			Want:  change("change password"),
			After: `[ "$(getent shadow wtalice | cut -d: -f2)" = '` + hash2 + `' ]`,
		},
		{
			Name:  "the same password",
			Setup: `useradd -m -U -p '` + hash1 + `' wtalice`,
			Args:  &module.User{Name: "wtalice", Password: hash1},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "lock the password",
			Setup: `useradd -m -U -p '` + hash1 + `' wtalice`,
			Args:  &module.User{Name: "wtalice", Password: "!" + hash1},
			Want:  change("lock the password"),
			After: `[ "$(getent shadow wtalice | cut -d: -f2)" = '!` + hash1 + `' ]`,
		},
		{
			Name:  "unlock the password",
			Setup: `useradd -m -U -p '!` + hash1 + `' wtalice`,
			Args:  &module.User{Name: "wtalice", Password: hash1},
			Want:  change("unlock the password"),
			After: `[ "$(getent shadow wtalice | cut -d: -f2)" = '` + hash1 + `' ]`,
		},
		{
			Name:  "a locked new password",
			Setup: `useradd -m -U -p '` + hash1 + `' wtalice`,
			Args:  &module.User{Name: "wtalice", Password: "!" + hash2},
			Want:  change("change password"),
			After: `[ "$(getent shadow wtalice | cut -d: -f2)" = '!` + hash2 + `' ]`,
		},
		{
			Name:  "a password of !",
			Setup: `useradd -m -U -p '` + hash1 + `' wtalice`,
			Args:  &module.User{Name: "wtalice", Password: "!"},
			Want:  change("lock the password"),
			After: `[ "$(getent shadow wtalice | cut -d: -f2)" = '!' ]`,
		},
		{
			Name:  "a password of * for a new user",
			Args:  &module.User{Name: "wtalice", Password: "*"},
			Want:  create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/sh", "set password"),
			After: `[ "$(getent shadow wtalice | cut -d: -f2)" = '*' ]`,
		},
		{
			Name:  "a home with a trailing slash in /etc/passwd",
			Setup: `useradd -m -U wtalice && sed -i 's|:/home/wtalice:|:/home/wtalice/:|' /etc/passwd`,
			Args:  &module.User{Name: "wtalice", Home: "/home/wtalice"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "the home of the login user with a trailing slash in /etc/passwd",
			Setup: `sed -i 's|:/home/admin:|:/home/admin/:|' /etc/passwd`,
			Args:  &module.User{Name: "admin", Home: "/home/admin"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a user with a Debian name that exists",
			Setup: `groupadd wtgrp && useradd -m -U Debian-wt`,
			Args:  &module.User{Name: "Debian-wt", Groups: &[]string{"wtgrp"}},
			Want:  change("add to group wtgrp"),
			After: `[ "$(id -nG Debian-wt)" = "Debian-wt wtgrp" ]`,
		},
		{
			Name:      "a new user with a Debian name",
			Args:      &module.User{Name: "Debian-wt"},
			WantErr:   `user Debian-wt does not exist, and winch creates only names with lower-case letters, digits, "_", and "-" that start with a letter or "_"`,
			Unchanged: `! getent passwd Debian-wt`,
		},
		{
			Name:  "create with a UTF-8 comment",
			Args:  &module.User{Name: "wtalice", Comment: "José Núñez"},
			Want:  create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/sh", `comment "José Núñez"`),
			After: `[ "$(getent passwd wtalice | cut -d: -f5)" = "José Núñez" ]`,
		},
		{
			Name:  "change a UTF-8 comment",
			Setup: `useradd -m -U -c 'José Nunez' wtalice`,
			Args:  &module.User{Name: "wtalice", Comment: "José Núñez"},
			Want:  change(`comment "José Nunez" → "José Núñez"`),
			After: `[ "$(getent passwd wtalice | cut -d: -f5)" = "José Núñez" ]`,
		},
		{
			Name:  "change comment",
			Setup: `useradd -m -U -c Alice wtalice`,
			Args:  &module.User{Name: "wtalice", Comment: "Alice Smith"},
			Want:  change(`comment "Alice" → "Alice Smith"`),
			After: `[ "$(getent passwd wtalice | cut -d: -f5)" = "Alice Smith" ]`,
		},
		{
			Name:  "a new user with a password and UsePAM no",
			Setup: `echo 'UsePAM no' > /etc/ssh/sshd_config.d/wt.conf`,
			Args:  &module.User{Name: "wtalice", Password: hash1, AuthorizedKeys: keys(k1)},
			Want: create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/sh", "set password",
				"create directory /home/wtalice/.ssh (owner wtalice, group wtalice, mode 0700)",
				"create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)",
				"add key "+keyLine(k1)),
		},
		{
			Name:  "a password from the step for a locked password with UsePAM no",
			Setup: `echo 'UsePAM no' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && usermod -p '!x' wtalice`,
			Args:  &module.User{Name: "wtalice", Password: hash1, AuthorizedKeys: keys(k1)},
			Want: change("change password",
				"create directory /home/wtalice/.ssh (owner wtalice, group wtalice, mode 0700)",
				"create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)",
				"add key "+keyLine(k1)),
		},
		{
			Name:    "a locked password from the step with UsePAM no",
			Setup:   `echo 'UsePAM no' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U -p '` + hash1 + `' wtalice`,
			Args:    &module.User{Name: "wtalice", Password: "!" + hash1, AuthorizedKeys: keys(k1)},
			WantErr: `with UsePAM no, sshd refuses the login of wtalice: its password is locked with "!"`,
		},
		{
			Name: "keys of a new user",
			Args: &module.User{Name: "wtalice", AuthorizedKeys: keys(k1, k2)},
			Want: create("group wtalice (new)", "home /home/wtalice (owner wtalice, group wtalice, mode 0700, files from /etc/skel)", "shell /bin/sh",
				"create directory /home/wtalice/.ssh (owner wtalice, group wtalice, mode 0700)",
				"create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)",
				"add key "+keyLine(k1), "add key "+keyLine(k2)),
			After: `[ "$(stat -c '%U %G %a' /home/wtalice/.ssh /home/wtalice/.ssh/authorized_keys)" = "wtalice wtalice 700
wtalice wtalice 600" ] && printf '%s\n%s\n' '` + k1 + `' '` + k2 + `' | cmp - /home/wtalice/.ssh/authorized_keys`,
		},
		{
			Name:  "keys change",
			Setup: `useradd -m -U wtalice && mkdir -m 755 /home/wtalice/.ssh && printf '%s\n%s\n' '` + k2 + `' '` + k1 + `' > /home/wtalice/.ssh/authorized_keys && chmod 644 /home/wtalice/.ssh/authorized_keys`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1, k3)},
			Want: change("/home/wtalice/.ssh: owner root → wtalice", "/home/wtalice/.ssh: group root → wtalice", "/home/wtalice/.ssh: mode 0755 → 0700",
				"/home/wtalice/.ssh/authorized_keys: owner root → wtalice", "/home/wtalice/.ssh/authorized_keys: group root → wtalice", "/home/wtalice/.ssh/authorized_keys: mode 0644 → 0600",
				"add key "+keyLine(k3), "remove key "+keyLine(k2)),
			Unchanged: `[ "$(stat -c '%U %a' /home/wtalice/.ssh)" = "root 755" ]`,
			After:     `printf '%s\n%s\n' '` + k1 + `' '` + k3 + `' | cmp - /home/wtalice/.ssh/authorized_keys`,
		},
		{
			Name:  "keys after a change of home",
			Setup: `useradd -m -U wtalice`,
			Args:  &module.User{Name: "wtalice", Home: "/srv/w/alice", AuthorizedKeys: keys(k1)},
			Want: change("home /home/wtalice → /srv/w/alice",
				"create directory /srv/w (owner root, group root, mode 0755)", "create home /srv/w/alice (owner wtalice, group wtalice, mode 0700)",
				"create directory /srv/w/alice/.ssh (owner wtalice, group wtalice, mode 0700)",
				"create file /srv/w/alice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)",
				"add key "+keyLine(k1)),
			After: `[ "$(cat /srv/w/alice/.ssh/authorized_keys)" = "` + k1 + `" ] && [ ! -e /home/wtalice/.ssh ]`,
		},
		{
			Name:  "a key file without the last newline",
			Setup: `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && printf '%s' '` + k1 + `' | install -o wtalice -g wtalice -m 600 /dev/stdin /home/wtalice/.ssh/authorized_keys`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  change("rewrite /home/wtalice/.ssh/authorized_keys"),
		},
		{
			Name:  "a key file larger than 1 MiB",
			Setup: `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && install -o wtalice -g wtalice -m 600 /dev/null /home/wtalice/.ssh/authorized_keys && truncate -s 64G /home/wtalice/.ssh/authorized_keys`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  change("rewrite /home/wtalice/.ssh/authorized_keys (larger than 1 MiB)"),
		},
		{
			Name:  "a key file that is a link",
			Setup: `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && ln -s /etc/hostname /home/wtalice/.ssh/authorized_keys && cp /etc/hostname /tmp/hostname`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  change("replace the symbolic link /home/wtalice/.ssh/authorized_keys to /etc/hostname", "create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)", "add key "+keyLine(k1)),
			After: `cmp /etc/hostname /tmp/hostname && [ -f /home/wtalice/.ssh/authorized_keys ] && [ ! -L /home/wtalice/.ssh/authorized_keys ]`,
		},
		{
			Name:  "a key file that is a link with a newline in its target",
			Setup: `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && ln -s "$(printf 'a\nb')" /home/wtalice/.ssh/authorized_keys`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  change("replace the symbolic link /home/wtalice/.ssh/authorized_keys to a?b", "create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)", "add key "+keyLine(k1)),
			After: `[ -f /home/wtalice/.ssh/authorized_keys ] && [ ! -L /home/wtalice/.ssh/authorized_keys ]`,
		},
		{
			Name:    "a key file that is a directory",
			Setup:   `useradd -m -U wtalice && mkdir -p /home/wtalice/.ssh/authorized_keys`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "/home/wtalice/.ssh/authorized_keys is a directory, not a file",
		},
		{
			Name:    "keys of a user without home",
			Args:    &module.User{Name: "nobody", AuthorizedKeys: keys(k1)},
			WantErr: "user nobody has no home (/nonexistent); authorized_keys needs one; set home",
		},
		{
			Name:    "keys in /",
			Setup:   `useradd -M -d / wtalice`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "the home of wtalice is /; authorized_keys needs another home; set home",
		},
		{
			Name:  "keys in another order",
			Setup: `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && printf '%s\n%s\n' '` + k2 + `' '` + k1 + `' | install -o wtalice -g wtalice -m 600 /dev/stdin /home/wtalice/.ssh/authorized_keys`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1, k2)},
			Want:  change("put the keys in order"),
		},
		{
			Name:  "no keys",
			Setup: `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && echo '` + k1 + `' | install -o wtalice -g wtalice -m 600 /dev/stdin /home/wtalice/.ssh/authorized_keys`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys()},
			Want:  change("remove key " + keyLine(k1)),
			After: `[ ! -s /home/wtalice/.ssh/authorized_keys ]`,
		},
		{
			Name:      "a link ~/.ssh in the user's home",
			Setup:     `useradd -m -U wtalice && ln -s /root/.ssh /home/wtalice/.ssh`,
			Args:      &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr:   "/home/wtalice/.ssh is a symbolic link in /home/wtalice, which a user other than root can write",
			Unchanged: `[ ! -e /root/.ssh ]`,
		},
		{
			Name:    "a home that is a file",
			Setup:   `mkdir -p /srv/w && touch /srv/w/f`,
			Args:    &module.User{Name: "wtalice", Home: "/srv/w/f"},
			WantErr: "/srv/w/f is a file, not a directory",
		},
		{
			Name:    "sshd reads another key file",
			Setup:   `echo 'AuthorizedKeysFile /etc/ssh/keys/%u' > /etc/ssh/sshd_config.d/wt.conf`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "sshd reads the keys of wtalice from /etc/ssh/keys/%u (AuthorizedKeysFile), not from ~/.ssh/authorized_keys",
		},
		{
			Name:    "a home of another user with StrictModes",
			Setup:   `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && chown admin /home/wtalice`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "with StrictModes yes, sshd ignores the keys of wtalice: admin owns /home/wtalice, not root or wtalice",
		},
		{
			Name:    "a home that the group can write with StrictModes",
			Setup:   `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && chgrp users /home/wtalice && chmod 775 /home/wtalice`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "with StrictModes yes, sshd ignores the keys of wtalice: the group users can write /home/wtalice (mode 0775) and is not the own group of wtalice alone",
		},
		{
			Name:  "a home that the user's private group can write with StrictModes",
			Setup: `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && chmod 775 /home/wtalice`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  addK1,
		},
		{
			Name:  "a home that the user's new private group can write with StrictModes",
			Setup: `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && groupadd wtnew && useradd -m -U wtalice && chmod 775 /home/wtalice`,
			Args:  &module.User{Name: "wtalice", Group: "wtnew", AuthorizedKeys: keys(k1)},
			Want: change("group wtalice → wtnew, also of the files in the home",
				"create directory /home/wtalice/.ssh (owner wtalice, group wtnew, mode 0700)",
				"create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtnew, mode 0600)", "add key "+keyLine(k1)),
			After:     `[ "$(stat -c '%G %a' /home/wtalice)" = "wtnew 775" ]`,
			WantState: module.State{MovedUsers: []string{"wtalice"}},
		},
		{
			Name:    "a root home that the user's old private group can write with StrictModes",
			Setup:   `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && groupadd wtnew && useradd -m -U wtalice && chown root /home/wtalice && chmod 775 /home/wtalice`,
			Args:    &module.User{Name: "wtalice", Group: "wtnew", AuthorizedKeys: keys(k1)},
			WantErr: "with StrictModes yes, sshd ignores the keys of wtalice: the group wtalice can write /home/wtalice (mode 0775) and is not the own group of wtalice alone",
		},
		{
			Name:    "a home that a private group with another member can write with StrictModes",
			Setup:   `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && chmod 775 /home/wtalice && usermod -aG wtalice admin`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "with StrictModes yes, sshd ignores the keys of wtalice: the group wtalice can write /home/wtalice (mode 0775) and is not the own group of wtalice alone",
		},
		{
			Name:    "an existing home of a new user with StrictModes",
			Setup:   `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && mkdir -p /srv/w/alice && chown admin /srv/w/alice`,
			Args:    &module.User{Name: "wtalice", Home: "/srv/w/alice", AuthorizedKeys: keys(k1)},
			WantErr: "with StrictModes yes, sshd ignores the keys of wtalice: admin owns /srv/w/alice, not root or wtalice",
		},
		{
			Name:    "a home that others can write with StrictModes",
			Setup:   `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && chmod 757 /home/wtalice`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "with StrictModes yes, sshd ignores the keys of wtalice: others can write /home/wtalice (mode 0757)",
		},
		{
			Name:  "a home of the old uid with StrictModes",
			Setup: `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U -u 2200 wtalice`,
			Args:  &module.User{Name: "wtalice", UID: "2300", AuthorizedKeys: keys(k1)},
			Want: change("uid 2200 → 2300, also of the files in the home; other files keep the old uid",
				"create directory /home/wtalice/.ssh (owner wtalice, group wtalice, mode 0700)",
				"create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)", "add key "+keyLine(k1)),
			After: `[ "$(stat -c %u /home/wtalice)" = 2300 ]`,
		},
		{
			Name:  "an existing home of the new uid with StrictModes",
			Setup: `echo 'StrictModes yes' > /etc/ssh/sshd_config.d/wt.conf && mkdir -p /srv/w/alice && chown 2300 /srv/w/alice`,
			Args:  &module.User{Name: "wtalice", UID: "2300", Home: "/srv/w/alice", AuthorizedKeys: keys(k1)},
			Want: create("uid 2300", "group wtalice (new)", "home /srv/w/alice exists (owner 2300, group root, mode 0755)", "shell /bin/sh",
				"create directory /srv/w/alice/.ssh (owner wtalice, group wtalice, mode 0700)",
				"create file /srv/w/alice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)", "add key "+keyLine(k1)),
		},
		{
			Name:  "a home that others can write without StrictModes",
			Setup: `echo 'StrictModes no' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && chmod 777 /home/wtalice`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  addK1,
		},
		{
			Name:    "a new user with UsePAM no",
			Setup:   `echo 'UsePAM no' > /etc/ssh/sshd_config.d/wt.conf`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: `with UsePAM no, sshd refuses the login of wtalice: its password is locked with "!"`,
		},
		{
			Name:    "a locked password with UsePAM no",
			Setup:   `echo 'UsePAM no' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && usermod -p '!x' wtalice`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: `with UsePAM no, sshd refuses the login of wtalice: its password is locked with "!"`,
		},
		{
			Name:  "a password without login with UsePAM no",
			Setup: `echo 'UsePAM no' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice && usermod -p '*' wtalice`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  addK1,
		},
		{
			Name:  "a Match Address block",
			Setup: `printf 'Match Address 10.9.9.9\n  PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  addK1,
		},
		{
			Name:  "a Match LocalPort block of another port",
			Setup: `printf 'Match LocalPort 2222\n  AuthorizedKeysFile /etc/ssh/keys/%%u\n' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  addK1,
		},
		{
			Name:  "a Match LocalPort block of a second Port of sshd",
			Setup: `printf 'Port 2222\nPort 22\nMatch LocalPort 2222\n  AuthorizedKeysFile /etc/ssh/keys/%%u\n' > /etc/ssh/sshd_config.d/wt.conf && useradd -m -U wtalice`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  addK1,
		},
		{
			// QEMU's user network connects from 10.0.2.2 to 10.0.2.15.
			Name:    "a Match LocalAddress block of the VM",
			Setup:   `printf 'Match LocalAddress 10.0.2.15\n  AuthorizedKeysFile /etc/ssh/keys/%%u\n' > /etc/ssh/sshd_config.d/wt.conf`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "sshd reads the keys of wtalice from /etc/ssh/keys/%u (AuthorizedKeysFile), not from ~/.ssh/authorized_keys",
		},
		{
			Name:    "a Match Address block of the controller",
			Setup:   `printf 'Match Address 10.0.2.2\n  AuthorizedKeysFile /etc/ssh/keys/%%u\n' > /etc/ssh/sshd_config.d/wt.conf`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "sshd reads the keys of wtalice from /etc/ssh/keys/%u (AuthorizedKeysFile), not from ~/.ssh/authorized_keys",
		},
		{
			Name:    "a Match LocalPort block of sshd's port",
			Setup:   `printf 'Match LocalPort 22\n  AuthorizedKeysFile /etc/ssh/keys/%%u\n' > /etc/ssh/sshd_config.d/wt.conf`,
			Args:    &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			WantErr: "sshd reads the keys of wtalice from /etc/ssh/keys/%u (AuthorizedKeysFile), not from ~/.ssh/authorized_keys",
		},
		{
			Name:      "absent",
			Setup:     `useradd -m -U wtalice`,
			Args:      &module.User{Name: "wtalice", Absent: true},
			WantState: module.State{RemovedUsers: []string{"wtalice"}},
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove group wtalice"}},
			Unchanged: `getent passwd wtalice`,
			After:     `! getent passwd wtalice && ! getent group wtalice && [ -d /home/wtalice ]`,
		},
		{
			Name:      "absent keeps a group with members",
			Setup:     `useradd -m -U wtalice && usermod -aG wtalice admin`,
			Args:      &module.User{Name: "wtalice", Absent: true},
			WantState: module.State{RemovedUsers: []string{"wtalice"}},
			Want:      module.Result{Status: module.Change, Action: module.Remove},
			After:     `! getent passwd wtalice && getent group wtalice`,
		},
		{
			Name:      "absent removes a group whose only member is the user",
			Setup:     `useradd -m -U wtalice && usermod -aG wtalice wtalice`,
			Args:      &module.User{Name: "wtalice", Absent: true},
			WantState: module.State{RemovedUsers: []string{"wtalice"}},
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove group wtalice"}},
			After:     `! getent group wtalice`,
		},
		{
			Name:      "absent keeps a group that is the primary group of another user",
			Setup:     `useradd -m -U wtalice && useradd -M -g wtalice wtbob`,
			Args:      &module.User{Name: "wtalice", Absent: true},
			WantState: module.State{RemovedUsers: []string{"wtalice"}},
			Want:      module.Result{Status: module.Change, Action: module.Remove},
			After:     `getent group wtalice`,
		},
		{
			Name:      "absent removes a group that is the primary group of a removed user",
			Setup:     `useradd -m -U wtalice && useradd -M -g wtalice wtbob`,
			State:     module.State{RemovedUsers: []string{"wtbob"}},
			Args:      &module.User{Name: "wtalice", Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove group wtalice"}},
			WantState: module.State{RemovedUsers: []string{"wtbob", "wtalice"}},
		},
		{
			Name:      "absent removes a group whose other member is a removed user",
			Setup:     `useradd -m -U wtalice && useradd -M -U -G wtalice wtbob`,
			State:     module.State{RemovedUsers: []string{"wtbob"}},
			Args:      &module.User{Name: "wtalice", Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove group wtalice"}},
			WantState: module.State{RemovedUsers: []string{"wtbob", "wtalice"}},
		},
		{
			Name: "absent of a missing user",
			Args: &module.User{Name: "wtalice", Absent: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:    "absent of the login user",
			Args:    &module.User{Name: "admin", Absent: true},
			WantErr: "admin is the login user of this session; log in as another user to remove it",
		},
		{
			Name:         "absent with a running process",
			Setup:        `useradd -U wtalice && systemd-run --uid=wtalice --unit=wt-sleep sleep 600 && timeout 10 sh -c 'until pgrep -x -u wtalice sleep; do sleep 0.1; done'`,
			Args:         &module.User{Name: "wtalice", Absent: true},
			WantState:    module.State{RemovedUsers: []string{"wtalice"}},
			Want:         module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove group wtalice", "processes of wtalice run (sleep); userdel fails while they run"}},
			WantApplyErr: "userdel: user wtalice is currently used by process",
			Fix:          "systemctl stop wt-sleep",
			After:        `getent passwd wtalice`,
		},
		{
			Name:      "create with an immutable /etc/passwd",
			Setup:     `chattr +i /etc/passwd`,
			Args:      &module.User{Name: "wtalice"},
			WantErr:   "/etc/passwd is immutable; chattr -i changes it",
			Unchanged: `! getent passwd wtalice`,
		},
		{
			Name:    "create with an append-only /etc/passwd",
			Setup:   `chattr +a /etc/passwd`,
			Args:    &module.User{Name: "wtalice"},
			WantErr: "/etc/passwd is append-only; chattr -a changes it",
		},
		{
			Name:    "create with an immutable /etc/shadow",
			Setup:   `chattr +i /etc/shadow`,
			Args:    &module.User{Name: "wtalice"},
			WantErr: "/etc/shadow is immutable; chattr -i changes it",
		},
		{
			Name:    "create with an immutable /etc/group",
			Setup:   `chattr +i /etc/group`,
			Args:    &module.User{Name: "wtalice"},
			WantErr: "/etc/group is immutable; chattr -i changes it",
		},
		{
			Name:    "create with an immutable /etc/gshadow",
			Setup:   `chattr +i /etc/gshadow`,
			Args:    &module.User{Name: "wtalice"},
			WantErr: "/etc/gshadow is immutable; chattr -i changes it",
		},
		{
			Name:    "a shell change with an immutable /etc/passwd",
			Setup:   `useradd -m -U -s /bin/sh wtalice && chattr +i /etc/passwd`,
			Args:    &module.User{Name: "wtalice", Shell: "/bin/bash"},
			WantErr: "/etc/passwd is immutable; chattr -i changes it",
		},
		{
			Name:    "a shell change with an immutable /etc/shadow",
			Setup:   `useradd -m -U -s /bin/sh wtalice && chattr +i /etc/shadow`,
			Args:    &module.User{Name: "wtalice", Shell: "/bin/bash"},
			WantErr: "/etc/shadow is immutable; chattr -i changes it",
		},
		{
			Name:  "a shell change with an immutable /etc/group and /etc/gshadow",
			Setup: `useradd -m -U -s /bin/sh wtalice && chattr +i /etc/group /etc/gshadow`,
			Args:  &module.User{Name: "wtalice", Shell: "/bin/bash"},
			Want:  change("shell /bin/sh → /bin/bash"),
			After: `[ "$(getent passwd wtalice | cut -d: -f7)" = /bin/bash ]`,
		},
		{
			Name:    "a password with an immutable /etc/shadow",
			Setup:   `useradd -m -U wtalice && chattr +i /etc/shadow`,
			Args:    &module.User{Name: "wtalice", Password: hash1},
			WantErr: "/etc/shadow is immutable; chattr -i changes it",
		},
		{
			Name:    "a password with an immutable /etc/passwd",
			Setup:   `useradd -m -U wtalice && chattr +i /etc/passwd`,
			Args:    &module.User{Name: "wtalice", Password: hash1},
			WantErr: "/etc/passwd is immutable; chattr -i changes it",
		},
		{
			Name:  "a password with an immutable /etc/group and /etc/gshadow",
			Setup: `useradd -m -U wtalice && chattr +i /etc/group /etc/gshadow`,
			Args:  &module.User{Name: "wtalice", Password: hash1},
			Want:  change("change password"),
			After: `[ "$(getent shadow wtalice | cut -d: -f2)" = '` + hash1 + `' ]`,
		},
		{
			Name:    "add groups with an immutable /etc/group",
			Setup:   `useradd -m -U wtalice && groupadd wtgrp && chattr +i /etc/group`,
			Args:    &module.User{Name: "wtalice", AddGroups: &[]string{"wtgrp"}},
			WantErr: "/etc/group is immutable; chattr -i changes it",
		},
		{
			Name:    "add groups with an immutable /etc/gshadow",
			Setup:   `useradd -m -U wtalice && groupadd wtgrp && chattr +i /etc/gshadow`,
			Args:    &module.User{Name: "wtalice", AddGroups: &[]string{"wtgrp"}},
			WantErr: "/etc/gshadow is immutable; chattr -i changes it",
		},
		{
			Name:    "absent with an immutable /etc/passwd",
			Setup:   `useradd -M -U wtalice && chattr +i /etc/passwd`,
			Args:    &module.User{Name: "wtalice", Absent: true},
			WantErr: "/etc/passwd is immutable; chattr -i changes it",
		},
		{
			Name:    "absent with an immutable /etc/gshadow",
			Setup:   `useradd -M -U wtalice && chattr +i /etc/gshadow`,
			Args:    &module.User{Name: "wtalice", Absent: true},
			WantErr: "/etc/gshadow is immutable; chattr -i changes it",
		},
		{
			Name:  "a user as declared with immutable account files",
			Setup: `useradd -m -U -s /bin/bash wtalice && chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow`,
			Args:  &module.User{Name: "wtalice", Shell: "/bin/bash"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "keys with immutable account files",
			Setup: `useradd -m -U wtalice && chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  addK1,
		},
		{
			Name:      "absent with an immutable /etc/shadow",
			Setup:     `useradd -M -U wtalice && chattr +i /etc/shadow`,
			Args:      &module.User{Name: "wtalice", Absent: true},
			WantErr:   "/etc/shadow is immutable; chattr -i changes it",
			Unchanged: `getent passwd wtalice`,
		},
		{
			Name:    "absent with an immutable /etc/group",
			Setup:   `useradd -M -U wtalice && chattr +i /etc/group`,
			Args:    &module.User{Name: "wtalice", Absent: true},
			WantErr: "/etc/group is immutable; chattr -i changes it",
		},
	})
}

// spec: Modules/user and group
func TestGroupModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "group")
	reset := `chattr -ia /etc/passwd /etc/shadow /etc/group /etc/gshadow; for u in wtu1 wtu2 wtu3; do userdel $u 2>/dev/null; done; for g in wtgrp wtother Debian-wt; do groupdel $g 2>/dev/null; done; true`
	vmtest.RunCases(t, vm, "group", reset, []vmtest.Case{
		{
			Name:      "create",
			Args:      &module.Group{Name: "wtgrp"},
			Want:      module.Result{Status: module.Change, Action: module.Create},
			Unchanged: `! getent group wtgrp`,
			After:     `[ "$(getent group wtgrp | cut -d: -f3)" -ge 1000 ]`,
		},
		{
			Name:  "create with gid and system",
			Args:  &module.Group{Name: "wtgrp", GID: "2500", System: true},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"gid 2500", "system group"}},
			After: `[ "$(getent group wtgrp)" = "wtgrp:x:2500:" ]`,
		},
		{
			Name:  "a system group",
			Args:  &module.Group{Name: "wtgrp", System: true},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"system group"}},
			After: `[ "$(getent group wtgrp | cut -d: -f3)" -lt 1000 ]`,
		},
		{
			Name:  "change gid",
			Setup: `groupadd -g 2600 wtgrp`,
			Args:  &module.Group{Name: "wtgrp", GID: "2700"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"gid 2600 → 2700; files keep the old gid"}},
			After: `[ "$(getent group wtgrp)" = "wtgrp:x:2700:" ]`,
		},
		{
			Name:  "change gid of a primary group",
			Setup: `groupadd -g 2600 wtgrp && useradd -M -g wtgrp wtu2 && useradd -M -g wtgrp wtu1 && useradd -M -U -G wtgrp wtu3`,
			Args:  &module.Group{Name: "wtgrp", GID: "2700"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"gid 2600 → 2700; files keep the old gid", "the primary group of wtu1, wtu2 moves to gid 2700"}},
			After: `[ "$(id -g wtu1) $(id -g wtu2)" = "2700 2700" ]`,
		},
		{
			Name:  "ok",
			Setup: `groupadd -g 2600 wtgrp`,
			Args:  &module.Group{Name: "wtgrp", GID: "2600", System: true},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a gid with a leading zero",
			Setup: `groupadd -g 2600 wtgrp`,
			Args:  &module.Group{Name: "wtgrp", GID: "02600"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a group with a Debian name that exists",
			Setup: `groupadd -g 2600 Debian-wt`,
			Args:  &module.Group{Name: "Debian-wt", GID: "2700"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"gid 2600 → 2700; files keep the old gid"}},
			After: `[ "$(getent group Debian-wt)" = "Debian-wt:x:2700:" ]`,
		},
		{
			Name:      "a new group with a Debian name",
			Args:      &module.Group{Name: "Debian-wt"},
			WantErr:   `group Debian-wt does not exist, and winch creates only names with lower-case letters, digits, "_", and "-" that start with a letter or "_"`,
			Unchanged: `! getent group Debian-wt`,
		},
		{
			Name:    "a gid of another group",
			Setup:   `groupadd -g 2800 wtother`,
			Args:    &module.Group{Name: "wtgrp", GID: "2800"},
			WantErr: "gid 2800 belongs to group wtother",
		},
		{
			Name:      "create with an immutable /etc/group",
			Setup:     `chattr +i /etc/group`,
			Args:      &module.Group{Name: "wtgrp"},
			WantErr:   "/etc/group is immutable; chattr -i changes it",
			Unchanged: `! getent group wtgrp`,
		},
		{
			Name:    "create with an append-only /etc/gshadow",
			Setup:   `chattr +a /etc/gshadow`,
			Args:    &module.Group{Name: "wtgrp"},
			WantErr: "/etc/gshadow is append-only; chattr -a changes it",
		},
		{
			Name:  "a group as declared with an immutable /etc/passwd and /etc/group",
			Setup: `groupadd -g 2600 wtgrp && chattr +i /etc/passwd /etc/group`,
			Args:  &module.Group{Name: "wtgrp", GID: "2600"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "create with an immutable /etc/gshadow",
			Setup:   `chattr +i /etc/gshadow`,
			Args:    &module.Group{Name: "wtgrp"},
			WantErr: "/etc/gshadow is immutable; chattr -i changes it",
		},
		{
			Name:    "change gid with an immutable /etc/group",
			Setup:   `groupadd -g 2600 wtgrp && chattr +i /etc/group`,
			Args:    &module.Group{Name: "wtgrp", GID: "2700"},
			WantErr: "/etc/group is immutable; chattr -i changes it",
		},
		{
			Name:    "change gid with an immutable /etc/passwd",
			Setup:   `groupadd -g 2600 wtgrp && chattr +i /etc/passwd`,
			Args:    &module.Group{Name: "wtgrp", GID: "2700"},
			WantErr: "/etc/passwd is immutable; chattr -i changes it",
		},
		{
			Name:  "change gid with an immutable /etc/shadow and /etc/gshadow",
			Setup: `groupadd -g 2600 wtgrp && chattr +i /etc/shadow /etc/gshadow`,
			Args:  &module.Group{Name: "wtgrp", GID: "2700"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"gid 2600 → 2700; files keep the old gid"}},
			After: `[ "$(getent group wtgrp)" = "wtgrp:x:2700:" ]`,
		},
		{
			Name:      "absent",
			Setup:     `groupadd wtgrp && useradd -M -U -G wtgrp wtu1`,
			Args:      &module.Group{Name: "wtgrp", Absent: true},
			Want:      module.Result{Status: module.Change, Action: module.Remove},
			Unchanged: `getent group wtgrp`,
			After:     `! getent group wtgrp && [ "$(id -Gn wtu1)" = wtu1 ]`,
		},
		{
			Name: "absent of a missing group",
			Args: &module.Group{Name: "wtgrp", Absent: true},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:      "absent of a primary group",
			Setup:     `groupadd wtgrp && useradd -M -g wtgrp wtu2 && useradd -M -g wtgrp wtu1`,
			Args:      &module.Group{Name: "wtgrp", Absent: true},
			WantErr:   "wtgrp is the primary group of wtu1, wtu2; remove them or change their group first",
			Unchanged: `getent group wtgrp`,
		},
		{
			Name:    "absent with an immutable /etc/gshadow",
			Setup:   `groupadd wtgrp && chattr +i /etc/gshadow`,
			Args:    &module.Group{Name: "wtgrp", Absent: true},
			WantErr: "/etc/gshadow is immutable; chattr -i changes it",
		},
		{
			Name:    "absent with an immutable /etc/group",
			Setup:   `groupadd wtgrp && chattr +i /etc/group`,
			Args:    &module.Group{Name: "wtgrp", Absent: true},
			WantErr: "/etc/group is immutable; chattr -i changes it",
		},
		{
			Name:      "absent of a group of the login user",
			Setup:     `groupadd wtgrp && gpasswd -a admin wtgrp`,
			Args:      &module.Group{Name: "wtgrp", Absent: true},
			WantErr:   "the login user admin is in group wtgrp; removing it cuts off winch's access",
			Unchanged: `getent group wtgrp`,
		},
		{
			Name:    "absent of the primary group of the login user",
			Args:    &module.Group{Name: "admin", Absent: true},
			WantErr: "the login user admin is in group admin; removing it cuts off winch's access",
		},
	})
}

// spec: Modules/user and group; Running a pipeline/Plan
func TestUsers(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "users")
	vm.MustRun(t, `useradd -M -U Debian-wt && install -d -o Debian-wt /var/lib/wt`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  " + vm.Name + ": {}\n",
		"pipelines/site.yaml": `stages:
  - name: people
    hosts: all
    steps:
      - group:
          name: wtteam
          gid: 2900
      - user:
          name: wtdev
          group: wtteam
          groups: [Debian-wt]
          shell: /bin/bash
          authorized_keys:
            - ` + strings.TrimSpace(vmtest.PublicKey) + `
      - cmd:
          command: id -un > /var/lib/wt/user
          creates: /var/lib/wt/user
          user: Debian-wt
`,
	})
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "group wtteam (does not exist yet)") {
		t.Fatalf("plan: exit %d", r.Code)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	vm.MustRun(t, `[ "$(cat /var/lib/wt/user)" = Debian-wt ] && [ "$(id -nG wtdev)" = "wtteam Debian-wt" ]`)
	cmd := exec.CommandContext(t.Context(), "ssh", "-l", "wtdev", vm.Name, "id -un; id -gn")
	cmd.Env = lab.Env()
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "wtdev\nwtteam\n" {
		t.Errorf("ssh as wtdev: %v: %q", err, out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}

// spec: Modules/user and group
func TestGroupAbsentAfterUser(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "group-absent")
	vm.MustRun(t, `useradd -M -U wtapp && groupadd wtshared && useradd -M -g wtshared wtu1`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  " + vm.Name + ": {}\n",
		"pipelines/site.yaml": `stages:
  - name: s
    hosts: all
    steps:
      - user: {name: wtapp, absent: true}
      - group: {name: wtapp, absent: true}
      - user: {name: wtu1, absent: true}
      - group: {name: wtshared, absent: true}
`,
		"pipelines/reverse.yaml": `stages:
  - name: s
    hosts: all
    steps:
      - group: {name: wtapp, absent: true}
      - user: {name: wtapp, absent: true}
`,
	})
	r := lab.Winch(t, dir, "plan", "reverse")
	if r.Code == 0 || !strings.Contains(r.Stderr, "wtapp is the primary group of wtapp") {
		t.Errorf("plan reverse: exit %d:\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "- group wtshared") {
		t.Fatalf("plan: exit %d:\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 || strings.Contains(r.Stdout, "s: - group wtapp") || !strings.Contains(r.Stdout, "s: - group wtshared") {
		t.Fatalf("apply: exit %d:\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, `! getent passwd wtapp && ! getent group wtapp && ! getent passwd wtu1 && ! getent group wtshared`)
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}

// spec: Modules/user and group
func TestGroupAbsentAfterMove(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "group-move")
	vm.MustRun(t, `groupadd wtold && useradd -M -g wtold wtu1`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  " + vm.Name + ": {}\n",
		"pipelines/site.yaml": `stages:
  - name: s
    hosts: all
    steps:
      - group: {name: wtnew}
      - user: {name: wtu1, group: wtnew}
      - group: {name: wtold, absent: true}
`,
	})
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "- group wtold") {
		t.Fatalf("plan: exit %d:\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d:\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, `[ "$(id -gn wtu1)" = wtnew ] && ! getent group wtold`)
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}

// spec: Modules/user and group; Running a pipeline/Plan
func TestUserAddGroupsCombine(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "add-groups")
	vm.MustRun(t, `groupadd wtgrp && groupadd wtother && useradd -m -U -G adm wtdev`)
	files := map[string]string{
		"winch.yaml":                 "name: acme\ninventory: test\n",
		"inventories/test.yaml":      "hosts:\n  " + vm.Name + ": {}\n",
		"recipes/docker/recipe.yaml": "steps:\n  - user:\n      name: wtdev\n      add_groups: [wtgrp]\n",
		"recipes/web/recipe.yaml":    "steps:\n  - user:\n      name: wtdev\n      add_groups: [wtother]\n",
		"pipelines/site.yaml":        "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: docker\n      - recipe: web\n",
		"pipelines/create.yaml":      "stages:\n  - name: s\n    hosts: all\n    steps:\n      - user:\n          name: wtnew\n      - user:\n          name: wtnew\n          add_groups: [wtgrp]\n",
		"pipelines/exact.yaml":       "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: docker\n      - user:\n          name: wtdev\n          groups: [adm]\n",
	}
	dir := vmtest.WriteProject(t, files)
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "add to group wtgrp") || !strings.Contains(r.Stdout, "add to group wtother") {
		t.Fatalf("plan: exit %d:\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d: %s", r.Code, r.Stderr)
	}
	vm.MustRun(t, `[ "$(id -nG wtdev)" = "wtdev adm wtgrp wtother" ]`)
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
	if r := lab.Winch(t, dir, "apply", "create", "--yes"); r.Code != 0 {
		t.Fatalf("apply create: exit %d: %s", r.Code, r.Stderr)
	}
	vm.MustRun(t, `[ "$(id -nG wtnew)" = "wtnew wtgrp" ] && [ -d /home/wtnew ]`)
	r = lab.Winch(t, dir, "plan", "create")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan create: exit %d, stdout %q", r.Code, r.Stdout)
	}
	r = lab.Winch(t, dir, "plan", "exact")
	want := "s: user wtdev: the user wtdev is also in docker: user wtdev, with other arguments"
	if r.Code == 0 || !strings.Contains(r.Stdout+r.Stderr, want) {
		t.Errorf("plan exact: exit %d, want the error %q:\n%s%s", r.Code, want, r.Stdout, r.Stderr)
	}
}

// spec: Modules/user and group
func TestUserKeysLogin(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "keys-login")
	// UsePAM no refuses a password locked with "!", as cloud-init sets for
	// admin.
	vm.MustRun(t, `printf 'UsePAM no\nStrictModes yes\n' > /etc/ssh/sshd_config.d/wt.conf && usermod -p '*' admin
useradd -m -U -s /bin/bash wtdev && usermod -p '*' wtdev && chown root /home/wtdev && chmod 755 /home/wtdev
systemctl reload ssh`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  " + vm.Name + ": {}\n",
		"pipelines/site.yaml": `stages:
  - name: people
    hosts: all
    steps:
      - user:
          name: wtdev
          authorized_keys:
            - ` + strings.TrimSpace(vmtest.PublicKey) + `
`,
	})
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d: %s", r.Code, r.Stderr)
	}
	cmd := exec.CommandContext(t.Context(), "ssh", "-l", "wtdev", vm.Name, "id -un")
	cmd.Env = lab.Env()
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "wtdev\n" {
		t.Errorf("ssh as wtdev: %v: %q", err, out)
	}
}

// spec: Modules/user and group
func TestUserLoginPassword(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "login-password")
	reset := `usermod -p '*' admin
userdel wtalice 2>/dev/null || true
printf 'UsePAM no\n' > /etc/ssh/sshd_config.d/wt.conf
systemctl reload ssh`
	vmtest.RunCases(t, vm, "user", reset, []vmtest.Case{
		{
			Name:      "a locked login password with UsePAM no",
			Args:      &module.User{Name: "admin", Password: "!"},
			WantErr:   `with UsePAM no, sshd refuses the login of admin: its password is locked with "!"`,
			Unchanged: `[ "$(getent shadow admin | cut -d: -f2)" = '*' ]`,
		},
		{
			Name:      "a locked login hash with UsePAM no",
			Args:      &module.User{Name: "admin", Password: "!" + hash1},
			WantErr:   `with UsePAM no, sshd refuses the login of admin: its password is locked with "!"`,
			Unchanged: `[ "$(getent shadow admin | cut -d: -f2)" = '*' ]`,
		},
		{
			Name: "a star password permits key login with UsePAM no",
			Args: &module.User{Name: "admin", Password: "*"},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "another user's password may be locked",
			Setup: `useradd -M -d /nonexistent wtalice && usermod -p '*' wtalice`,
			Args:  &module.User{Name: "wtalice", Password: "!"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"change password"}},
			After: `[ "$(getent shadow wtalice | cut -d: -f2)" = '!' ]`,
		},
		{
			Name:  "a locked login password with UsePAM yes",
			Setup: `printf 'UsePAM yes\n' > /etc/ssh/sshd_config.d/wt.conf && systemctl reload ssh`,
			Args:  &module.User{Name: "admin", Password: "!"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"change password"}},
			After: `[ "$(getent shadow admin | cut -d: -f2)" = '!' ]`,
		},
	})
}

// spec: Modules/user; Modules/file, dir, link (dir purge)
func TestSSHDChecksWithoutRunDir(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "sshd-norun")
	vm.MustRun(t, "mkdir /tmp/w && touch /tmp/w/junk")
	s := vm.Session(t)
	// The state after a stop of ssh.service on a host with ssh.socket. A new
	// login would make /run/sshd again, so the test uses the session alone.
	if res, err := s.Exec(t.Context(), "mv /run/sshd /run/sshd.off"); err != nil || res.ExitCode != 0 {
		t.Fatalf("move /run/sshd: %+v, %v", res, err)
	}
	t.Cleanup(func() { s.Exec(context.Background(), "mv /run/sshd.off /run/sshd") }) //nolint:errcheck // the VM can be gone
	ctx := t.Context()
	got, err := s.Check(ctx, "user", &module.User{Name: "wtalice", AuthorizedKeys: keys(fakeKey('1', "one"))}, &module.State{})
	if err != nil || got.Status != module.Change {
		t.Errorf("check of user keys = %+v, %v; want a change", got, err)
	}
	got, err = s.Check(ctx, "dir", &module.Dir{Path: "/tmp/w", Purge: true}, &module.State{})
	if want := []string{"remove file /tmp/w/junk"}; err != nil || !slices.Equal(got.Changes, want) {
		t.Errorf("check of a purge = %+v, %v; want the changes %q", got, err, want)
	}
	_, err = s.Check(ctx, "dir", &module.Dir{Path: "/etc/ssh", Purge: true}, &module.State{})
	if want := "purge of /etc/ssh would remove files that sshd needs: "; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("check of a purge of /etc/ssh: %v, want an error that starts with %q", err, want)
	}
	if res, err := s.Exec(ctx, "echo 'NoSuchOption yes' > /etc/ssh/sshd_config.d/wt.conf"); err != nil || res.ExitCode != 0 {
		t.Fatalf("write a bad sshd drop-in: %+v, %v", res, err)
	}
	_, err = s.Check(ctx, "user", &module.User{Name: "wtalice", AuthorizedKeys: keys(fakeKey('1', "one"))}, &module.State{})
	if want := "sshd -T without /run/sshd: "; err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "NoSuchOption") {
		t.Errorf("check of user keys with a bad sshd config: %v, want an error that starts with %q and names the option", err, want)
	}
	if res, err := s.Exec(ctx, "rm /etc/ssh/sshd_config.d/wt.conf"); err != nil || res.ExitCode != 0 {
		t.Fatalf("remove the bad sshd drop-in: %+v, %v", res, err)
	}
	if res, err := s.Exec(ctx, "[ ! -e /run/sshd ]"); err != nil || res.ExitCode != 0 {
		t.Errorf("the checks made /run/sshd: %+v, %v", res, err)
	}
}
