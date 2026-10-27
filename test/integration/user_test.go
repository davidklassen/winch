package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os/exec"
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
	reset := `systemctl stop wt-sleep 2>/dev/null || true
for u in wtalice wtbob wtsvc; do pkill -9 -u $u; userdel $u 2>/dev/null; done
sed -i '/^wtbob:/d' /etc/passwd /etc/shadow
for g in wtalice wtbob wtsvc wtgrp wtnew wtother; do groupdel $g 2>/dev/null; done
gpasswd -d admin wtalice 2>/dev/null
chattr -R -ia /home/wtalice 2>/dev/null
rm -rf /home/wtalice /home/wtbob /srv/w /var/lib/wtsvc /opt/wt /root/.ssh /etc/ssh/sshd_config.d/wt.conf
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
			Setup:        `useradd -m -U -u 2200 wtalice && systemd-run --uid=wtalice --unit=wt-sleep sleep 600 && timeout 10 sh -c 'until pgrep -u wtalice sleep; do sleep 0.1; done'`,
			Args:         &module.User{Name: "wtalice", UID: "2300"},
			Want:         change("uid 2200 → 2300, also of the files in the home; other files keep the old uid", "processes of wtalice run (sleep); usermod fails while they run"),
			WantApplyErr: "usermod: user wtalice is currently used by process",
			Fix:          "systemctl stop wt-sleep",
			After:        `[ "$(id -u wtalice)" = 2200 ]`,
		},
		{
			Name:         "a home change with a running process",
			Setup:        `useradd -m -U wtalice && systemd-run --uid=wtalice --unit=wt-sleep sleep 600 && timeout 10 sh -c 'until pgrep -u wtalice sleep; do sleep 0.1; done'`,
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
			After: `[ "$(getent passwd wtalice | cut -d: -f3,6,7)" = "2300:/srv/w/alice:/bin/bash" ] && [ "$(id -gn wtalice)" = wtgrp ] && [ "$(stat -c '%U %G %a' /srv/w/alice)" = "wtalice wtgrp 700" ]`,
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
			Name:    "the groups of the login user",
			Setup:   `groupadd wtgrp`,
			Args:    &module.User{Name: "admin", Groups: &[]string{"wtgrp"}},
			WantErr: "admin is the login user of this session; log in as another user to change its groups",
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
			WantErr: "password is not a crypt hash, such as one from mkpasswd -m yescrypt",
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
			Setup: `useradd -m -U wtalice && install -d -o wtalice -g wtalice -m 700 /home/wtalice/.ssh && ln -s /etc/motd /home/wtalice/.ssh/authorized_keys && cp /etc/motd /tmp/motd`,
			Args:  &module.User{Name: "wtalice", AuthorizedKeys: keys(k1)},
			Want:  change("replace the symbolic link /home/wtalice/.ssh/authorized_keys to /etc/motd", "create file /home/wtalice/.ssh/authorized_keys (owner wtalice, group wtalice, mode 0600)", "add key "+keyLine(k1)),
			After: `cmp /etc/motd /tmp/motd && [ -f /home/wtalice/.ssh/authorized_keys ] && [ ! -L /home/wtalice/.ssh/authorized_keys ]`,
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
			After: `[ "$(stat -c '%G %a' /home/wtalice)" = "wtnew 775" ]`,
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
			Want:      module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove group wtalice"}},
			Unchanged: `getent passwd wtalice`,
			After:     `! getent passwd wtalice && ! getent group wtalice && [ -d /home/wtalice ]`,
		},
		{
			Name:  "absent keeps a group with members",
			Setup: `useradd -m -U wtalice && usermod -aG wtalice admin`,
			Args:  &module.User{Name: "wtalice", Absent: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove},
			After: `! getent passwd wtalice && getent group wtalice`,
		},
		{
			Name:  "absent removes a group whose only member is the user",
			Setup: `useradd -m -U wtalice && usermod -aG wtalice wtalice`,
			Args:  &module.User{Name: "wtalice", Absent: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove group wtalice"}},
			After: `! getent group wtalice`,
		},
		{
			Name:  "absent keeps a group that is the primary group of another user",
			Setup: `useradd -m -U wtalice && useradd -M -g wtalice wtbob`,
			Args:  &module.User{Name: "wtalice", Absent: true},
			Want:  module.Result{Status: module.Change, Action: module.Remove},
			After: `getent group wtalice`,
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
			Setup:        `useradd -U wtalice && systemd-run --uid=wtalice --unit=wt-sleep sleep 600 && timeout 10 sh -c 'until pgrep -u wtalice sleep; do sleep 0.1; done'`,
			Args:         &module.User{Name: "wtalice", Absent: true},
			Want:         module.Result{Status: module.Change, Action: module.Remove, Changes: []string{"remove group wtalice"}},
			WantApplyErr: "userdel: user wtalice is currently used by process",
			Fix:          "systemctl stop wt-sleep",
			After:        `getent passwd wtalice`,
		},
	})
}

// spec: Modules/user and group
func TestGroupModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "group")
	reset := `for u in wtu1 wtu2 wtu3; do userdel $u 2>/dev/null; done; for g in wtgrp wtother; do groupdel $g 2>/dev/null; done; true`
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
			Name:    "a gid of another group",
			Setup:   `groupadd -g 2800 wtother`,
			Args:    &module.Group{Name: "wtgrp", GID: "2800"},
			WantErr: "gid 2800 belongs to group wtother",
		},
	})
}

// spec: Modules/user and group; Running a pipeline/Plan
func TestUsers(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "users")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
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
          shell: /bin/bash
          authorized_keys:
            - ` + strings.TrimSpace(vmtest.PublicKey) + `
`,
	})
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "group wtteam (does not exist yet)") {
		t.Fatalf("plan: exit %d", r.Code)
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
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
func TestUserKeysLogin(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "keys-login")
	// UsePAM no refuses a password locked with "!", as cloud-init sets for
	// admin.
	vm.MustRun(t, `printf 'UsePAM no\nStrictModes yes\n' > /etc/ssh/sshd_config.d/wt.conf && usermod -p '*' admin
useradd -m -U -s /bin/bash wtdev && usermod -p '*' wtdev && chown root /home/wtdev && chmod 755 /home/wtdev
systemctl reload ssh`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
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
