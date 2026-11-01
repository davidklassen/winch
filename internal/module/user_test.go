package module

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// key returns an authorized_keys line of type typ with a blob of that type.
func key(typ, comment string) string {
	return keyBlob(typ, typ, comment)
}

// keyBlob returns a line of type typ whose blob names the type inner.
func keyBlob(typ, inner, comment string) string {
	blob := binary.BigEndian.AppendUint32(nil, uint32(len(inner)))
	blob = append(blob, inner...)
	blob = append(blob, make([]byte, 32)...)
	line := typ + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		line += " " + comment
	}
	return line
}

// rsaKey returns an ssh-rsa authorized_keys line whose modulus has bits bits.
func rsaKey(bits int) string {
	mpint := func(b []byte, n *big.Int) []byte {
		v := n.Bytes()
		if v[0]&0x80 != 0 {
			v = append([]byte{0}, v...)
		}
		return append(binary.BigEndian.AppendUint32(b, uint32(len(v))), v...)
	}
	blob := binary.BigEndian.AppendUint32(nil, 7)
	blob = append(blob, "ssh-rsa"...)
	blob = mpint(blob, big.NewInt(65537))
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	blob = mpint(blob, n.Or(n, big.NewInt(1)))
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(blob)
}

// spec: Modules/user and group
func TestUserValidate(t *testing.T) {
	ed := key("ssh-ed25519", "alice@laptop")
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"name", "name: alice\n", ""},
		{"all fields", "name: vmail\nuid: 5000\ngroup: vmail\nsystem: true\nhome: /var/vmail\nshell: /usr/sbin/nologin\n", ""},
		{"quoted uid", "name: a\nuid: \"5000\"\n", ""},
		{"numeric group", "name: a\ngroup: 100\n", ""},
		{"underscore and digits", "name: _rspamd-2\n", ""},
		{"no name", "uid: 5\n", `t.yaml:1:1: missing key "name"`},
		{"upper case", "name: Debian-exim\n", ""},
		{"dot", "name: john.doe\n", ""},
		{"leading dot", "name: .a\n", `t.yaml:1:7: name: ".a" is not a user name; a name has letters, digits, _, ., and -, and starts with a letter or _`},
		{"leading digit", "name: 1a\n", `t.yaml:1:7: name: "1a" is not a user name; a name has letters, digits, _, ., and -, and starts with a letter or _`},
		{"too long", "name: " + strings.Repeat("a", 33) + "\n", `t.yaml:1:7: name: has 33 characters; a name has at most 32`},
		{"uid name", "name: a\nuid: alice\n", `t.yaml:2:6: uid: must be a numeric ID, such as "1000"`},
		{"uid negative", "name: a\nuid: -1\n", `t.yaml:2:6: uid: must be a numeric ID, such as "1000"`},
		{"uid too large", "name: a\nuid: 4294967295\n", `t.yaml:2:6: uid: an ID must be below 4294967295`},
		{"bad group", "name: a\ngroup: \"a b\"\n", `t.yaml:2:8: group: "a b" is not a group name; a name has letters, digits, _, ., and -, and starts with a letter or _`},
		{"relative home", "name: a\nhome: var/a\n", `t.yaml:2:7: home: must be an absolute path`},
		{"unclean home", "name: a\nhome: /srv/app/\n", `t.yaml:2:7: home: must be a clean path, such as "/srv/app"`},
		{"dot dot home", "name: a\nhome: /srv/../app\n", `t.yaml:2:7: home: ".." is not allowed; write the path without it`},
		{"relative shell", "name: a\nshell: bash\n", `t.yaml:2:8: shell: must be an absolute path`},
		{"control character in home", "name: a\nhome: \"/home/a\\rb\"\n", `t.yaml:2:7: home: has a control character`},
		{"control character in shell", "name: a\nshell: \"/bin/sh\\n\"\n", `t.yaml:2:8: shell: has a control character`},
		{"absent", "name: a\nabsent: true\n", ""},
		{"absent with uid", "name: a\nabsent: true\nuid: 5\n", `t.yaml:3:6: uid: not with absent: true`},
		{"absent with keys", "name: a\nabsent: true\nauthorized_keys: []\n", `t.yaml:3:18: authorized_keys: not with absent: true`},
		{"keys", "name: a\nauthorized_keys:\n  - " + ed + "\n  - " + rsaKey(3072) + "\n  - " + key("ecdsa-sha2-nistp256", "a b c") + "\n", ""},
		{"no keys", "name: a\nauthorized_keys: []\n", ""},
		{"rsa 1024", "name: a\nauthorized_keys:\n  - " + rsaKey(1024) + "\n", ""},
		{"rsa 1023", "name: a\nauthorized_keys:\n  - " + ed + "\n  - " + rsaKey(1023) + "\n", `t.yaml:3:3: authorized_keys: element 2 is a 1023-bit RSA key; sshd rejects RSA keys under 1024 bits`},
		{"rsa without modulus", "name: a\nauthorized_keys:\n  - " + key("ssh-rsa", "") + "\n", `t.yaml:3:3: authorized_keys: element 1 is not a key: the key data is not an ssh-rsa key`},
		{"rsa modulus past the end", "name: a\nauthorized_keys:\n  - " + rsaKey(2048)[:len("ssh-rsa ")+40] + "\n", `t.yaml:3:3: authorized_keys: element 1 is not a key: the key data is not an ssh-rsa key`},
		{"dss", "name: a\nauthorized_keys:\n  - " + key("ssh-dss", "") + "\n", `t.yaml:3:3: authorized_keys: element 1 is an ssh-dss key; sshd rejects ssh-dss keys`},
		{"options", "name: a\nauthorized_keys:\n  - 'command=\"echo a b\",no-pty " + ed + "'\n", ""},
		{"security key", "name: a\nauthorized_keys:\n  - " + key("sk-ssh-ed25519@openssh.com", "") + "\n", ""},
		{"a string", "name: a\nauthorized_keys: x\n", `t.yaml:2:18: authorized_keys: expected a list, got the string "x"`},
		{"two lines", "name: a\nauthorized_keys:\n  - \"" + ed + "\\n" + ed + "\"\n", `t.yaml:3:3: authorized_keys: element 1 has more than one line`},
		{"empty", "name: a\nauthorized_keys: [\"\"]\n", `t.yaml:2:18: authorized_keys: element 1 is empty`},
		{"unknown type", "name: a\nauthorized_keys:\n  - " + ed + "\n  - " + key("ssh-foo", "") + "\n", `t.yaml:3:3: authorized_keys: element 2 is not a key: no key type such as "ssh-ed25519"`},
		{"bad base64", "name: a\nauthorized_keys:\n  - ssh-ed25519 AAAA!!!!\n", `t.yaml:3:3: authorized_keys: element 1 is not a key: the key data is not base64`},
		{"no data", "name: a\nauthorized_keys:\n  - ssh-ed25519\n", `t.yaml:3:3: authorized_keys: element 1 is not a key: the key data is missing`},
		{"other blob type", "name: a\nauthorized_keys:\n  - " + keyBlob("ssh-ed25519", "ssh-rsa", "") + "\n", `t.yaml:3:3: authorized_keys: element 1 is not a key: the key data is not an ssh-ed25519 key`},
		{"truncated", "name: a\nauthorized_keys:\n  - ssh-ed25519 AAAAC3NzaC1lZDI1\n", `t.yaml:3:3: authorized_keys: element 1 is not a key: the key data is not an ssh-ed25519 key`},
		{"tabs", "name: a\nauthorized_keys:\n  - \"" + strings.ReplaceAll(ed, " ", "\\t") + "\"\n", ""},
		{"repeated key", "name: a\nauthorized_keys:\n  - " + ed + "\n  - " + ed + "\n", `t.yaml:3:3: authorized_keys: element 2 has the key of element 1`},
		{"same key, other comment", "name: a\nauthorized_keys:\n  - " + ed + "\n  - " + rsaKey(2048) + "\n  - 'no-pty " + strings.TrimSuffix(ed, "alice@laptop") + "bob'\n", `t.yaml:3:3: authorized_keys: element 3 has the key of element 1`},
		{"system keys without home", "name: a\nsystem: true\nauthorized_keys: []\n", `t.yaml:3:18: authorized_keys: a system user without home has no home for its keys; set home`},
		{"system keys with home", "name: a\nsystem: true\nhome: /var/a\nauthorized_keys: []\n", ""},
		{"unknown key", "name: a\ngroupz: [sudo]\n", `t.yaml:2:1: unknown key "groupz"; did you mean "group"?`},
		{"groups", "name: a\ngroups: [sudo, docker]\n", ""},
		{"Debian groups", "name: a\ngroup: Debian-exim\ngroups: [Debian-snmp, john.doe]\n", ""},
		{"no groups", "name: a\ngroups: []\n", ""},
		{"groups a string", "name: a\ngroups: sudo\n", `t.yaml:2:9: groups: expected a list, got the string "sudo"`},
		{"bad group in groups", "name: a\ngroups: [sudo, \"-A\"]\n", `t.yaml:2:9: groups: "-A" is not a group name; a name has letters, digits, _, ., and -, and starts with a letter or _`},
		{"repeated group", "name: a\ngroups: [sudo, docker, sudo]\n", `t.yaml:2:9: groups: sudo is in the list twice`},
		{"add_groups", "name: a\nadd_groups: [docker]\n", ""},
		{"bad group in add_groups", "name: a\nadd_groups: [\"-A\"]\n", `t.yaml:2:13: add_groups: "-A" is not a group name; a name has letters, digits, _, ., and -, and starts with a letter or _`},
		{"repeated group in add_groups", "name: a\nadd_groups: [docker, docker]\n", `t.yaml:2:13: add_groups: docker is in the list twice`},
		{"groups and add_groups", "name: a\ngroups: [sudo]\nadd_groups: [docker]\n", `t.yaml:3:13: a user step has at most one of groups and add_groups`},
		{"no groups and add_groups", "name: a\ngroups: []\nadd_groups: []\n", `t.yaml:3:13: a user step has at most one of groups and add_groups`},
		{"password", "name: a\npassword: $y$j9T$abc$def\n", ""},
		{"locked password", "name: a\npassword: '!$6$abc$def'\n", ""},
		{"comment", "name: a\ncomment: Alice Smith,,,\n", ""},
		{"comment with a colon", "name: a\ncomment: \"a:b\"\n", `t.yaml:2:10: comment: must not have ":"`},
		{"comment with a newline", "name: a\ncomment: \"a\\nb\"\n", `t.yaml:2:10: comment: has a control character`},
		{"absent with groups", "name: a\nabsent: true\ngroups: []\n", `t.yaml:3:9: groups: not with absent: true`},
		{"absent with add_groups", "name: a\nabsent: true\nadd_groups: []\n", `t.yaml:3:13: add_groups: not with absent: true`},
		{"absent with password", "name: a\nabsent: true\npassword: $6$a$b\n", `t.yaml:3:11: password: not with absent: true`},
		{"absent with comment", "name: a\nabsent: true\ncomment: a\n", `t.yaml:3:10: comment: not with absent: true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &User{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/user and group
func TestCheckHash(t *testing.T) {
	tests := []struct {
		pw string
		ok bool
	}{
		{"$y$j9T$salt$hash", true},
		{"$6$rounds=5000$salt$hash", true},
		{"$2b$12$abc./XYZ", true},
		{"!$6$salt$hash", true},
		{"hunter2", false},
		{"$6$", false},
		{"$6$a:b", false},
		{"$6$a b", false},
		{"$6$a\nb", false},
		{"!", true},
		{"*", true},
		{"!!", false},
		{"*$6$salt$hash", false},
	}
	for _, tt := range tests {
		err := checkHash(tt.pw)
		if (err == nil) != tt.ok {
			t.Errorf("checkHash(%q) = %v, want ok %v", tt.pw, err, tt.ok)
		}
		if err != nil && strings.Contains(err.Error(), tt.pw) {
			t.Errorf("checkHash(%q) = %v, shows the hash", tt.pw, err)
		}
	}
}

// spec: Modules/user and group
func TestGroupValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"name", "name: vmail\n", ""},
		{"all fields", "name: vmail\ngid: 5000\nsystem: true\n", ""},
		{"quoted gid", "name: vmail\ngid: \"5000\"\n", ""},
		{"no name", "gid: 5\n", `t.yaml:1:1: missing key "name"`},
		{"Debian name", "name: Debian-exim\n", ""},
		{"bad name", "name: \"-x\"\n", `t.yaml:1:7: name: "-x" is not a group name; a name has letters, digits, _, ., and -, and starts with a letter or _`},
		{"gid name", "name: a\ngid: abc\n", `t.yaml:2:6: gid: must be a numeric ID, such as "1000"`},
		{"gid too large", "name: a\ngid: \"99999999999\"\n", `t.yaml:2:6: gid: an ID must be below 4294967295`},
		{"absent", "name: a\nabsent: true\n", ""},
		{"absent with gid", "name: a\nabsent: true\ngid: 5\n", `t.yaml:3:6: gid: not with absent: true`},
		{"absent with system", "name: a\nabsent: true\nsystem: true\n", `t.yaml:3:9: system: not with absent: true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Group{}, tt.yaml, tt.want) })
	}
}

func TestParsePasswd(t *testing.T) {
	data := "# a comment\nroot:x:0:0:root:/root:/bin/bash\n\nalice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\nsvc:x:999:999:::\nadmin:x:1001:1001::/home/admin/:/bin/sh\n"
	got, err := parsePasswd("/etc/passwd", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := []passwdEntry{
		{name: "root", uid: 0, gid: 0, comment: "root", home: "/root", shell: "/bin/bash"},
		{name: "alice", uid: 1000, gid: 1000, comment: "Alice,,,", home: "/home/alice", shell: "/bin/bash"},
		// Empty fields are what login uses.
		{name: "svc", uid: 999, gid: 999, home: "/", shell: "/bin/sh"},
		{name: "admin", uid: 1001, gid: 1001, home: "/home/admin", shell: "/bin/sh"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParsePasswdBad(t *testing.T) {
	tests := []struct{ data, want string }{
		{"root:x:0:0:root:/root\n", "/etc/passwd:1: expected 7 fields, got 6"},
		{"root:x:0:0:root:/root:/bin/sh\nbob:x:b:0::/:/bin/sh\n", `/etc/passwd:2: the UID "b" is not a number`},
		{"bob:x:1:-1::/:/bin/sh\n", `/etc/passwd:1: the GID "-1" is not a number`},
		{"bob:x:4294967296:0::/:/bin/sh\n", "/etc/passwd:1: the UID 4294967296 is out of range"},
	}
	for _, tt := range tests {
		_, err := parsePasswd("/etc/passwd", []byte(tt.data))
		if err == nil || err.Error() != tt.want {
			t.Errorf("%q: error %v, want %q", tt.data, err, tt.want)
		}
	}
}

func TestParseGroup(t *testing.T) {
	data := "# a comment\nroot:x:0:\nsudo:x:27:alice,bob\n"
	got, err := parseGroup("/etc/group", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := []groupEntry{{name: "root", gid: 0}, {name: "sudo", gid: 27, members: []string{"alice", "bob"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	for _, bad := range []string{"root:x:0\n", "root:x:z:\n"} {
		if _, err := parseGroup("/etc/group", []byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestKeyPlan(t *testing.T) {
	ed := key("ssh-ed25519", "alice@laptop")
	blob, _ := base64.StdEncoding.DecodeString(strings.Fields(ed)[1])
	fp := fingerprint(blob)
	tests := []struct{ line, want string }{
		{ed, "key ssh-ed25519 " + fp + " alice@laptop"},
		{key("ssh-ed25519", ""), "key ssh-ed25519 " + fp},
		{`from="10.0.0.1",no-pty ` + ed, `key from="10.0.0.1",no-pty ssh-ed25519 ` + fp + " alice@laptop"},
		{"# a comment", "a line that is not a key"},
	}
	for _, tt := range tests {
		if got := keyPlan(tt.line, false); got != tt.want {
			t.Errorf("keyPlan(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
	if !strings.HasPrefix(fp, "SHA256:") || strings.HasSuffix(fp, "=") {
		t.Errorf("fingerprint %q is not in the form of ssh-keygen -l", fp)
	}
}

// spec: Modules/user and group
func TestKeyChanges(t *testing.T) {
	a, b, c := key("ssh-ed25519", "a"), key("ssh-ed25519", "b"), rsaKey(3072)+" c"
	blob, _ := base64.StdEncoding.DecodeString(strings.Fields(a)[1])
	fp := fingerprint(blob)
	tests := []struct {
		name      string
		cur, want []string
		secret    []bool
		changes   []string
	}{
		{"same", []string{a, b}, []string{a, b}, nil, nil},
		{"add", []string{a}, []string{a, b}, nil, []string{"add " + keyPlan(b, false)}},
		{"remove", []string{a, b, c}, []string{a}, nil, []string{"remove " + keyPlan(b, false), "remove " + keyPlan(c, false)}},
		{"order", []string{b, a}, []string{a, b}, nil, []string{"put the keys in order"}},
		{"duplicate", []string{a, a}, []string{a}, nil, []string{"remove a duplicate line"}},
		{"not a key", []string{"# x", a}, []string{a}, nil, []string{"remove a line that is not a key"}},
		{"secret options", nil, []string{`environment="TOKEN=abc" ` + a, `no-pty ` + c}, []bool{true, false},
			[]string{"add key (secret) ssh-ed25519 " + fp + " a", "add " + keyPlan(`no-pty `+c, false)}},
		{"secret without options", nil, []string{a}, []bool{true}, []string{"add " + keyPlan(a, false)}},
		{"new options of the same key", []string{`environment="TOKEN=old" ` + b}, []string{`environment="TOKEN=new" ` + a}, []bool{true},
			[]string{"add key (secret) ssh-ed25519 " + fp + " a", "remove key (secret) ssh-ed25519 " + fp + " b"}},
		{"old options of another key", []string{`environment="TOKEN=old" ` + c}, []string{`environment="TOKEN=new" ` + a}, []bool{true},
			[]string{"add key (secret) ssh-ed25519 " + fp + " a", "remove key (secret) ssh-rsa " + strings.Fields(keyPlan(c, false))[2] + " c"}},
		{"old options without a secret", []string{`no-pty ` + c}, []string{a}, []bool{false}, []string{"add " + keyPlan(a, false), "remove " + keyPlan(`no-pty `+c, false)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keyChanges(tt.cur, tt.want, tt.secret)
			if fmt.Sprint(got) != fmt.Sprint(tt.changes) {
				t.Errorf("got %q, want %q", got, tt.changes)
			}
		})
	}
}

// spec: Modules/user and group
func TestGroupRemovable(t *testing.T) {
	a := accounts{
		users:  []passwdEntry{{name: "root", gid: 0}, {name: "admin", uid: 1000, gid: 1000}, {name: "app", uid: 1001, gid: 1001}, {name: "u2", uid: 1003, gid: 1002}, {name: "u1", uid: 1002, gid: 1002}},
		groups: []groupEntry{{name: "root", gid: 0}, {name: "admin", gid: 1000}, {name: "app", gid: 1001}, {name: "shared", gid: 1002}, {name: "sudo", gid: 27, members: []string{"app", "admin", "root"}}, {name: "web", gid: 33, members: []string{"app"}}},
	}
	tests := []struct {
		name    string
		group   string
		login   uint32
		removed []string
		moved   []string
		want    string
	}{
		{"a group with members", "web", 1000, nil, nil, ""},
		{"a primary group", "shared", 1000, nil, nil, "shared is the primary group of u1, u2; remove them or change their group first"},
		{"a primary group of removed users", "shared", 1000, []string{"u1", "u2"}, nil, ""},
		{"a primary group of one removed user", "shared", 1000, []string{"u2"}, nil, "shared is the primary group of u1; remove them or change their group first"},
		{"a primary group of moved users", "shared", 1000, nil, []string{"u1", "u2"}, ""},
		{"a primary group of a removed and a moved user", "shared", 1000, []string{"u1"}, []string{"u2"}, ""},
		{"a primary group of one moved user", "shared", 1000, nil, []string{"u1"}, "shared is the primary group of u2; remove them or change their group first"},
		{"a group of the login user", "sudo", 1000, nil, nil, "the login user admin is in group sudo; removing it cuts off winch's access"},
		{"the primary group of the login user", "admin", 1000, nil, nil, "the login user admin is in group admin; removing it cuts off winch's access"},
		{"root as the login user", "root", 0, nil, nil, "root is the primary group of root; remove them or change their group first"},
		{"a group of root as the login user", "sudo", 0, nil, nil, ""},
		{"a login user that is not in passwd", "root", 4294967295, nil, nil, "root is the primary group of root; remove them or change their group first"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := Group{Name: tt.group, Absent: true}
			cur, _ := a.group(tt.group)
			got := ""
			if err := g.removable(a, cur, &State{LoginUID: tt.login, RemovedUsers: tt.removed, MovedUsers: tt.moved}); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("removable() = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Modules/user and group
func TestUserCheckLogin(t *testing.T) {
	admin := passwdEntry{name: "admin", uid: 1000, gid: 1000, home: "/home/admin", shell: "/bin/bash"}
	a := accounts{users: []passwdEntry{admin}, groups: []groupEntry{{name: "admin", gid: 1000}, {name: "sudo", gid: 27, members: []string{"admin"}}, {name: "adm", gid: 4}, {name: "docker", gid: 990, members: []string{"bob", "admin"}}}}
	tests := []struct {
		name  string
		user  User
		login uint32
		want  string
		// groups is whether the step adds groups to the login user.
		groups bool
	}{
		{"same fields", User{Name: "admin", UID: "1000", Home: "/home/admin", Shell: "/bin/bash"}, 1000, "", false},
		{"uid", User{Name: "admin", UID: "2000"}, 1000, "admin is the login user of this session; log in as another user to change its uid", false},
		{"shell", User{Name: "admin", Shell: "/usr/sbin/nologin"}, 1000, "admin is the login user of this session; log in as another user to change its shell", false},
		{"home", User{Name: "admin", Home: "/srv/admin"}, 1000, "admin is the login user of this session; log in as another user to change its home", false},
		{"group", User{Name: "admin", Group: "sudo"}, 1000, "admin is the login user of this session; log in as another user to change its group", false},
		{"a new group", User{Name: "admin", Group: "staff"}, 1000, "admin is the login user of this session; log in as another user to change its group", false},
		{"same group by gid", User{Name: "admin", Group: "1000"}, 1000, "", false},
		{"group of another user", User{Name: "admin", Group: "sudo"}, 0, "", false},
		{"uid of another user", User{Name: "admin", UID: "2000"}, 0, "", false},
		{"shell of another user", User{Name: "admin", Shell: "/usr/sbin/nologin"}, 0, "", false},
		{"home of another user", User{Name: "admin", Home: "/srv/admin"}, 0, "", false},
		{"same groups", User{Name: "admin", Groups: &[]string{"sudo", "docker"}}, 1000, "", false},
		{"add a group", User{Name: "admin", Groups: &[]string{"sudo", "docker", "adm"}}, 1000, "", true},
		{"remove a group", User{Name: "admin", Groups: &[]string{"docker", "adm"}}, 1000, "admin is the login user of this session; log in as another user to change its groups", false},
		{"no groups", User{Name: "admin", Groups: &[]string{}}, 1000, "admin is the login user of this session; log in as another user to change its groups", false},
		{"groups of another user", User{Name: "admin", Groups: &[]string{}}, 0, "", false},
		{"add a group to another user", User{Name: "admin", Groups: &[]string{"sudo", "docker", "adm"}}, 0, "", false},
		{"add_groups", User{Name: "admin", AddGroups: &[]string{"adm"}}, 1000, "", true},
		{"add_groups that it has", User{Name: "admin", AddGroups: &[]string{"sudo"}}, 1000, "", false},
		{"add_groups to another user", User{Name: "admin", AddGroups: &[]string{"adm"}}, 0, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			if err := tt.user.checkLogin(a, admin, tt.login); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("checkLogin() = %q, want %q", got, tt.want)
			}
			if got := tt.user.loginGroups != nil; got != tt.groups {
				t.Errorf("loginGroups set = %t, want %t", got, tt.groups)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (a groups change of the login
// user)
func TestUserUndo(t *testing.T) {
	a := accounts{users: []passwdEntry{{name: "admin", uid: 1000}}, groups: []groupEntry{{name: "sudo", members: []string{"admin"}}, {name: "docker"}}}
	tests := []struct {
		name string
		have []groupEntry
		user User
		want string
	}{
		{"back to the old groups", a.groups, User{Name: "admin", Groups: &[]string{"sudo", "docker"}}, `{"name":"admin","groups":["sudo"]}`},
		{"back to no groups", []groupEntry{{name: "docker"}}, User{Name: "admin", Groups: &[]string{"docker"}}, `{"name":"admin","groups":[]}`},
		{"no change", a.groups, User{Name: "admin", Groups: &[]string{"sudo"}}, "null"},
		{"add_groups", a.groups, User{Name: "admin", AddGroups: &[]string{"docker"}}, `{"name":"admin","groups":["sudo"]}`},
		{"add_groups without a change", a.groups, User{Name: "admin", AddGroups: &[]string{"sudo"}}, "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := tt.user
			if err := u.checkLogin(accounts{users: a.users, groups: tt.have}, a.users[0], 1000); err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(u.Undo())
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("Undo = %s, want %s", got, tt.want)
			}
		})
	}
}

// spec: Modules/user and group
func TestUserProcesses(t *testing.T) {
	proc := t.TempDir()
	status := map[string]string{
		"1":    "Name:\tsystemd\nUid:\t0\t0\t0\t0\n",
		"20":   "Name:\tsleep\nUid:\t2200\t2200\t2200\t2200\n",
		"21":   "Name:\tsleep\nUid:\t2200\t2200\t2200\t2200\n",
		"30":   "Name:\tsetuid\nUid:\t1000\t2200\t2200\t2200\n",
		"40":   "Name:\tsaved\nUid:\t1000\t1000\t2200\t1000\n",
		"50":   "Name:\tfs\nUid:\t1000\t1000\t1000\t2200\n",
		"self": "Name:\tself\nUid:\t2200\t2200\t2200\t2200\n",
	}
	for pid, s := range status {
		if err := os.Mkdir(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/", filepath.Join(proc, pid, "root")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "status"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// usermod skips a process in another root, such as a container.
	if err := os.MkdirAll(filepath.Join(proc, "70"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(proc, "70", "root")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "70", "status"), []byte("Name:\tcontainer\nUid:\t2200\t2200\t2200\t2200\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A process that ends during the read has no status.
	if err := os.Mkdir(filepath.Join(proc, "60"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := userProcesses(proc, 2200)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"saved", "setuid", "sleep"}; !reflect.DeepEqual(got, want) {
		t.Errorf("userProcesses() = %q, want %q", got, want)
	}
}

// spec: Modules/user and group
func TestCheckShell(t *testing.T) {
	dir := t.TempDir()
	exe, plain, link := filepath.Join(dir, "exe"), filepath.Join(dir, "plain"), filepath.Join(dir, "link")
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("exe", link); err != nil {
		t.Fatal(err)
	}
	plainLink := filepath.Join(dir, "plain-link")
	if err := os.Symlink("plain", plainLink); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		shell, note, err string
	}{
		{exe, "", ""},
		{link, "", ""},
		{filepath.Join(dir, "missing"), " (does not exist yet)", ""},
		{plain, "", "shell " + plain + " is not an executable file"},
		{dir, "", "shell " + dir + " is not an executable file"},
		{plainLink, "", "shell " + plainLink + " is not an executable file"},
	}
	for _, tt := range tests {
		note, err := checkShell(tt.shell)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if note != tt.note || got != tt.err {
			t.Errorf("checkShell(%s) = %q, %q; want %q, %q", tt.shell, note, got, tt.note, tt.err)
		}
	}
}

// spec: Modules/user and group
func TestUserCheckNewSystemHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "svc")
	u := User{Name: "wtsvc", System: true, Home: home}
	res, _, _, err := u.checkNew(accounts{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "home " + home + " (owner wtsvc, group wtsvc, mode 0700)"; !slices.Contains(res.Changes, want) {
		t.Errorf("changes = %q, want %q", res.Changes, want)
	}
	if !slices.Contains(u.account, "-M") || slices.Contains(u.account, "-m") || u.mkHome != home {
		t.Errorf("account = %q, mkHome = %q; want useradd -M and mkHome %s", u.account, u.mkHome, home)
	}
}

// spec: Modules/user and group
func TestUserCheckExistingGroups(t *testing.T) {
	alice := passwdEntry{name: "alice", uid: 1000, gid: 1000, home: noHome}
	a := accounts{users: []passwdEntry{alice}, groups: []groupEntry{{name: "alice", gid: 1000}, {name: "adm", gid: 4, members: []string{"alice"}}, {name: "wtgrp", gid: 1001}}}
	tests := []struct {
		name    string
		user    User
		changes []string
		account []string
	}{
		{"add_groups", User{Name: "alice", AddGroups: &[]string{"wtgrp", "adm"}}, []string{"add to group wtgrp"}, []string{"usermod", "-a", "-G", "wtgrp", "alice"}},
		{"add_groups that it has", User{Name: "alice", AddGroups: &[]string{"adm"}}, nil, nil},
		{"no add_groups", User{Name: "alice", AddGroups: &[]string{}}, nil, nil},
		{"groups", User{Name: "alice", Groups: &[]string{"wtgrp"}}, []string{"add to group wtgrp", "remove from group adm"}, []string{"usermod", "-G", "wtgrp", "alice"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _, _, err := tt.user.checkExisting(a, alice, &State{})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(res.Changes, tt.changes) || !slices.Equal(tt.user.account, tt.account) {
				t.Errorf("changes = %q, account = %q; want %q, %q", res.Changes, tt.user.account, tt.changes, tt.account)
			}
		})
	}
}

// spec: Modules/user and group
func TestOwnGroup(t *testing.T) {
	a := accounts{
		users: []passwdEntry{
			{name: "root", uid: 0, gid: 0},
			{name: "alice", uid: 1000, gid: 1000},
			{name: "bob", uid: 1001, gid: 1001},
			{name: "carol", uid: 1002, gid: 1003},
		},
		groups: []groupEntry{
			{name: "alice", gid: 1000},
			{name: "bob", gid: 1001, members: []string{"bob"}},
			{name: "users", gid: 100},
			{name: "shared", gid: 1003},
			{name: "dev", gid: 1004, members: []string{"alice"}},
			{name: "team", gid: 1005, members: []string{"alice", "bob"}},
		},
	}
	tests := []struct {
		name  string
		user  string
		gid   uint32
		group string
		owner string
		want  bool
	}{
		{"private group", "alice", 1000, "alice", "alice", true},
		{"private group of a root home", "alice", 1000, "alice", "root", true},
		{"private group that lists the owner", "bob", 1001, "bob", "bob", true},
		{"private group that lists the user of a root home", "bob", 1001, "bob", "root", false},
		{"group without members", "alice", 100, "alice", "alice", false},
		{"primary group of another user", "alice", 1003, "shared", "alice", false},
		{"listed group of the owner only", "alice", 1004, "alice", "alice", true},
		{"listed group with two members", "alice", 1005, "alice", "alice", false},
		{"primary group after the step", "alice", 100, "users", "alice", true},
		{"old primary group after the step", "alice", 1000, "users", "alice", false},
		{"missing group", "alice", 1234, "alice", "alice", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Name: tt.user}
			if got := u.ownGroup(a, tt.gid, tt.group, tt.owner); got != tt.want {
				t.Errorf("ownGroup = %v, want %v", got, tt.want)
			}
		})
	}
}

// spec: Modules/user and group
func TestSSHDSpec(t *testing.T) {
	tests := []struct {
		conn, want, wantErr string
	}{
		{"10.0.2.2 51234 10.0.2.15 22", "user=wtalice,host=10.0.2.2,addr=10.0.2.2,laddr=10.0.2.15,lport=22", ""},
		{"2001:db8::1 40000 2001:db8::2 2222", "user=wtalice,host=2001:db8::1,addr=2001:db8::1,laddr=2001:db8::2,lport=2222", ""},
		{"", "", `SSH_CONNECTION "" is not a client address and port and a local address and port`},
		{"10.0.2.2 51234 10.0.2.15", "", `SSH_CONNECTION "10.0.2.2 51234 10.0.2.15" is not`},
		{"10.0.2.2,x 51234 10.0.2.15 22", "", `SSH_CONNECTION "10.0.2.2,x 51234 10.0.2.15 22" is not`},
	}
	for _, tt := range tests {
		got, err := sshdSpec("wtalice", tt.conn)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("sshdSpec(%q) error = %v, want %q", tt.conn, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("sshdSpec(%q) = %q, %v, want %q", tt.conn, got, err, tt.want)
		}
	}
}

// spec: Modules/user and group
func TestPasswordChange(t *testing.T) {
	tests := []struct{ cur, want, line string }{
		{"$6$a$old", "!$6$a$old", "lock the password"},
		{"$6$a$old", "!", "lock the password"},
		{"$6$a$old", "*", "lock the password"},
		{"$6$a$old", "!$6$a$new", "change password"},
		{"!$6$a$old", "$6$a$old", "unlock the password"},
		{"!$6$a$old", "$6$a$new", "change password"},
		{"*", "$6$a$new", "change password"},
		{"!!", "!", "change password"},
		{"$6$a$old", "$6$a$new", "change password"},
	}
	for _, tt := range tests {
		if got := passwordChange(tt.cur, tt.want); got != tt.line {
			t.Errorf("passwordChange(%q, %q) = %q, want %q", tt.cur, tt.want, got, tt.line)
		}
	}
}
