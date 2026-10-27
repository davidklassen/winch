package module

import (
	"encoding/base64"
	"encoding/binary"
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
		{"upper case", "name: Alice\n", `t.yaml:1:7: name: "Alice" is not a user name; a name has lower-case letters, digits, "_", and "-", and starts with a letter or "_"`},
		{"leading digit", "name: 1a\n", `t.yaml:1:7: name: "1a" is not a user name; a name has lower-case letters, digits, "_", and "-", and starts with a letter or "_"`},
		{"too long", "name: " + strings.Repeat("a", 33) + "\n", `t.yaml:1:7: name: has 33 characters; a name has at most 32`},
		{"uid name", "name: a\nuid: alice\n", `t.yaml:2:6: uid: must be a numeric ID, such as "1000"`},
		{"uid negative", "name: a\nuid: -1\n", `t.yaml:2:6: uid: must be a numeric ID, such as "1000"`},
		{"uid too large", "name: a\nuid: 4294967295\n", `t.yaml:2:6: uid: an ID must be below 4294967295`},
		{"bad group", "name: a\ngroup: \"a b\"\n", `t.yaml:2:8: group: "a b" is not a group name; a name has lower-case letters, digits, "_", and "-", and starts with a letter or "_"`},
		{"relative home", "name: a\nhome: var/a\n", `t.yaml:2:7: home: must be an absolute path`},
		{"unclean home", "name: a\nhome: /srv/app/\n", `t.yaml:2:7: home: must be a clean path, such as "/srv/app"`},
		{"dot dot home", "name: a\nhome: /srv/../app\n", `t.yaml:2:7: home: ".." is not allowed; write the path without it`},
		{"relative shell", "name: a\nshell: bash\n", `t.yaml:2:8: shell: must be an absolute path`},
		{"control character in home", "name: a\nhome: \"/home/a\\rb\"\n", `t.yaml:2:7: home: has a control character`},
		{"control character in shell", "name: a\nshell: \"/bin/sh\\n\"\n", `t.yaml:2:8: shell: has a control character`},
		{"absent", "name: a\nabsent: true\n", ""},
		{"absent with uid", "name: a\nabsent: true\nuid: 5\n", `t.yaml:3:6: uid: absent: true takes no uid`},
		{"absent with keys", "name: a\nabsent: true\nauthorized_keys: []\n", `t.yaml:3:18: authorized_keys: absent: true takes no authorized_keys`},
		{"keys", "name: a\nauthorized_keys:\n  - " + ed + "\n  - " + rsaKey(3072) + "\n  - " + key("ecdsa-sha2-nistp256", "a b c") + "\n", ""},
		{"no keys", "name: a\nauthorized_keys: []\n", ""},
		{"rsa 1024", "name: a\nauthorized_keys:\n  - " + rsaKey(1024) + "\n", ""},
		{"rsa 1023", "name: a\nauthorized_keys:\n  - " + ed + "\n  - " + rsaKey(1023) + "\n", `t.yaml:3:3: authorized_keys: element 2 is a 1023-bit RSA key; Debian 13's sshd rejects RSA keys under 1024 bits`},
		{"rsa without modulus", "name: a\nauthorized_keys:\n  - " + key("ssh-rsa", "") + "\n", `t.yaml:3:3: authorized_keys: element 1 is not a key: the key data is not an ssh-rsa key`},
		{"rsa modulus past the end", "name: a\nauthorized_keys:\n  - " + rsaKey(2048)[:len("ssh-rsa ")+40] + "\n", `t.yaml:3:3: authorized_keys: element 1 is not a key: the key data is not an ssh-rsa key`},
		{"dss", "name: a\nauthorized_keys:\n  - " + key("ssh-dss", "") + "\n", `t.yaml:3:3: authorized_keys: element 1 is an ssh-dss key; Debian 13's sshd rejects ssh-dss keys`},
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
		{"unknown key", "name: a\ngroups: [sudo]\n", `t.yaml:2:1: unknown key "groups"; did you mean "group"?`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &User{}, tt.yaml, tt.want) })
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
		{"bad name", "name: \"-x\"\n", `t.yaml:1:7: name: "-x" is not a group name; a name has lower-case letters, digits, "_", and "-", and starts with a letter or "_"`},
		{"gid name", "name: a\ngid: abc\n", `t.yaml:2:6: gid: must be a numeric ID, such as "1000"`},
		{"gid too large", "name: a\ngid: \"99999999999\"\n", `t.yaml:2:6: gid: an ID must be below 4294967295`},
		{"absent", "name: a\nabsent: true\n", `t.yaml:2:1: unknown key "absent"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Group{}, tt.yaml, tt.want) })
	}
}

func TestParsePasswd(t *testing.T) {
	data := "# a comment\nroot:x:0:0:root:/root:/bin/bash\n\nalice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\nsvc:x:999:999:::\n"
	got, err := parsePasswd("/etc/passwd", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := []passwdEntry{
		{name: "root", uid: 0, gid: 0, home: "/root", shell: "/bin/bash"},
		{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/bash"},
		// Empty fields are what login uses.
		{name: "svc", uid: 999, gid: 999, home: "/", shell: "/bin/sh"},
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
		if got := keyPlan(tt.line); got != tt.want {
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
	tests := []struct {
		name      string
		cur, want []string
		changes   []string
	}{
		{"same", []string{a, b}, []string{a, b}, nil},
		{"add", []string{a}, []string{a, b}, []string{"add " + keyPlan(b)}},
		{"remove", []string{a, b, c}, []string{a}, []string{"remove " + keyPlan(b), "remove " + keyPlan(c)}},
		{"order", []string{b, a}, []string{a, b}, []string{"put the keys in order"}},
		{"duplicate", []string{a, a}, []string{a}, []string{"remove a duplicate line"}},
		{"not a key", []string{"# x", a}, []string{a}, []string{"remove a line that is not a key"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keyChanges(tt.cur, tt.want)
			if fmt.Sprint(got) != fmt.Sprint(tt.changes) {
				t.Errorf("got %q, want %q", got, tt.changes)
			}
		})
	}
}

// spec: Modules/user and group
func TestUserCheckLogin(t *testing.T) {
	admin := passwdEntry{name: "admin", uid: 1000, gid: 1000, home: "/home/admin", shell: "/bin/bash"}
	tests := []struct {
		name  string
		user  User
		login uint32
		want  string
	}{
		{"same fields", User{Name: "admin", UID: "1000", Home: "/home/admin", Shell: "/bin/bash"}, 1000, ""},
		{"uid", User{Name: "admin", UID: "2000"}, 1000, "admin is the login user of this session; log in as another user to change its uid"},
		{"shell", User{Name: "admin", Shell: "/usr/sbin/nologin"}, 1000, "admin is the login user of this session; log in as another user to change its shell"},
		{"home", User{Name: "admin", Home: "/srv/admin"}, 1000, "admin is the login user of this session; log in as another user to change its home"},
		{"uid of another user", User{Name: "admin", UID: "2000"}, 0, ""},
		{"shell of another user", User{Name: "admin", Shell: "/usr/sbin/nologin"}, 0, ""},
		{"home of another user", User{Name: "admin", Home: "/srv/admin"}, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			if err := tt.user.checkLogin(admin, tt.login); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("checkLogin() = %q, want %q", got, tt.want)
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
