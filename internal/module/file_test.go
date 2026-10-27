package module

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/davidklassen/winch/internal/yamlx"
)

// spec: Modules/file, dir, link
func TestFileValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"content", "path: /etc/motd\ncontent: hi\n", ""},
		{"empty content", "path: /etc/motd\ncontent: \"\"\n", ""},
		{"all fields", "path: /etc/motd\ncontent: hi\nowner: admin\ngroup: adm\nmode: \"0600\"\n", ""},
		{"four digit mode", "path: /x\ncontent: hi\nmode: \"1755\"\n", ""},
		{"absent", "path: /etc/motd\nabsent: true\n", ""},
		{"no path", "content: hi\n", `t.yaml:1:1: missing key "path"`},
		{"relative path", "path: etc/motd\ncontent: hi\n", `t.yaml:1:7: path: must be an absolute path`},
		{"dot dot path", "path: /etc/../motd\ncontent: hi\n", `t.yaml:1:7: path: ".." is not allowed; write the path without it`},
		{"trailing dot dot path", "path: /srv/app/..\ncontent: hi\n", `t.yaml:1:7: path: ".." is not allowed; write the path without it`},
		{"dot dot after a double slash", "path: /srv//../x\ncontent: hi\n", `t.yaml:1:7: path: ".." is not allowed; write the path without it`},
		{"name that starts with dot dot", "path: /srv/..b\ncontent: hi\n", ""},
		{"name of three dots", "path: /srv/...\ncontent: hi\n", ""},
		{"unclean path", "path: /etc//motd\ncontent: hi\n", `t.yaml:1:7: path: must be a clean path, such as "/etc/motd"`},
		{"root path", "path: /\ncontent: hi\n", `t.yaml:1:7: path: must not be /`},
		{"control character in path", "path: \"/etc/mo\\x7ftd\"\ncontent: hi\n", `t.yaml:1:7: path: has a control character`},
		{"no content", "path: /etc/motd\n", `t.yaml:1:1: content: a file needs content, template, source, copy_from, or stock, one of owner, group, and mode, or absent: true`},
		{"only mode", "path: /etc/gitea/app.ini\nmode: \"0640\"\n", ""},
		{"only owner", "path: /etc/gitea/app.ini\nowner: git\n", ""},
		{"only group", "path: /etc/shadow\ngroup: shadow\n", ""},
		{"validate without content", "path: /x\nmode: \"0640\"\nvalidate: nginx -t\n", `t.yaml:3:11: validate: a file without content takes no validate`},
		{"replace without content", "path: /x\nmode: \"0640\"\nreplace: true\n", `t.yaml:3:10: replace: a file without content takes no replace`},
		{"template", "path: /x\ntemplate: site.tmpl\n", ""},
		{"source in a subdirectory", "path: /x\nsource: sieve/spam.sieve\n", ""},
		{"content and template", "path: /x\ncontent: hi\ntemplate: a.tmpl\n", `t.yaml:3:11: template: a file has only one of content, template, source, copy_from, and stock`},
		{"template and source", "path: /x\ntemplate: a.tmpl\nsource: a\n", `t.yaml:3:9: source: a file has only one of content, template, source, copy_from, and stock`},
		{"template and absent", "path: /x\ntemplate: a.tmpl\nabsent: true\n", `t.yaml:2:11: template: absent: true takes no template`},
		{"source and absent", "path: /x\nsource: a\nabsent: true\n", `t.yaml:2:9: source: absent: true takes no source`},
		{"absolute source", "path: /x\nsource: /etc/a\n", `t.yaml:2:9: source: must be a clean relative path, such as "a/b.conf"`},
		{"source with ..", "path: /x\nsource: ../a\n", `t.yaml:2:9: source: must be a clean relative path, such as "a/b.conf"`},
		{"source is .", "path: /x\nsource: .\n", `t.yaml:2:9: source: must be a clean relative path, such as "a/b.conf"`},
		{"content and source", "path: /x\ncontent: a\nsource: b\n", `t.yaml:3:9: source: a file has only one of content, template, source, copy_from, and stock`},
		{"template with ./", "path: /x\ntemplate: ./a.tmpl\n", `t.yaml:2:11: template: must be a clean relative path, such as "a/b.conf"`},
		{"content and absent", "path: /x\ncontent: hi\nabsent: true\n", `t.yaml:2:10: content: absent: true takes no content`},
		{"mode and absent", "path: /x\nmode: \"0644\"\nabsent: true\n", `t.yaml:2:7: mode: absent: true takes no mode`},
		{"owner and absent", "path: /x\nowner: root\nabsent: true\n", `t.yaml:2:8: owner: absent: true takes no owner`},
		{"group and absent", "path: /x\ngroup: root\nabsent: true\n", `t.yaml:2:8: group: absent: true takes no group`},
		{"names with digits", "path: /x\ncontent: hi\nowner: user1\ngroup: \"2g\"\n", ""},
		{"numeric IDs", "path: /x\ncontent: hi\nowner: 999\ngroup: 999\n", ""},
		{"quoted numeric IDs", "path: /x\ncontent: hi\nowner: \"999\"\ngroup: \"50\"\n", ""},
		{"owner ID too large", "path: /x\ncontent: hi\nowner: 4294967295\n", `t.yaml:3:8: owner: an ID must be below 4294967295`},
		{"group ID too large", "path: /x\ncontent: hi\ngroup: \"4294967296\"\n", `t.yaml:3:8: group: an ID must be below 4294967295`},
		{"bad mode", "path: /x\ncontent: hi\nmode: \"644x\"\n", `t.yaml:3:7: mode: must be an octal mode such as "0644"`},
		{"long mode", "path: /x\ncontent: hi\nmode: \"07777\"\n", `t.yaml:3:7: mode: must be an octal mode such as "0644"`},
		{"validate", "path: /x\ncontent: hi\nvalidate: nginx -t\n", ""},
		{"validate and absent", "path: /x\nabsent: true\nvalidate: nginx -t\n", `t.yaml:3:11: validate: absent: true takes no validate`},
		{"replace", "path: /x\ncontent: hi\nreplace: true\n", ""},
		{"replace and absent", "path: /x\nabsent: true\nreplace: true\n", `t.yaml:3:10: replace: absent: true takes no replace`},
		{"empty validate", "path: /x\ncontent: hi\nvalidate: \"\"\n", `t.yaml:3:11: validate: must not be empty`},
		{"copy_from", "path: /etc/ssh/sshd_config\ncopy_from: /usr/share/openssh/sshd_config\n", ""},
		{"copy_from with attributes and validate", "path: /x\ncopy_from: /y\nmode: \"0600\"\nowner: admin\nvalidate: sshd -t\nreplace: true\n", ""},
		{"stock", "path: /etc/monit/monitrc\nstock: true\n", ""},
		{"stock with mode and validate", "path: /x\nstock: true\nmode: \"0600\"\nvalidate: monit -t\n", ""},
		{"stock false", "path: /x\nstock: false\n", `t.yaml:1:1: content: a file needs content, template, source, copy_from, or stock, one of owner, group, and mode, or absent: true`},
		{"content and stock", "path: /x\ncontent: a\nstock: true\n", `t.yaml:3:8: stock: a file has only one of content, template, source, copy_from, and stock`},
		{"source and copy_from", "path: /x\nsource: a\ncopy_from: /y\n", `t.yaml:3:12: copy_from: a file has only one of content, template, source, copy_from, and stock`},
		{"copy_from and stock", "path: /x\ncopy_from: /y\nstock: true\n", `t.yaml:3:8: stock: a file has only one of content, template, source, copy_from, and stock`},
		{"copy_from and absent", "path: /x\ncopy_from: /y\nabsent: true\n", `t.yaml:2:12: copy_from: absent: true takes no copy_from`},
		{"stock and absent", "path: /x\nstock: true\nabsent: true\n", `t.yaml:2:8: stock: absent: true takes no stock`},
		{"relative copy_from", "path: /x\ncopy_from: y\n", `t.yaml:2:12: copy_from: must be an absolute path`},
		{"unclean copy_from", "path: /x\ncopy_from: /y/\n", `t.yaml:2:12: copy_from: must be a clean path, such as "/y"`},
		{"copy_from with ..", "path: /x\ncopy_from: /y/../z\n", `t.yaml:2:12: copy_from: ".." is not allowed; write the path without it`},
		{"copy_from is path", "path: /x\ncopy_from: /x\n", `t.yaml:2:12: copy_from: is the path of the step itself`},
		{"unknown key", "path: /x\ncontnet: hi\n", `t.yaml:2:1: unknown key "contnet"; did you mean "content"?`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := yamlx.Parse("t.yaml", []byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if err := yamlx.Decode(n, &File{}); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// spec: Modules/file, dir, link; Remote execution/Helper
func TestFileJSON(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"text", []byte("hello\n")},
		{"binary", []byte{0, 0xff, 0xfe, '\n', 0x80}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{Path: "/x", Data: tt.data}
			var got File
			roundTrip(t, f, &got)
			if got.Data == nil || !bytes.Equal(got.Data, tt.data) {
				t.Errorf("data = %v, want %v", got.Data, tt.data)
			}
			var hashed File
			roundTrip(t, f.WithoutContent(), &hashed)
			if want := sha(tt.data); hashed.Data != nil || hashed.sum() != want {
				t.Errorf("without content: data %v, sum %s, want nil and %s", hashed.Data, hashed.sum(), want)
			}
		})
	}
}

func roundTrip(t *testing.T, in any, out any) {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

// spec: CLI/Output; Modules/file, dir, link
func TestFileText(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		reason string
	}{
		{"text", []byte("a\n"), ""},
		{"1 MiB", bytes.Repeat([]byte("a"), maxDiff), ""},
		{"larger than 1 MiB", bytes.Repeat([]byte("a"), maxDiff+1), "larger than 1 MiB"},
		{"NUL", []byte("a\x00"), "binary"},
		{"NUL and not UTF-8", []byte{0, 0xff}, "binary"},
		{"larger than 1 MiB with NUL", append(bytes.Repeat([]byte("a"), maxDiff), 0), "larger than 1 MiB"},
		{"not UTF-8", []byte("caf\xe9\n"), "not UTF-8"},
	}
	for _, tt := range tests {
		f := &File{Path: "/x", Data: tt.data}
		text, reason := f.Text()
		if reason != tt.reason {
			t.Errorf("%s: reason = %q, want %q", tt.name, reason, tt.reason)
		}
		if reason == "" && !bytes.Equal(text, tt.data) {
			t.Errorf("%s: text = %q", tt.name, text)
		}
	}
}

// spec: Modules/file, dir, link
func TestLookupNumericID(t *testing.T) {
	for _, lookup := range []func(string) (uint32, bool, error){lookupUser, lookupGroup} {
		id, ok, err := lookup("4242")
		if id != 4242 || !ok || err != nil {
			t.Errorf("lookup(%q) = %d, %t, %v; want 4242, true, nil", "4242", id, ok, err)
		}
	}
}

// spec: Modules/file, dir, link
func TestCheckNamesSpecialKind(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "p")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	// A socket path has a short length limit, which t.TempDir can pass on macOS.
	short, err := os.MkdirTemp("/tmp", "w")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	sock := filepath.Join(short, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	tests := []struct {
		path, want string
	}{
		{fifo, fifo + " is a named pipe, not a file"},
		{sock, sock + " is a socket, not a file"},
		{"/dev/null", "/dev/null is a character device, not a file"},
	}
	for _, tt := range tests {
		_, err := (&File{Path: tt.path, Absent: true}).Check(t.Context(), nil, nil)
		if err == nil || err.Error() != tt.want {
			t.Errorf("Check(%s) error = %v, want %q", tt.path, err, tt.want)
		}
	}
}

// spec: CLI/Output; Modules/file, dir, link
func TestCheckNamesWhyNoDiff(t *testing.T) {
	tests := []struct {
		name string
		old  []byte
		want string
	}{
		{"not UTF-8", []byte("caf\xe9\n"), "not UTF-8"},
		{"binary", []byte("a\x00b"), "binary"},
		{"larger than 1 MiB", bytes.Repeat([]byte("a"), maxDiff+1), "larger than 1 MiB"},
		{"larger than 1 MiB with NUL", append([]byte{0}, bytes.Repeat([]byte("a"), maxDiff)...), "larger than 1 MiB"},
	}
	for _, tt := range tests {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, tt.old, 0o644); err != nil {
			t.Fatal(err)
		}
		f := &File{Path: p, Data: []byte("new\n"), Mode: "0644",
			Owner: yamlx.NameOrID(strconv.Itoa(os.Getuid())), Group: yamlx.NameOrID(strconv.Itoa(os.Getgid()))}
		res, err := f.Check(t.Context(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.OldReason != tt.want || res.Changes != nil || res.Old != nil {
			t.Errorf("%s: old reason %q, changes %q, old %v; want %q, nil, nil", tt.name, res.OldReason, res.Changes, res.Old, tt.want)
		}
	}
}
