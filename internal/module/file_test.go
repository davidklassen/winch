package module

import (
	"bytes"
	"encoding/json"
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
		{"unclean path", "path: /etc/../motd\ncontent: hi\n", `t.yaml:1:7: path: must be a clean path, such as "/motd"`},
		{"root path", "path: /\ncontent: hi\n", `t.yaml:1:7: path: must not be /`},
		{"no content", "path: /etc/motd\n", `t.yaml:1:1: content: a file needs content, template, or source, or absent: true`},
		{"template", "path: /x\ntemplate: site.tmpl\n", ""},
		{"source in a subdirectory", "path: /x\nsource: sieve/spam.sieve\n", ""},
		{"content and template", "path: /x\ncontent: hi\ntemplate: a.tmpl\n", `t.yaml:3:11: template: a file has only one of content, template, and source`},
		{"template and source", "path: /x\ntemplate: a.tmpl\nsource: a\n", `t.yaml:3:9: source: a file has only one of content, template, and source`},
		{"template and absent", "path: /x\ntemplate: a.tmpl\nabsent: true\n", `t.yaml:2:11: template: absent: true takes no template`},
		{"source and absent", "path: /x\nsource: a\nabsent: true\n", `t.yaml:2:9: source: absent: true takes no source`},
		{"absolute source", "path: /x\nsource: /etc/a\n", `t.yaml:2:9: source: must be a clean relative path, such as "a/b.conf"`},
		{"source with ..", "path: /x\nsource: ../a\n", `t.yaml:2:9: source: must be a clean relative path, such as "a/b.conf"`},
		{"source is .", "path: /x\nsource: .\n", `t.yaml:2:9: source: must be a clean relative path, such as "a/b.conf"`},
		{"content and source", "path: /x\ncontent: a\nsource: b\n", `t.yaml:3:9: source: a file has only one of content, template, and source`},
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

// spec: Modules/file, dir, link
func TestFileText(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		text bool
	}{
		{"text", []byte("a\n"), true},
		{"1 MiB", bytes.Repeat([]byte("a"), maxDiff), true},
		{"larger than 1 MiB", bytes.Repeat([]byte("a"), maxDiff+1), false},
		{"NUL", []byte("a\x00"), false},
		{"not UTF-8", []byte{0xff}, false},
		{"no content", nil, false},
	}
	for _, tt := range tests {
		f := &File{Path: "/x", Data: tt.data}
		if got := f.Text() != nil; got != tt.text {
			t.Errorf("%s: text = %v, want %v", tt.name, got, tt.text)
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
