package module

import (
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
		{"no content", "path: /etc/motd\n", `t.yaml:1:1: content: a file needs content, or absent: true`},
		{"content and absent", "path: /x\ncontent: hi\nabsent: true\n", `t.yaml:2:10: content: absent: true takes no content`},
		{"mode and absent", "path: /x\nmode: \"0644\"\nabsent: true\n", `t.yaml:2:7: mode: absent: true takes no mode`},
		{"owner and absent", "path: /x\nowner: root\nabsent: true\n", `t.yaml:2:8: owner: absent: true takes no owner`},
		{"group and absent", "path: /x\ngroup: root\nabsent: true\n", `t.yaml:2:8: group: absent: true takes no group`},
		{"names with digits", "path: /x\ncontent: hi\nowner: user1\ngroup: \"2g\"\n", ""},
		{"numeric owner", "path: /x\ncontent: hi\nowner: \"1000\"\n", `t.yaml:3:8: owner: must be a user name, not a number`},
		{"numeric group", "path: /x\ncontent: hi\ngroup: \"50\"\n", `t.yaml:3:8: group: must be a group name, not a number`},
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
