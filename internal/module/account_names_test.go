package module

import (
	"fmt"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/yamlx"
)

// spec: Modules/user and group; Modules/file, dir, link
func TestExistingAccountNames(t *testing.T) {
	for _, name := range []struct {
		value string
		valid bool
	}{
		{"root", true},
		{"Debian-exim", true},
		{"john.doe", true},
		{"_user.9-A", true},
		{strings.Repeat("a", 32), true},
		{"x+y", false},
		{"1user", false},
		{".user", false},
		{"-user", false},
		{"a:b", false},
		{"a/b", false},
		{"a b", false},
		{"a\tb", false},
		{"a\x01b", false},
		{"élise", false},
		{strings.Repeat("a", 33), false},
	} {
		t.Run(name.value, func(t *testing.T) {
			q := fmt.Sprintf("%q", name.value)
			for _, field := range []struct {
				name string
				mod  Module
				yaml string
			}{
				{"file owner", &File{}, "path: /x\nowner: " + q},
				{"file group", &File{}, "path: /x\ngroup: " + q},
				{"dir owner", &Dir{}, "path: /x\nowner: " + q},
				{"dir group", &Dir{}, "path: /x\ngroup: " + q},
				{"download owner", &Download{}, "url: https://example.com/a\nsha256: " + strings.Repeat("a", 64) + "\npath: /x\nowner: " + q},
				{"download group", &Download{}, "url: https://example.com/a\nsha256: " + strings.Repeat("a", 64) + "\npath: /x\ngroup: " + q},
				{"user name", &User{}, "name: " + q},
				{"user group", &User{}, "name: test\ngroup: " + q},
				{"user groups", &User{}, "name: test\ngroups: [" + q + "]"},
				{"group name", &Group{}, "name: " + q},
				{"cmd user", &Cmd{}, "command: 'true'\nuser: " + q},
			} {
				t.Run(field.name, func(t *testing.T) {
					n, err := yamlx.Parse("t.yaml", []byte(field.yaml))
					if err != nil {
						t.Fatal(err)
					}
					err = yamlx.Decode(n, field.mod)
					if (err == nil) != name.valid {
						t.Errorf("load %q: error %v, want valid=%v", name.value, err, name.valid)
					}
				})
			}
		})
	}
}
