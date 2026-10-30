package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/vmtest"
	"github.com/davidklassen/winch/internal/yamlx"
)

// spec: CLI
func TestDoc(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"modules", []string{"doc"}},
		{"file", []string{"doc", "file"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := winch(t, t.TempDir(), fakehost.New(), false, "", tt.args...)
			if r.code != exitOK || r.err != "" {
				t.Fatalf("exit %d, stderr %q", r.code, r.err)
			}
			golden.Assert(t, filepath.Join("testdata", "doc", tt.name+".golden"), []byte(r.out))
		})
	}
}

// spec: CLI
func TestDocKey(t *testing.T) {
	tests := []struct{ arg, want string }{
		{"file.mode", `file.mode: string, default 0644

The mode of the file, in octal, such as 0640. Quote it, or YAML reads it
as a number. With stock, the package gives the default. With copy_from,
the source gives it. A step without content has no default.
`},
		{"file.path", "file.path: string, required\n\nThe absolute path of the file.\n"},
		{"file.content", "file.content: string\n\nThe content of the file, as a string. A step without content, template,\nsource, copy_from, or stock sets only the owner, group, and mode that it\ngives, with no defaults, of a file that exists.\n"},
		{"firewall.allow", `firewall.allow: list of maps

The rules of the traffic that the host accepts. The host drops other
traffic to it. It always accepts established and related traffic,
loopback, ICMP echo requests, the ICMPv6 types that IPv6 needs, and DHCP
replies. It drops invalid packets.

Keys of each element:
  tcp   integer or list of integers  -  A TCP port or a list of TCP ports.
  udp   integer or list of integers  -  A UDP port or a list of UDP ports.
  from  string or list of strings    -  An address or a network, or a list of them.
`},
		{"firewall.allow.from", `firewall.allow.from: string or list of strings

An address or a network, or a list of them. IPv4 and IPv6 are allowed.
Without from, the rule accepts every source.
`},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc", tt.arg)
			if r.code != exitOK || r.err != "" || r.out != tt.want {
				t.Errorf("exit %d, stderr %q, stdout\n%s\nwant\n%s", r.code, r.err, r.out, tt.want)
			}
		})
	}
}

// spec: CLI
func TestDocInvalid(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown module", []string{"doc", "fiel"}, `winch doc: unknown module "fiel"; did you mean "file"?`},
		{"unknown key", []string{"doc", "file.mdoe"}, `winch doc: file has no key "mdoe"; did you mean "mode"?`},
		{"unknown key of a list element", []string{"doc", "firewall.allow.tpc"}, `winch doc: firewall.allow has no key "tpc"; did you mean "tcp"?`},
		{"key of a key without keys", []string{"doc", "file.mode.x"}, `winch doc: file.mode has no key "x"`},
		{"unknown module of a key", []string{"doc", "fiel.mode"}, `winch doc: unknown module "fiel"; did you mean "file"?`},
		{"two arguments", []string{"doc", "file", "dir"}, "winch: doc takes one module or one key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := winch(t, t.TempDir(), fakehost.New(), false, "", tt.args...)
			if r.code != exitInvalid || r.out != "" || r.err != tt.want+"\n" {
				t.Errorf("exit %d, stdout %q, stderr %q, want %q", r.code, r.out, r.err, tt.want)
			}
		})
	}
}

// spec: CLI
func TestDocNoTrailingSpace(t *testing.T) {
	for _, name := range module.Names() {
		r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc", name)
		for i, line := range strings.Split(r.out, "\n") {
			if strings.TrimRight(line, " ") != line {
				t.Errorf("winch doc %s: line %d ends in a space: %q", name, i+1, line)
			}
		}
	}
}

// spec: CLI
func TestDocExamples(t *testing.T) {
	key, err := os.ReadFile(filepath.Join("..", "module", "testdata", "key.asc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range module.Names() {
		t.Run(name, func(t *testing.T) {
			d, _ := module.Reference(name)
			if d.Example == "" {
				t.Fatal("no example")
			}
			n, err := yamlx.Parse("example.yaml", []byte(d.Example))
			if err != nil || n.Kind != yamlx.List || len(n.Items) != 1 || !slices.ContainsFunc(n.Items[0].Pairs, func(p yamlx.Pair) bool { return p.Key == name }) {
				t.Errorf("the example is not one %s step: %v\n%s", name, err, d.Example)
			}
			steps := "  " + strings.ReplaceAll(strings.TrimSuffix(d.Example, "\n"), "\n", "\n  ") + "\n"
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":                "name: doc\nhosts:\n  web1: {}\nsteps:\n  - recipe: doc\n",
				"recipes/doc/recipe.yaml":   "steps:\n" + steps,
				"recipes/doc/files/key.asc": string(key),
			})
			warnings, err := project.Validate(dir, "", nil)
			if err != nil || len(warnings) > 0 {
				t.Errorf("the example does not load: %v %v\n%s", err, warnings, d.Example)
			}
		})
	}
}
