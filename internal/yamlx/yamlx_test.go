package yamlx

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/davidklassen/winch/internal/golden"
)

type testHost struct {
	Name    string `yaml:",key"`
	Address string `yaml:"address"`
	Pos     Pos
}

type testDoc struct {
	Name    string `yaml:"name,required"`
	Enabled bool   `yaml:"enabled"`
	Count   int    `yaml:"count"`
	Mode    string `yaml:"mode"`
	ModePos Pos
	Note    *string    `yaml:"note"`
	Tags    []string   `yaml:"tags"`
	Hosts   []testHost `yaml:"hosts"`
	Pos     Pos
}

func (d *testDoc) Validate() error {
	if d.Count < -10 {
		return &FieldError{Field: "count", Msg: "must not be less than -10"}
	}
	return nil
}

// spec: YAML
func TestDecode(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"valid", "name: a\nenabled: true\ncount: 3\nmode: \"0644\"\nnote: hi\ntags: [x, y]\nhosts:\n  h2:\n    address: 10.0.0.2\n  h1: {}\n"},
		{"empty-host", "name: a\nhosts:\n  h1:\n"},
		{"unknown-key", "name: a\nenabeld: true\n"},
		{"unknown-key-far", "name: a\nzzzz: 1\n"},
		{"missing-key", "count: 1\n"},
		{"duplicate-key", "name: a\nname: b\n"},
		{"merge-key", "base: &b {count: 1}\nname: a\n<<: *b\n"},
		{"alias", "name: &n shared\nmode: *n\n"},
		{"yes-is-string", "name: a\nenabled: yes\n"},
		{"on-is-string", "name: a\nenabled: on\n"},
		{"True-is-string", "name: a\nenabled: True\n"},
		{"leading-zero-decimal", "name: a\ncount: 010\n"},
		{"octal", "name: a\ncount: 0o10\n"},
		{"unquoted-mode", "name: a\nmode: 0644\n"},
		{"quoted-number", "name: \"10\"\n"},
		{"null-name", "name:\n"},
		{"wrong-kind", "name: [a]\n"},
		{"two-documents", "name: a\n---\nname: b\n"},
		{"syntax", "name: a\n  bad: [\n"},
		{"unknown-tag", "name: !tpl x\n"},
		{"validate", "name: a\ncount: -11\n"},
		{"self-alias", "name: a\ntags: &t [*t]\n"},
		{"hex", "name: a\ncount: 0x1f\n"},
		{"signed", "name: a\ncount: -5\n"},
		{"many-errors", "name: 1\nenabled: no\nfoo: 1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeString(tt.yaml)
			golden.Assert(t, filepath.Join("testdata", tt.name+".golden"), []byte(got))
		})
	}
}

func decodeString(src string) string {
	n, err := Parse("test.yaml", []byte(src))
	if err != nil {
		return err.Error() + "\n"
	}
	var d testDoc
	if err := Decode(n, &d); err != nil {
		return err.Error() + "\n"
	}
	note := "<nil>"
	if d.Note != nil {
		note = *d.Note
	}
	return fmt.Sprintf("name=%q enabled=%v count=%d mode=%q (at %s) note=%s tags=%q pos=%s\nhosts=%+v\n",
		d.Name, d.Enabled, d.Count, d.Mode, d.ModePos, note, d.Tags, d.Pos, d.Hosts)
}

func TestErrorType(t *testing.T) {
	n, _ := Parse("f.yaml", []byte("nope: 1\n"))
	err := Decode(n, &testDoc{})
	e, ok := errors.AsType[*Error](err)
	if !ok {
		t.Fatalf("got %T, want *Error", err)
	}
	if e.Pos != (Pos{"f.yaml", 1, 1}) {
		t.Errorf("pos = %v", e.Pos)
	}
}

func TestSuggest(t *testing.T) {
	tests := []struct {
		name    string
		options []string
		want    string
	}{
		{"nginx_prot", []string{"nginx_port", "nginx_sites"}, `; did you mean "nginx_port"?`},
		{"fiel", []string{"file"}, `; did you mean "file"?`},
		{"zzzz", []string{"file"}, ""},
		{"x", nil, ""},
	}
	for _, tt := range tests {
		if got := Suggest(tt.name, tt.options); got != tt.want {
			t.Errorf("Suggest(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// spec: Modules/pkg
func TestStrings(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"one", "names: nginx\n", `["nginx"]`},
		{"list", "names: [a, b]\n", `["a" "b"]`},
		{"empty list", "names: []\n", `[]`},
		{"number", "names: 1\n", `t.yaml:1:8: names: expected a string, got the integer 1; quote the value to make it a string`},
		{"map", "names: {a: b}\n", `t.yaml:1:8: names: expected a string or a list of strings, got a map`},
		{"number in list", "names: [a, 2]\n", `t.yaml:1:12: names: expected a string, got the integer 2; quote the value to make it a string`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse("t.yaml", []byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			var d struct {
				Names Strings `yaml:"names"`
			}
			got := ""
			if err := Decode(n, &d); err != nil {
				got = err.Error()
			} else {
				got = fmt.Sprintf("%q", []string(d.Names))
			}
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// spec: Templates and expressions; YAML
func TestTags(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"expr", "x: !expr 'facts.os.id == \"debian\"'\n", `!expr "facts.os.id == \"debian\""`},
		{"expr keeps the text", "x: !expr 010\n", `!expr "010"`},
		{"expr on a list", "x: !expr [a]\n", `t.yaml:1:4: the !expr tag needs a string, got a list`},
		{"expr on a map", "x: !expr {a: b}\n", `t.yaml:1:4: the !expr tag needs a string, got a map`},
		{"tpl", "x: !tpl a\n", `t.yaml:1:4: unknown tag "!tpl"`},
		{"str", "x: !!str 10\n", ` "10"`},
		{"tag on a key", "!expr x: a\n", `t.yaml:1:1: a map key cannot have the tag "!expr"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse("t.yaml", []byte(tt.yaml))
			got := ""
			if err != nil {
				got = err.Error()
			} else {
				v := n.Pairs[0].Value
				got = fmt.Sprintf("%s %q", v.Tag, v.Value)
			}
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// spec: Templates and expressions
func TestTagInPlainField(t *testing.T) {
	n, err := Parse("t.yaml", []byte("name: !expr x\n"))
	if err != nil {
		t.Fatal(err)
	}
	err = Decode(n, &testDoc{})
	want := "t.yaml:1:7: name: !expr is not allowed here"
	if err == nil || err.Error() != want {
		t.Errorf("got %v, want %s", err, want)
	}
}
