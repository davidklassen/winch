package yamlx

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
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

var decodeCases = []struct {
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
	{"unknown-tag", "name: !$6$abc$def\n"},
	{"validate", "name: a\ncount: -11\n"},
	{"self-alias", "name: a\ntags: &t [*t]\n"},
	{"hex", "name: a\ncount: 0x1f\n"},
	{"signed", "name: a\ncount: -5\n"},
	{"many-errors", "name: 1\nenabled: no\nfoo: 1\n"},
}

// spec: YAML
func TestDecode(t *testing.T) {
	for _, tt := range decodeCases {
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

// spec: Modules/firewall (one port or a list of ports)
func TestInts(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"one", "ports: 22\n", `[22]`},
		{"list", "ports: [22, 80]\n", `[22 80]`},
		{"string", "ports: ssh\n", `t.yaml:1:8: ports: expected an integer, got the string "ssh"`},
		{"map", "ports: {a: b}\n", `t.yaml:1:8: ports: expected an integer or a list of integers, got a map`},
		{"string in list", "ports: [22, ssh]\n", `t.yaml:1:13: ports: expected an integer, got the string "ssh"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse("t.yaml", []byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			var d struct {
				Ports Ints `yaml:"ports"`
			}
			got := ""
			if err := Decode(n, &d); err != nil {
				got = err.Error()
			} else {
				got = fmt.Sprint([]int(d.Ports))
			}
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// spec: YAML
func TestIntRange(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"max", "x: 9223372036854775807\n", "9223372036854775807"},
		{"min", "x: -9223372036854775808\n", "-9223372036854775808"},
		{"above max", "x: 9223372036854775808\n", "t.yaml:1:4: the integer 9223372036854775808 is out of range (-9223372036854775808 to 9223372036854775807); quote it to make it a string"},
		{"below min", "x: -9223372036854775809\n", "t.yaml:1:4: the integer -9223372036854775809 is out of range (-9223372036854775808 to 9223372036854775807); quote it to make it a string"},
		{"hex above max", "x: 0x8000000000000000\n", "t.yaml:1:4: the integer 0x8000000000000000 is out of range (-9223372036854775808 to 9223372036854775807); quote it to make it a string"},
		{"key above max", "9223372036854775808: a\n", "t.yaml:1:1: the integer 9223372036854775808 is out of range (-9223372036854775808 to 9223372036854775807); quote it to make it a string"},
		{"quoted", "x: '9223372036854775808'\n", "9223372036854775808"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse("t.yaml", []byte(tt.yaml))
			got := ""
			if err != nil {
				got = err.Error()
			} else {
				got = fmt.Sprint(Value(n.Pairs[0].Value))
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
		{"tpl", "x: !tpl '{{ .host.name }}'\n", `!tpl "{{ .host.name }}"`},
		{"tpl on a list", "x: !tpl [a]\n", `t.yaml:1:4: the !tpl tag needs a string, got a list`},
		{"tpl on a map", "x: !tpl {a: b}\n", `t.yaml:1:4: the !tpl tag needs a string, got a map`},
		{"other tag", "x: !foo a\n", `t.yaml:1:4: unknown tag; the tags are !expr, !tpl, and !secret; quote a value that starts with "!"`},
		{"str", "x: !!str 10\n", ` "10"`},
		{"tag on a key", "!expr x: a\n", `t.yaml:1:1: a map key cannot have the tag "!expr"`},
		{"unknown tag on a key", "!$6$abc$def x: a\n", `t.yaml:1:1: a map key cannot have a tag; quote a key that starts with "!"`},
		{"double-bang hash", "x: !!$6$abc$def\n", `t.yaml:1:4: unknown tag; the tags are !expr, !tpl, and !secret; quote a value that starts with "!"`},
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

// spec: Templates and expressions ("Any module argument can be a template or an expression")
func TestDecodeLazy(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"static", "name: a\ncount: 3\n", `name="a" count=3 tags=[]`},
		{"static runs Validate", "name: a\ncount: -11\n", `t.yaml:2:8: count: must not be less than -10`},
		{"tagged required key", "name: !tpl '{{ .x }}'\ncount: -11\n", `name="" count=-11 tags=[]`},
		{"tagged list item", "name: a\ntags: [x, !expr y]\n", `name="a" count=0 tags=["x" ""]`},
		{"unknown key", "name: !expr x\nnmae: b\n", `t.yaml:2:1: unknown key "nmae"; did you mean "name"?`},
		{"static type error", "name: !expr x\ncount: a\n", `t.yaml:2:8: count: expected an integer, got the string "a"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse("t.yaml", []byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			var d testDoc
			err = DecodeLazy(n, &d)
			got := fmt.Sprintf("name=%q count=%d tags=%q", d.Name, d.Count, d.Tags)
			if d.Tags == nil {
				got = fmt.Sprintf("name=%q count=%d tags=[]", d.Name, d.Count)
			}
			if err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// spec: Variables ("A value keeps the type YAML gives it")
func TestValue(t *testing.T) {
	n, err := Parse("t.yaml", []byte("a: 1\nb: 1.5\nc: x\nd: true\ne: [1, y]\nf: {k: v}\ng:\n"))
	if err != nil {
		t.Fatal(err)
	}
	v := Value(n)
	want := map[string]any{"a": 1, "b": 1.5, "c": "x", "d": true, "e": []any{1, "y"}, "f": map[string]any{"k": "v"}, "g": nil}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("Value = %#v, want %#v", v, want)
	}
	back, err := FromValue(v, Pos{File: "e", Line: 1, Col: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(Value(back), want) {
		t.Errorf("FromValue round trip = %#v", Value(back))
	}
	if _, err := FromValue(struct{}{}, Pos{File: "e", Line: 1, Col: 1}); err == nil {
		t.Error("FromValue of a struct: no error")
	}
	if l, err := FromValue([]string{"a"}, Pos{}); err != nil || l.Kind != List {
		t.Errorf("FromValue of []string = %v, %v", l, err)
	}
}

// spec: CLI/Errors
func TestSuggestSwap(t *testing.T) {
	if got := Suggest("web_titel", []string{"web_sites", "web_title"}); got != `; did you mean "web_title"?` {
		t.Errorf("Suggest = %q", got)
	}
}

// spec: Modules/file, dir, link
func TestNameOrID(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"name", "owner: www-data\n", `"www-data"`},
		{"integer", "owner: 999\n", `"999"`},
		{"quoted integer", "owner: \"0999\"\n", `"0999"`},
		{"quoted", "owner: \"999\"\n", `"999"`},
		{"leading zero", "owner: 0999\n", `"999"`},
		{"map", "owner: {a: b}\n", `t.yaml:1:8: owner: expected a string, got a map`},
		{"null", "owner:\n", `t.yaml:1:7: owner: expected a string, got null`},
		{"negative", "owner: -1\n", `t.yaml:1:8: owner: must be a name or a numeric ID, such as "www-data" or "999"`},
		{"float", "owner: 1.5\n", `t.yaml:1:8: owner: must be a name or a numeric ID, such as "www-data" or "999"`},
		{"hex", "owner: 0x3e7\n", `t.yaml:1:8: owner: must be a name or a numeric ID, such as "www-data" or "999"`},
		{"octal", "owner: 0o750\n", `t.yaml:1:8: owner: must be a name or a numeric ID, such as "www-data" or "999"`},
		{"plus sign", "owner: +999\n", `t.yaml:1:8: owner: must be a name or a numeric ID, such as "www-data" or "999"`},
		{"boolean", "owner: true\n", `t.yaml:1:8: owner: must be a name or a numeric ID, such as "www-data" or "999"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse("t.yaml", []byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			var d struct {
				Owner NameOrID `yaml:"owner"`
			}
			got := ""
			if err := Decode(n, &d); err != nil {
				got = err.Error()
			} else {
				got = fmt.Sprintf("%q", d.Owner)
			}
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// spec: Modules/file, dir, link
func TestNameOrIDFromValue(t *testing.T) {
	msg := `t.yaml:1:1: owner: must be a name or a numeric ID, such as "www-data" or "999"`
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"integer", 999, `"999"`},
		{"negative", -1, msg},
		{"float", 1.5, msg},
		{"boolean", true, msg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := FromValue(map[string]any{"owner": tt.value}, Pos{File: "t.yaml", Line: 1, Col: 1})
			if err != nil {
				t.Fatal(err)
			}
			var d struct {
				Owner NameOrID `yaml:"owner"`
			}
			got := ""
			if err := Decode(n, &d); err != nil {
				got = err.Error()
			} else {
				got = fmt.Sprintf("%q", d.Owner)
			}
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// spec: CLI/Errors
func TestPosWithoutLine(t *testing.T) {
	err := Errorf(Pos{File: "winch run: nam=htop"}, `unknown key "nam"`)
	if got := err.Error(); got != `winch run: nam=htop: unknown key "nam"` {
		t.Errorf("error = %q", got)
	}
}

// spec: CLI/Messages
func TestParseTab(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"a tab before a key", "a:\n\tb: 1\n", "t.yaml:2:1: a tab indents this line; YAML indents with spaces"},
		{"a tab after spaces", "a:\n  b:\n  \tc: 1\n", "t.yaml:3:3: a tab indents this line; YAML indents with spaces"},
		{"a tab below the line of the error", "a:\n  b: 1\n\tc: 2\n", "t.yaml:3:1: a tab indents this line; YAML indents with spaces"},
		{"a tab on line 1", "\ta: 1\n", "t.yaml:1:1: a tab indents this line; YAML indents with spaces"},
		{"a tab in a block scalar", "a: |\n  x\n\ty\n", "t.yaml:3:1: a tab indents this line; YAML indents with spaces"},
		{"no tab", "a: @x\n", "t.yaml:1:1: found character that cannot start any token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("t.yaml", []byte(tt.yaml))
			if err == nil || err.Error() != tt.want {
				t.Errorf("got  %v\nwant %s", err, tt.want)
			}
		})
	}
}

// spec: CLI/Messages
func TestFromValueKinds(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want string
	}{
		{"a function", func(string) ([]any, error) { return nil, nil }, `the expression gives a function; call it, such as match("web")`},
		{"a struct", struct{ ID string }{}, "the expression gives a set of fields; use one of them, such as facts.os.id"},
		{"a map with number keys", map[int]string{1: "a"}, "a map key must be a string"},
	}
	for _, tt := range tests {
		_, err := FromValue(tt.v, Pos{})
		if err == nil || err.Error() != tt.want {
			t.Errorf("%s: got %v, want %s", tt.name, err, tt.want)
		}
	}
}
