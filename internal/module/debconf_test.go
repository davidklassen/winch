package module

import (
	"reflect"
	"slices"
	"testing"
)

// spec: Modules/debconf
func TestDebconfValidate(t *testing.T) {
	const pq = "package: postfix\nquestion: postfix/main_mailer_type\n"
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"select", pq + "type: select\nvalue: Internet Site\n", ""},
		{"boolean", "package: unattended-upgrades\nquestion: unattended-upgrades/enable_auto_updates\ntype: boolean\nvalue: \"true\"\n", ""},
		{"empty string", pq + "type: string\nvalue: \"\"\n", ""},
		{"multiselect", pq + "type: multiselect\nvalue: a, b\n", ""},
		{"password", pq + "type: password\nvalue: x\n", ""},
		{"no value", pq + "type: string\n", `t.yaml:1:1: a debconf step needs value`},
		{"no type", pq + "value: x\n", `t.yaml:1:1: a debconf step needs type`},
		{"unknown type", pq + "type: note\nvalue: x\n", `t.yaml:3:7: type: "note" is not a type; use string, password, boolean, select, or multiselect`},
		{"boolean value", pq + "type: boolean\nvalue: yes\n", `t.yaml:4:8: value: a boolean answer is "true" or "false"`},
		{"boolean upper", pq + "type: boolean\nvalue: \"True\"\n", `t.yaml:4:8: value: a boolean answer is "true" or "false"`},
		{"unquoted boolean", pq + "type: boolean\nvalue: true\n", `t.yaml:4:8: value: expected a string, got the boolean true; quote the value to make it a string`},
		{"bad package", "package: Postfix\nquestion: postfix/x\ntype: string\nvalue: x\n", `t.yaml:1:10: package: "Postfix" is not a package name`},
		{"space in question", "package: postfix\nquestion: postfix/a b\ntype: string\nvalue: x\n", `t.yaml:2:11: question: has white space or a control character`},
		{"newline in value", pq + "type: string\nvalue: \"a\\nSET x y\"\n", `t.yaml:4:8: value: has a control character, such as a newline`},
		{"tab in value", pq + "type: string\nvalue: \"a\\tb\"\n", `t.yaml:4:8: value: has a control character, such as a newline`},
		{"no package", "question: postfix/x\ntype: string\nvalue: x\n", `t.yaml:1:1: a debconf step needs package`},
		{"empty question", "package: postfix\nquestion: \"\"\ntype: string\nvalue: x\n", `t.yaml:2:11: question: is empty`},
		{"unknown key", pq + "type: string\nvalue: x\nseen: true\n", `t.yaml:5:1: unknown key "seen"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Debconf{}, tt.yaml, tt.want) })
	}
}

func TestSplitChoices(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"No configuration, Internet Site, Local only", []string{"No configuration", "Internet Site", "Local only"}},
		{`a, b\, c, d`, []string{"a", "b, c", "d"}},
	}
	for _, tt := range tests {
		if got := splitChoices(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitChoices(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// spec: Modules/debconf
func TestSameAnswer(t *testing.T) {
	tests := []struct {
		typ, a, b string
		want      bool
	}{
		{"string", "a", "a", true},
		{"string", "a", "b", false},
		{"string", "a, b", "b, a", false},
		{"multiselect", "a, b", "b, a", true},
		{"multiselect", "a", "a, b", false},
		{"multiselect", "", "", true},
		{"boolean", "true", "false", false},
	}
	for _, tt := range tests {
		if got := sameAnswer(tt.typ, tt.a, tt.b); got != tt.want {
			t.Errorf("sameAnswer(%q, %q, %q) = %v, want %v", tt.typ, tt.a, tt.b, got, tt.want)
		}
	}
}

// spec: Modules/debconf; CLI/Messages
func TestDebconfInstalledNote(t *testing.T) {
	fakeCommand(t, "dpkg-query", "installed")
	var s said
	if err := (&Debconf{Package: "nginx"}).sayInstalled(t.Context(), &s); err != nil {
		t.Fatal(err)
	}
	want := []string{"nginx is installed, so the new answer has no effect until dpkg-reconfigure runs"}
	if !slices.Equal(s.notes, want) || s.warns != nil {
		t.Errorf("notes %q, warnings %q; want notes %q", s.notes, s.warns, want)
	}
}
