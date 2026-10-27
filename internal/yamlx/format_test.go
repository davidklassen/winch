package yamlx

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// testRank ranks the step keys of the format cases.
func testRank(key string) int {
	keys := []string{"name", "recipe", "vars", "when", "loop", "then", "confirm_access", "notify"}
	if i := slices.Index(keys, key); i >= 0 {
		return i
	}
	return 1
}

// formatSteps are the step paths of the format cases.
var formatSteps = map[string][]string{
	"recipe":   {"steps", "handlers.*"},
	"pipeline": {"stages.*.steps"},
}

func formatCases(t *testing.T) []string {
	t.Helper()
	ins, err := filepath.Glob("testdata/format/*.in.yaml")
	if err != nil || len(ins) == 0 {
		t.Fatalf("no format cases: %v", err)
	}
	var names []string
	for _, in := range ins {
		names = append(names, strings.TrimSuffix(filepath.Base(in), ".in.yaml"))
	}
	return names
}

func readCase(t *testing.T, name, ext string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata/format", name+ext))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// spec: Steps (winch fmt: indentation, key order, comments, blank lines,
// quoting)
func TestFormat(t *testing.T) {
	for _, name := range formatCases(t) {
		t.Run(name, func(t *testing.T) {
			got, err := Format(name+".yaml", readCase(t, name, ".in.yaml"), formatSteps[name], testRank)
			if err != nil {
				t.Fatal(err)
			}
			if want := readCase(t, name, ".out.yaml"); string(got) != string(want) {
				t.Errorf("got\n%s\nwant\n%s", got, want)
			}
		})
	}
}

// spec: Steps (winch fmt of its own output changes nothing)
func TestFormatIdempotent(t *testing.T) {
	for _, name := range formatCases(t) {
		t.Run(name, func(t *testing.T) {
			want := readCase(t, name, ".out.yaml")
			got, err := Format(name+".yaml", want, formatSteps[name], testRank)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("got\n%s\nwant\n%s", got, want)
			}
		})
	}
}

// plain is a YAML value with its tags, styles, and anchors, and with the
// keys of each map sorted.
func plain(n *yaml.Node) any {
	switch n.Kind {
	case yaml.DocumentNode:
		return plain(n.Content[0])
	case yaml.AliasNode:
		return "*" + n.Value
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = plain(n.Content[i+1])
		}
		return []any{n.Tag, n.Style, n.Anchor, m}
	case yaml.SequenceNode:
		var l []any
		for _, c := range n.Content {
			l = append(l, plain(c))
		}
		return []any{n.Tag, n.Style, n.Anchor, l}
	}
	return []any{n.Tag, n.Style, n.Anchor, n.Value}
}

// spec: Steps (winch fmt keeps comments, blank lines, and quoting); YAML
func TestFormatMeaning(t *testing.T) {
	for _, name := range formatCases(t) {
		t.Run(name, func(t *testing.T) {
			var in, out yaml.Node
			if err := yaml.Unmarshal(readCase(t, name, ".in.yaml"), &in); err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal(readCase(t, name, ".out.yaml"), &out); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(plain(&in), plain(&out)) {
				t.Error("the input and the output have different values")
			}
		})
	}
}

// spec: CLI/Errors
func TestFormatError(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"syntax", "a:\n  b: [1,\n", "x.yaml:2:1: "},
		{"two documents", "a: 1\n---\nb: 2\n", "x.yaml:2:1: a file holds one YAML document"},
		{"alias before its anchor", "steps:\n  - pkg: &p htop\n    name: *p\n", "x.yaml:2:1: cannot format the file without a change to its values"},
		{"complex key", "a:\n    ? b\n    : 1\n", "x.yaml:2:1: cannot format the file without a change to its values"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Format("x.yaml", []byte(tt.in), []string{"steps"}, testRank)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("error %v, want %q", err, tt.want)
			}
		})
	}
}

// spec: Steps (winch fmt)
func TestFormatLines(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{
			"commented-out item stays in its list",
			"steps:\n- apt:\n    pkg:\n      - a\n      # - b\n  name: x\n",
			"steps:\n  - name: x\n    apt:\n      pkg:\n        - a\n        # - b\n",
		},
		{
			"CRLF block scalar",
			"a:\r\n    lit: |\r\n        one\r\n\r\n        two\r\n    k: v\r\n",
			"a:\r\n  lit: |\r\n    one\r\n\r\n    two\r\n  k: v\r\n",
		},
		{
			"CRLF blank line in a step",
			"steps:\r\n- name: x\r\n\r\n  apt: y\r\n",
			"steps:\r\n  - name: x\r\n\r\n    apt: y\r\n",
		},
		{
			"kept blank lines of the last key",
			"steps:\n- apt: y\n  name: |+\n    x\n\n- name: b\n",
			"steps:\n  - name: |+\n      x\n\n    apt: y\n  - name: b\n",
		},
		{
			"double-quoted line that starts with #",
			"a:\n    b:\n        c: \"x \\\"\n          # y\"\n    d: 1\n",
			"a:\n  b:\n    c: \"x \\\"\n      # y\"\n  d: 1\n",
		},
		{
			"single-quoted line that starts with #",
			"a:\n    b:\n        c: 'x ''\n          # y'\n    d: 1\n",
			"a:\n  b:\n    c: 'x ''\n      # y'\n  d: 1\n",
		},
		{
			"comment after a block scalar",
			"a:\n    lit: |\n        x\n    # c\n    b: 1\n",
			"a:\n  lit: |\n    x\n  # c\n  b: 1\n",
		},
		{
			"empty line in a block scalar that moves right",
			"l:\n- |\n p\n\n q\n",
			"l:\n  - |\n    p\n\n    q\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Format("x.yaml", []byte(tt.in), []string{"steps"}, testRank)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Steps (winch fmt keeps comments and quoting); YAML
func TestSameFile(t *testing.T) {
	tests := []struct {
		name, a, b string
		want       bool
	}{
		{"key order", "a: 1\nb: 2\n", "b: 2\na: 1\n", true},
		{"value", "a: 1\n", "a: 2\n", false},
		{"quoting", "a: x\n", "a: 'x'\n", false},
		{"tag", "a: !tpl x\n", "a: !expr x\n", false},
		{"anchor", "a: &x 1\n", "a: &y 1\n", false},
		{"comment", "a: 1 # one\n", "a: 1 # two\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := parseRoot("x.yaml", []byte(tt.a))
			if err != nil {
				t.Fatal(err)
			}
			if got := sameFile(root, []byte(tt.b)); got != tt.want {
				t.Errorf("sameFile = %v, want %v", got, tt.want)
			}
		})
	}
}
