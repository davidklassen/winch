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
		{"index", []string{"doc"}},
		{"file", []string{"doc", "file"}},
		{"unit", []string{"doc", "unit"}},
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

// docTopics are the topics of winch doc, in index order.
var docTopics = []string{"project", "inventory", "pipeline", "recipe", "step", "handlers", "variables", "templates", "expressions", "facts", "secrets", "workflow"}

// spec: CLI
func TestDocFunctions(t *testing.T) {
	for _, topic := range project.Topics() {
		if len(topic.Functions) == 0 {
			continue
		}
		r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc", topic.Name)
		_, section, _ := strings.Cut(r.out, "\nFunctions:")
		for _, f := range topic.Functions {
			if !strings.Contains(section, "\n  "+f.Name+" ") {
				t.Errorf("winch doc %s does not list the function %s", topic.Name, f.Name)
			}
		}
	}
}

// spec: CLI
func TestDocOldTopics(t *testing.T) {
	for _, name := range []string{"values", "functions", "lockout", "plan"} {
		r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc", name)
		if r.code != exitInvalid {
			t.Errorf("winch doc %s: exit %d, want %d", name, r.code, exitInvalid)
		}
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
		{"templates.has", "templates.has: function\n\nhas list v: true when list contains v. In an expression, use v in list.\n"},
		{"file.path", "file.path: string, required\n\nThe absolute path of the file. The step creates missing parent\ndirectories, owned by root with mode 0755.\n"},
		{"file.content", "file.content: string\n\nThe content of the file, as a string. A step without content, template,\nsource, copy_from, or stock sets only the owner, group, and mode that it\ngives, with no defaults, of a file that exists. When that file is\nmissing, the plan says does not exist yet, and apply fails when it is\nstill missing.\n"},
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
		{"step.notify", `step.notify: string or list of strings

A handler name, or a list of them. Not a template or an expression. With
loop, notify fires once when any element changed. Run winch doc handlers
for more.
`},
		{"pipeline.health", `pipeline.health: map

A health gate: a check that must pass on a host after it finishes the
stage, when the stage has a change on that host.

Keys:
  command  string   required  A command that must exit 0.
  stable   integer  0         The seconds that the command must keep exiting 0.
  timeout  integer  60        The seconds that the gate has to pass.
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
		{"unknown module", []string{"doc", "fiel"}, `winch doc: unknown topic or module "fiel"; did you mean "file"?`},
		{"unknown topic", []string{"doc", "projct"}, `winch doc: unknown topic or module "projct"; did you mean "project"?`},
		{"unknown key of a topic", []string{"doc", "step.wen"}, `winch doc: step has no key "wen"; did you mean "when"?`},
		{"key of a topic without keys", []string{"doc", "workflow.x"}, `winch doc: workflow has no key "x"`},
		{"unknown key", []string{"doc", "file.mdoe"}, `winch doc: file has no key "mdoe"; did you mean "mode"?`},
		{"unknown key of a list element", []string{"doc", "firewall.allow.tpc"}, `winch doc: firewall.allow has no key "tpc"; did you mean "tcp"?`},
		{"key of a key without keys", []string{"doc", "file.mode.x"}, `winch doc: file.mode has no key "x"`},
		{"unknown module of a key", []string{"doc", "fiel.mode"}, `winch doc: unknown topic or module "fiel"; did you mean "file"?`},
		{"two arguments", []string{"doc", "file", "dir"}, "winch: doc takes one topic, module, or key"},
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
	for _, name := range append(module.Names(), docTopics...) {
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

// spec: CLI
func TestDocTopicNames(t *testing.T) {
	r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc")
	_, after, _ := strings.Cut(r.out, "\nTopics:\n")
	section, _, _ := strings.Cut(after, "\n\n")
	var topics []string
	for line := range strings.Lines(section) {
		topics = append(topics, strings.Fields(line)[0])
	}
	if !slices.Equal(topics, docTopics) {
		t.Errorf("topics %v, want %v", topics, docTopics)
	}
	for _, name := range topics {
		if slices.Contains(module.Names(), name) {
			t.Errorf("topic %s is also a module; rename the topic", name)
		}
	}
}

// spec: CLI
func TestDocTopicExamples(t *testing.T) {
	for _, name := range docTopics {
		t.Run(name, func(t *testing.T) {
			r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc", name)
			if r.code != exitOK {
				t.Fatalf("exit %d, stderr %q", r.code, r.err)
			}
			files := map[string]string{}
			blocks := strings.Split(r.out, "```")
			if len(blocks)%2 == 0 {
				t.Fatal("an example has no end")
			}
			for i := 1; i < len(blocks); i += 2 {
				_, text, _ := strings.Cut(blocks[i], "\n")
				first, _, _ := strings.Cut(text, "\n")
				file, ok := strings.CutPrefix(first, "# ")
				if !ok {
					t.Fatalf("an example does not start with the name of its file:\n%s", text)
				}
				if _, ok := files[file]; ok {
					t.Fatalf("two YAML examples of %s", file)
				}
				files[file] = text
			}
			if len(files) == 0 {
				return
			}
			if name == "project" {
				var kinds []string
				for file := range files {
					kinds = append(kinds, strings.Split(file, "/")[0])
				}
				slices.Sort(kinds)
				if !slices.Equal(kinds, []string{"inventories", "pipelines", "winch.yaml"}) {
					t.Errorf("the minimal project has the files %v, want winch.yaml, one inventory, and one pipeline", kinds)
				}
			}
			dir := vmtest.WriteProject(t, files)
			warnings, err := project.Validate(dir, "", nil)
			if err != nil || len(warnings) > 0 {
				t.Errorf("the examples do not load as a project: %v %v", err, warnings)
			}
		})
	}
}
