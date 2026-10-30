package cli

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
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

Octal, in quotes: "0640". Without quotes, YAML reads it as a number.
With stock, the package gives the default. With copy_from, the source
gives it. A step without content has no default.
`},
		{"templates.has", `templates.has: function

has list v: true when list contains v. In an expression, use v in list.
`},
		{"file.path", `file.path: string, required

Absolute. The step creates missing parent directories, owned by root
with mode 0755.
`},
		{"file.content", `file.content: string

Literal text. A step without content, template, source, copy_from, or
stock sets only the owner, group, and mode that it gives, with no
defaults, of a file that exists. When that file is missing, the plan
says does not exist yet. Apply fails when it is still missing.
`},
		{"file.owner", `file.owner: name or ID, default root

A user name or a numeric ID. A step without content has no default.
`},
		{"firewall.allow", `firewall.allow: list of maps

Accepted traffic; the host drops the rest. It always accepts established
and related traffic, loopback, ICMP echo requests, the ICMPv6 types that
IPv6 needs, and DHCP replies. It drops invalid packets.

Keys of each element:
  tcp   integer or list of integers  -  ports
  udp   integer or list of integers  -  ports
  from  string or list of strings    -  source addresses or networks
`},
		{"firewall.allow.from", `firewall.allow.from: string or list of strings

Source addresses or networks. IPv4 and IPv6 are allowed. Without from,
the rule accepts every source.
`},
		{"step.notify", `step.notify: string or list of strings

Handlers to run after a change. Not a template or an expression. With
loop, notify fires once when any element changed. Run winch doc
handlers.
`},
		{"step.confirm_access", `step.confirm_access: boolean, default false

SSH check with rollback, for a service step. Only a service step can use
it, in steps or in handlers. A firewall step gets the same check without
it.

Before the step, the helper keeps the old state of each path that the
changed steps of the recipe wrote or removed in this run. It starts a
60-second rollback timer in a process of its own.

After the step, winch opens a new SSH connection and runs a command,
through sudo -n when the login user is not root. It tries twice, 5
seconds apart.

When both tries fail, the helper puts back the old files and runs
daemon-reload after a unit file. It reverses a start or a stop of the
step, and reloads or restarts the unit again. The host fails with the
error "no new SSH connection works: <error>; the old files are back".
When the session ends first, the helper rolls back at the session end.
When the helper is gone, the timer does it.

When a run ends before a notified handler with confirm_access ran, the
helper puts back the files of that handler at once. The next run applies
the change again.

A rollback puts back files only. It does not undo a change of a user or
a group.
`},
		{"pipeline.health", `pipeline.health: map

Check after a host changed in the stage. The gate runs on a host after
it finishes the stage, when the stage has a change on that host. The
plan marks it with * and does not run it. A gate that fails stays
pending on the host, and the next apply runs it.

Keys:
  command  string   required  must exit 0
  stable   integer  0         seconds the command keeps passing
  timeout  integer  60        seconds the gate has to pass
`},
		{"pipeline.stages.parallelism", `pipeline.stages.parallelism: integer

Maximum hosts at the same time. Hosts start in inventory order. The next
host starts when a host finishes the stage and its health gate passes. A
failure stops new hosts from starting. Running hosts finish the stage.
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
		{"key path of a topic", []string{"doc", "stages.parallelism"}, `winch doc: unknown topic or module "stages"; did you mean "pipeline.stages.parallelism"?`},
		{"key path of three topics", []string{"doc", "vars"}, `winch doc: unknown topic or module "vars"; did you mean "project.vars", "recipe.vars", or "step.vars"?`},
		{"key path of two topics", []string{"doc", "name"}, `winch doc: unknown topic or module "name"; did you mean "project.name" or "step.name"?`},
		{"topic name and key path", []string{"doc", "recipes"}, `winch doc: unknown topic or module "recipes"; did you mean "recipe" or "project.recipes"?`},
		{"topic name and key paths", []string{"doc", "steps"}, `winch doc: unknown topic or module "steps"; did you mean "step", "project.steps", "pipeline.steps", or "recipe.steps"?`},
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
func TestDocTopicKeyPaths(t *testing.T) {
	dir, h := t.TempDir(), fakehost.New()
	names := append(module.Names(), docTopics...)
	checked := 0
	for _, name := range docTopics {
		r := winch(t, dir, h, false, "", "doc", name)
		_, keys, ok := strings.Cut(r.out, "\nKeys:\n")
		if !ok {
			continue
		}
		keys, _, _ = strings.Cut(keys, "\n\n")
		for line := range strings.Lines(keys) {
			path := strings.Fields(line)[0]
			arg := name + "." + path
			r := winch(t, dir, h, false, "", "doc", arg)
			if r.code != exitOK || !strings.HasPrefix(r.out, arg+": ") {
				t.Errorf("winch doc %s: exit %d, stderr %q, stdout %q", arg, r.code, r.err, r.out)
			}
			if first, _, _ := strings.Cut(path, "."); !slices.Contains(names, first) {
				r := winch(t, dir, h, false, "", "doc", path)
				if !strings.Contains(r.err, strconv.Quote(arg)) {
					t.Errorf("winch doc %s does not suggest %s: stderr %q", path, arg, r.err)
				}
			}
			checked++
		}
	}
	if checked == 0 {
		t.Error("no topic page lists keys")
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
func TestDocTopicLayout(t *testing.T) {
	for _, name := range docTopics {
		r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc", name)
		if strings.Contains(r.out, "\n\n\n") {
			t.Errorf("winch doc %s has two empty lines in a row", name)
		}
		example := strings.Index(r.out, "\nExample:\n")
		for _, section := range []string{"\nKeys:\n", "\nFunctions:\n"} {
			if i := strings.Index(r.out, section); example >= 0 && i > example {
				t.Errorf("winch doc %s: %q comes after the example", name, strings.TrimSpace(section))
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

// secretExample is a !secret of a topic example, with its ciphertext cut
// short. The test encrypts a value for the age recipients of the example.
var (
	secretExample = regexp.MustCompile(`!secret \S+\.\.\.`)
	ageRecipient  = regexp.MustCompile(`age1[0-9a-z]+`)
)

// spec: CLI
func TestDocTopicExamples(t *testing.T) {
	for _, name := range docTopics {
		t.Run(name, func(t *testing.T) {
			r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc", name)
			if r.code != exitOK {
				t.Fatalf("exit %d, stderr %q", r.code, r.err)
			}
			files := map[string]string{}
			lines := strings.Split(r.out, "\n")
			for i := 0; i < len(lines); i++ {
				indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " "))]
				file, ok := strings.CutPrefix(lines[i], indent+"# ")
				if indent == "" || !ok {
					continue
				}
				if _, ok := files[file]; ok {
					t.Fatalf("two examples of %s", file)
				}
				var text strings.Builder
				// An empty line ends the file unless the file goes on after it.
				for i++; i < len(lines); i++ {
					line := lines[i]
					if line == "" && i+1 < len(lines) && strings.HasPrefix(lines[i+1], indent) && !strings.HasPrefix(lines[i+1], indent+"# ") {
						line = indent
					}
					if !strings.HasPrefix(line, indent) {
						break
					}
					text.WriteString(strings.TrimPrefix(line, indent) + "\n")
				}
				files[file] = text.String()
			}
			for file, text := range files {
				if !secretExample.MatchString(text) {
					continue
				}
				recipients, err := secret.ParseRecipients(ageRecipient.FindAllString(files["winch.yaml"], -1))
				if err != nil {
					t.Fatal(err)
				}
				ciphertext, err := secret.Encrypt("example", recipients)
				if err != nil {
					t.Fatal(err)
				}
				files[file] = secretExample.ReplaceAllLiteralString(text, "!secret "+ciphertext)
			}
			if name == "project" && (len(files) != 1 || !strings.Contains(files["winch.yaml"], "path: /etc/motd")) {
				t.Errorf("the minimal project is not one winch.yaml that writes /etc/motd: %v", slices.Collect(maps.Keys(files)))
			}
			if name == "workflow" {
				return
			}
			if len(files) == 0 {
				t.Fatal("the example names no file")
			}
			dir := vmtest.WriteProject(t, files)
			warnings, err := project.Validate(dir, "", nil)
			if err != nil || len(warnings) > 0 {
				t.Errorf("the examples do not load as a project: %v %v", err, warnings)
			}
		})
	}
}
