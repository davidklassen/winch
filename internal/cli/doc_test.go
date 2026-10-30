package cli

import (
	"bytes"
	"cmp"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/doc"
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
		{"remote", []string{"doc", "remote"}},
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
var docTopics = []string{"project", "inventory", "pipeline", "recipe", "step", "handlers", "variables", "templates", "expressions", "facts", "secrets", "workflow", "remote"}

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

Before the step, winch keeps the old state of each path that the changed
steps of the recipe wrote or removed in this run. It starts a 60-second
rollback timer in a process of its own.

After the step, winch opens a new SSH connection and runs a command,
through sudo -n when the login user is not root. It tries twice, 5
seconds apart.

When both tries fail, winch puts back the old files and runs
daemon-reload after a unit file. It reverses a start or a stop of the
step, and reloads or restarts the unit again. The host fails with the
error "no new SSH connection works: <error>; the old files are back".
When the SSH connection ends first, winch rolls back as it ends. When
the process of winch on the host is gone, the timer rolls back.

When a run ends before a notified handler with confirm_access ran, winch
puts back the files of that handler at once. The next run applies the
change again.

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
		{"json with a module", []string{"doc", "file", "--json"}, "winch: doc --json takes no topic, module, or key"},
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
	groups, _, _ := strings.Cut(r.out, "\nModules:\n")
	var topics []string
	for line := range strings.Lines(groups) {
		if strings.HasPrefix(line, "  ") {
			topics = append(topics, strings.Fields(line)[0])
		}
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
				// A comment with a space states the result of an example. It
				// names no file.
				file, ok := strings.CutPrefix(lines[i], indent+"# ")
				if indent == "" || !ok || strings.Contains(file, " ") {
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
			// The examples of workflow and remote are commands and an SSH
			// config.
			if name == "workflow" || name == "remote" {
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

// docJSON is the shape of winch doc --json.
type docJSON struct {
	Intro  string
	Groups []struct {
		Title  string
		Topics []docJSONTopic
	}
	Modules  []docJSONModule
	Commands []docJSONCommand
}

type docJSONTopic struct {
	Name, Line string
	Blocks     []docJSONBlock
	Keys       []docJSONKey
	Functions  []struct{ Name, Line, Text string }
}

type docJSONBlock struct {
	Type, Text string
	Ordered    bool
	Items      []string
	Rows       [][]string
}

type docJSONModule struct {
	Name, Line, Body, Example string
	Keys                      []docJSONKey
}

type docJSONKey struct {
	Name, Path, Type, Default string
	Required                  bool
	Line, Text                string
	Keys                      []docJSONKey
}

type docJSONCommand struct {
	Name, Summary string
	Usage         []string
	Description   []string
	Examples      []struct{ Comment, Command string }
	Flags         []struct{ Name, Value, Default, Text string }
	See           []string
}

// docColumns splits a table row of winch doc into its columns.
var docColumns = regexp.MustCompile(` {2,}`)

// docTable returns the rows of the table that starts after head in page.
func docTable(page, head string) [][]string {
	_, table, ok := strings.Cut(page, head)
	if !ok {
		return nil
	}
	table, _, _ = strings.Cut(table, "\n\n")
	var rows [][]string
	for line := range strings.Lines(table) {
		rows = append(rows, docColumns.Split(strings.TrimSpace(line), -1))
	}
	return rows
}

// docKeyRows returns the rows of a key table of keys, with nested keys by
// their path when nested is true.
func docKeyRows(prefix string, keys []docJSONKey, nested bool) [][]string {
	var rows [][]string
	for _, k := range keys {
		def := cmp.Or(k.Default, "-")
		if k.Required {
			def = "required"
		}
		row := []string{prefix + k.Name, k.Type, def}
		if k.Line != "" {
			row = append(row, k.Line)
		}
		rows = append(rows, row)
		if nested {
			rows = append(rows, docKeyRows(prefix+k.Name+".", k.Keys, true)...)
		}
	}
	return rows
}

// docSection returns the part of page after head up to the first of ends.
func docSection(page, head string, ends ...string) string {
	_, s, _ := strings.Cut(page, head)
	for _, end := range ends {
		s, _, _ = strings.Cut(s, end)
	}
	return s
}

func indentDoc(text string) string {
	var b strings.Builder
	for line := range strings.Lines(text) {
		if line != "\n" {
			line = "  " + line
		}
		b.WriteString(line)
	}
	return b.String()
}

func decodeDocJSON(t *testing.T) (docJSON, string) {
	t.Helper()
	r := winch(t, t.TempDir(), fakehost.New(), false, "", "doc", "--json")
	if r.code != exitOK || r.err != "" {
		t.Fatalf("exit %d, stderr %q", r.code, r.err)
	}
	dec := json.NewDecoder(strings.NewReader(r.out))
	dec.DisallowUnknownFields()
	var d docJSON
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("the output does not parse: %v", err)
	}
	if dec.More() {
		t.Fatal("the output has more than one JSON document")
	}
	return d, r.out
}

// checkDocKeys checks that winch doc <path> of each key in keys prints its
// type, default, text, and the table of its keys.
func checkDocKeys(t *testing.T, dir string, h *fakehost.Hosts, keys []docJSONKey) {
	t.Helper()
	for _, k := range keys {
		r := winch(t, dir, h, false, "", "doc", k.Path)
		head := k.Type
		switch {
		case k.Required:
			head += ", required"
		case k.Default != "":
			head += ", default " + k.Default
		}
		head = k.Path + ": " + head + "\n\n"
		if r.code != exitOK || !strings.HasPrefix(r.out, head) {
			t.Errorf("winch doc %s: exit %d, stdout %q, want the head %q", k.Path, r.code, r.out, head)
			continue
		}
		text := docSection(r.out, head, "\nKeys")
		if !slices.Equal(strings.Fields(text), strings.Fields(k.Text)) {
			t.Errorf("winch doc %s: text %q, JSON %q", k.Path, text, k.Text)
		}
		rows := docTable(r.out, "Keys of each element:\n")
		if rows == nil {
			rows = docTable(r.out, "\nKeys:\n")
		}
		if want := docKeyRows("", k.Keys, false); !slices.EqualFunc(rows, want, slices.Equal) {
			t.Errorf("winch doc %s: keys %q, JSON %q", k.Path, rows, want)
		}
		checkDocKeys(t, dir, h, k.Keys)
	}
}

// docBlockWords returns the words of the blocks before the example, with a
// heading as it shows on the page. The JSON joins the lines of a table cell,
// so the words of a table come from src, the blocks in the source, line by
// line as the page shows them.
func docBlockWords(blocks []docJSONBlock, src []doc.Block) []string {
	var words []string
	for i, b := range blocks {
		switch b.Type {
		case "heading":
			words = append(words, strings.Fields(b.Text+":")...)
		case "paragraph", "code":
			words = append(words, strings.Fields(b.Text)...)
		case "list":
			for i, item := range b.Items {
				marker := "-"
				if b.Ordered {
					marker = strconv.Itoa(i+1) + "."
				}
				words = append(words, marker)
				words = append(words, strings.Fields(item)...)
			}
		case "table":
			for _, row := range src[i].Rows {
				lines := make([][]string, len(row))
				n := 0
				for c, cell := range row {
					lines[c] = strings.Split(cell, "\n")
					n = max(n, len(lines[c]))
				}
				for l := range n {
					for c := range row {
						if l < len(lines[c]) {
							words = append(words, strings.Fields(lines[c][l])...)
						}
					}
				}
			}
		}
	}
	return words
}

// spec: CLI
func TestDocJSON(t *testing.T) {
	d, _ := decodeDocJSON(t)
	dir, h := t.TempDir(), fakehost.New()
	index := winch(t, dir, h, false, "", "doc").out
	if intro, _, _ := strings.Cut(index, "\n\n"); d.Intro == "" || strings.Join(strings.Fields(intro), " ") != d.Intro {
		t.Errorf("intro %q, index %q", d.Intro, index)
	}
	var topics []docJSONTopic
	for _, g := range d.Groups {
		var rows [][]string
		for _, tp := range g.Topics {
			rows = append(rows, []string{tp.Name, tp.Line})
		}
		if got := docTable(index, "\n"+g.Title+":\n"); g.Title == "" || !slices.EqualFunc(got, rows, slices.Equal) {
			t.Errorf("index group %q: %q, JSON %q", g.Title, got, rows)
		}
		topics = append(topics, g.Topics...)
	}
	var names []string
	for _, tp := range topics {
		names = append(names, tp.Name)
	}
	if !slices.Equal(names, docTopics) {
		t.Errorf("JSON topics %q, want %q", names, docTopics)
	}
	var moduleRows [][]string
	for _, m := range d.Modules {
		moduleRows = append(moduleRows, []string{m.Name, m.Line})
	}
	if rows := docTable(index, "\nModules:\n"); !slices.EqualFunc(rows, moduleRows, slices.Equal) {
		t.Errorf("index modules %q, JSON %q", rows, moduleRows)
	}

	sources := map[string][]doc.Block{}
	for _, tp := range project.Topics() {
		sources[tp.Name] = tp.Blocks
	}
	for _, tp := range topics {
		page := winch(t, dir, h, false, "", "doc", tp.Name).out
		head := tp.Name + ": " + tp.Line + "\n\n"
		if !strings.HasPrefix(page, head) {
			t.Errorf("winch doc %s: %q does not start with %q", tp.Name, page, head)
			continue
		}
		blocks := tp.Blocks
		var example string
		if n := len(blocks); n > 0 && blocks[n-1].Type == "example" {
			blocks, example = blocks[:n-1], blocks[n-1].Text
		}
		for _, b := range blocks {
			if !slices.Contains([]string{"heading", "paragraph", "list", "table", "code"}, b.Type) {
				t.Errorf("winch doc %s: block %q in the body", tp.Name, b.Type)
			}
			if strings.Contains(b.Text, "\n") && b.Type != "code" || slices.ContainsFunc(b.Items, func(s string) bool { return strings.Contains(s, "\n") }) {
				t.Errorf("winch doc %s: a line break in the text of a %s block: %+v", tp.Name, b.Type, b)
			}
		}
		body := docSection(page, head, "\nKeys:\n", "\nFunctions:\n", "\nExample:\n", "\nRun \"winch doc")
		src := sources[tp.Name]
		for i, b := range blocks {
			if b.Type != "table" {
				continue
			}
			var rows [][]string
			for _, row := range src[i].Rows {
				var cells []string
				for _, cell := range row {
					cells = append(cells, oneLine(cell))
				}
				rows = append(rows, cells)
			}
			if !slices.EqualFunc(b.Rows, rows, slices.Equal) {
				t.Errorf("winch doc %s: table %q, source %q", tp.Name, b.Rows, rows)
			}
		}
		if got, want := strings.Fields(body), docBlockWords(blocks, src); !slices.Equal(got, want) {
			t.Errorf("winch doc %s: body\n%s\nJSON\n%q", tp.Name, body, want)
		}
		if got := docSection(page, "\nExample:\n", "\nRun \"winch doc"); got != indentDoc(example) {
			t.Errorf("winch doc %s: example %q, JSON %q", tp.Name, got, example)
		}
		if rows, want := docTable(page, "\nKeys:\n"), docKeyRows("", tp.Keys, true); !slices.EqualFunc(rows, want, slices.Equal) {
			t.Errorf("winch doc %s: keys %q, JSON %q", tp.Name, rows, want)
		}
		var functions [][]string
		for _, f := range tp.Functions {
			functions = append(functions, []string{f.Name, f.Line})
			path := tp.Name + "." + f.Name
			r := winch(t, dir, h, false, "", "doc", path)
			head := path + ": function\n\n"
			if !strings.HasPrefix(r.out, head) || !slices.Equal(strings.Fields(r.out[len(head):]), strings.Fields(f.Text)) {
				t.Errorf("winch doc %s: %q, JSON %q", path, r.out, f.Text)
			}
		}
		if rows := docTable(page, "\nFunctions:\n"); !slices.EqualFunc(rows, functions, slices.Equal) {
			t.Errorf("winch doc %s: functions %q, JSON %q", tp.Name, rows, functions)
		}
		checkDocKeys(t, dir, h, tp.Keys)
	}

	for _, m := range d.Modules {
		page := winch(t, dir, h, false, "", "doc", m.Name).out
		head := m.Name + ": " + m.Line + "\n\n"
		if !strings.HasPrefix(page, head) {
			t.Errorf("winch doc %s: %q does not start with %q", m.Name, page, head)
			continue
		}
		if body := docSection(page, head, "Keys:\n"); !slices.Equal(strings.Fields(body), strings.Fields(m.Body)) {
			t.Errorf("winch doc %s: body %q, JSON %q", m.Name, body, m.Body)
		}
		if example := docSection(page, "\nExample:\n", "\nRun \"winch doc"); m.Example == "" || example != indentDoc(m.Example) {
			t.Errorf("winch doc %s: example %q, JSON %q", m.Name, example, m.Example)
		}
		if rows, want := docTable(page, "\nKeys:\n"), docKeyRows("", m.Keys, false); !slices.EqualFunc(rows, want, slices.Equal) {
			t.Errorf("winch doc %s: keys %q, JSON %q", m.Name, rows, want)
		}
		checkDocKeys(t, dir, h, m.Keys)
	}

	names = nil
	for _, c := range d.Commands {
		names = append(names, c.Name)
		checkDocCommand(t, dir, h, c)
	}
	// The commands come in the order of winch --help, each with its
	// subcommands in the order of its own help.
	main := winch(t, dir, h, false, "", "--help").out
	var want []string
	for _, row := range docTable(main, "\nCommands:\n") {
		want = append(want, row[0])
		sub := winch(t, dir, h, false, "", row[0], "--help").out
		for _, row2 := range docTable(sub, "\nCommands:\n") {
			want = append(want, row[0]+" "+row2[0])
		}
	}
	if len(want) == 0 || !slices.Equal(names, want) {
		t.Errorf("commands %q, want %q", names, want)
	}
}

// checkDocCommand checks that winch <command> --help shows each field of c.
func checkDocCommand(t *testing.T, dir string, h *fakehost.Hosts, c docJSONCommand) {
	t.Helper()
	r := winch(t, dir, h, false, "", append(strings.Fields(c.Name), "--help")...)
	help := r.out
	if r.code != exitOK || c.Summary == "" || !strings.HasPrefix(help, "winch "+c.Name+": "+c.Summary+"\n\n") {
		t.Errorf("winch %s --help: exit %d, the summary %q is not the first line:\n%s", c.Name, r.code, c.Summary, help)
		return
	}
	var examples []string
	for _, e := range c.Examples {
		if e.Comment == "" || e.Command == "" {
			t.Errorf("winch %s: example %q", c.Name, e)
		}
		examples = append(examples, "  # "+e.Comment+"\n  "+e.Command+"\n")
	}
	if got := docSection(help, "\nExamples:\n", "\n\n"); len(examples) == 0 || got+"\n" != strings.Join(examples, "") {
		t.Errorf("winch %s: examples %q, JSON %q", c.Name, got, examples)
	}
	usage := docSection(help, "\nUsage:\n", "\n\n")
	var usageLines []string
	for _, u := range c.Usage {
		usageLines = append(usageLines, "  "+u)
	}
	if len(c.Usage) == 0 || usage != strings.Join(usageLines, "\n") {
		t.Errorf("winch %s: usage %q, JSON %q", c.Name, usage, c.Usage)
	}
	// The description follows the usage up to the next section.
	_, rest, _ := strings.Cut(help, "\nUsage:\n"+usage+"\n\n")
	var description []string
	for para := range strings.SplitSeq(strings.TrimSuffix(rest, "\n"), "\n\n") {
		if strings.HasPrefix(para, "Flags:\n") || strings.HasPrefix(para, "Commands:\n") || strings.HasPrefix(para, "Run \"") || strings.HasPrefix(para, "See: ") {
			break
		}
		description = append(description, strings.Join(strings.Fields(para), " "))
	}
	if len(c.Description) == 0 || !slices.Equal(description, c.Description) {
		t.Errorf("winch %s: description %q, JSON %q", c.Name, description, c.Description)
	}
	var flags []string
	for _, f := range c.Flags {
		if !strings.HasPrefix(f.Name, "--") || f.Text == "" {
			t.Errorf("winch %s: flag %q", c.Name, f)
		}
		line := strings.Join(strings.Fields(f.Name+" "+f.Value+" "+f.Text), " ")
		if f.Default != "" {
			line += " default: " + f.Default
		}
		flags = append(flags, line)
	}
	var got []string
	for line := range strings.Lines(docSection(help, "\nFlags:\n", "\n\n")) {
		if strings.HasPrefix(line, "  --") || len(got) == 0 {
			got = append(got, "")
		}
		got[len(got)-1] = strings.TrimSpace(got[len(got)-1] + " " + strings.Join(strings.Fields(line), " "))
	}
	if !slices.Equal(got, flags) {
		t.Errorf("winch %s: flags %q, JSON %q", c.Name, got, flags)
	}
	var see []string
	if line := docSection(help, "\n\nSee: ", "\n"); line != "" {
		see = strings.Split(line, ", ")
	}
	if !slices.Equal(see, c.See) {
		t.Errorf("winch %s: see %q, JSON %q", c.Name, see, c.See)
	}
}

// spec: CLI
func TestDocJSONFields(t *testing.T) {
	_, out := decodeDocJSON(t)
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(top)); !slices.Equal(got, []string{"commands", "groups", "intro", "modules"}) {
		t.Errorf("top-level fields %q", got)
	}
	checkKeys := func(what string, obj map[string]json.RawMessage, want ...string) {
		t.Helper()
		if got := slices.Sorted(maps.Keys(obj)); !slices.Equal(got, want) {
			t.Errorf("%s fields %q, want %q", what, got, want)
		}
	}
	var cmds []map[string]json.RawMessage
	if err := json.Unmarshal(top["commands"], &cmds); err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds {
		checkKeys("command", c, "description", "examples", "flags", "name", "see", "summary", "usage")
		var examples, flags []map[string]json.RawMessage
		if json.Unmarshal(c["examples"], &examples) != nil || json.Unmarshal(c["flags"], &flags) != nil {
			t.Fatalf("command %s: examples or flags are not lists of objects", c["name"])
		}
		for _, e := range examples {
			checkKeys("example", e, "command", "comment")
		}
		for _, f := range flags {
			checkKeys("flag", f, "default", "name", "text", "value")
		}
	}
	var rawGroups []map[string]json.RawMessage
	if err := json.Unmarshal(top["groups"], &rawGroups); err != nil {
		t.Fatal(err)
	}
	for _, g := range rawGroups {
		checkKeys("group", g, "title", "topics")
		var topics []map[string]json.RawMessage
		if err := json.Unmarshal(g["topics"], &topics); err != nil {
			t.Fatal(err)
		}
		for _, tp := range topics {
			checkKeys("topic", tp, "blocks", "functions", "keys", "line", "name")
		}
	}
	var groups []struct {
		Topics []struct {
			Blocks []map[string]json.RawMessage
		}
	}
	if err := json.Unmarshal(top["groups"], &groups); err != nil {
		t.Fatal(err)
	}
	fields := map[string][]string{
		"heading":   {"text", "type"},
		"paragraph": {"text", "type"},
		"code":      {"text", "type"},
		"example":   {"text", "type"},
		"list":      {"items", "ordered", "type"},
		"table":     {"rows", "type"},
	}
	seen := map[string]bool{}
	for _, g := range groups {
		for _, tp := range g.Topics {
			for _, b := range tp.Blocks {
				var typ string
				_ = json.Unmarshal(b["type"], &typ)
				seen[typ] = true
				if got := slices.Sorted(maps.Keys(b)); !slices.Equal(got, fields[typ]) {
					t.Errorf("block %s fields %q, want %q", typ, got, fields[typ])
				}
			}
		}
	}
	if len(seen) != len(fields) {
		t.Errorf("block types %q, want each of %q", slices.Sorted(maps.Keys(seen)), slices.Sorted(maps.Keys(fields)))
	}
}

// spec: CLI
func TestDocJSONGolden(t *testing.T) {
	_, out := decodeDocJSON(t)
	var d struct {
		Groups  []struct{ Topics []json.RawMessage }
		Modules []json.RawMessage
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatal(err)
	}
	var topics []json.RawMessage
	for _, g := range d.Groups {
		topics = append(topics, g.Topics...)
	}
	tests := []struct {
		name  string
		items []json.RawMessage
	}{
		{"file", d.Modules},
		{"secrets", topics},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := slices.IndexFunc(tt.items, func(raw json.RawMessage) bool {
				var v struct{ Name string }
				return json.Unmarshal(raw, &v) == nil && v.Name == tt.name
			})
			if i < 0 {
				t.Fatalf("no %s in the JSON", tt.name)
			}
			var b bytes.Buffer
			if err := json.Indent(&b, tt.items[i], "", "  "); err != nil {
				t.Fatal(err)
			}
			b.WriteByte('\n')
			golden.Assert(t, filepath.Join("testdata", "doc", tt.name+".json.golden"), b.Bytes())
		})
	}
}

// docPages returns the argument of each page of winch doc: each topic but
// remote, each module, and each of their keys and functions.
func docPages() []string {
	var pages []string
	var add func(prefix string, keys []doc.Key)
	add = func(prefix string, keys []doc.Key) {
		for _, k := range keys {
			pages = append(pages, prefix+k.Name)
			add(prefix+k.Name+".", k.Keys)
		}
	}
	for _, t := range project.Topics() {
		if t.Name == "remote" {
			continue
		}
		pages = append(pages, t.Name)
		add(t.Name+".", t.Keys)
		add(t.Name+".", t.Functions)
	}
	for _, name := range module.Names() {
		d, _ := module.Reference(name)
		pages = append(pages, name)
		add(name+".", d.Keys)
	}
	return pages
}

// spec: CLI
func TestDocPages(t *testing.T) {
	dir, h := t.TempDir(), fakehost.New()
	var b strings.Builder
	for _, page := range docPages() {
		r := winch(t, dir, h, false, "", "doc", page)
		if r.code != exitOK || r.err != "" {
			t.Errorf("winch doc %s: exit %d, stderr %q", page, r.code, r.err)
		}
		b.WriteString("==> winch doc " + page + "\n" + r.out)
	}
	golden.Assert(t, filepath.Join("testdata", "doc", "pages.golden"), []byte(b.String()))
}
