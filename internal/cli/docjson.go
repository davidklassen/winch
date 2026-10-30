package cli

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/davidklassen/winch/internal/doc"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
)

type docKeyJSON struct {
	Name     string       `json:"name"`
	Path     string       `json:"path"`
	Type     string       `json:"type"`
	Default  string       `json:"default"`
	Required bool         `json:"required"`
	Line     string       `json:"line"`
	Text     string       `json:"text"`
	Keys     []docKeyJSON `json:"keys"`
}

type docFunctionJSON struct {
	Name string `json:"name"`
	Line string `json:"line"`
	Text string `json:"text"`
}

type docTopicJSON struct {
	Name      string            `json:"name"`
	Line      string            `json:"line"`
	Body      string            `json:"body"`
	Keys      []docKeyJSON      `json:"keys"`
	Functions []docFunctionJSON `json:"functions"`
	Example   string            `json:"example"`
}

type docModuleJSON struct {
	Name    string       `json:"name"`
	Line    string       `json:"line"`
	Body    string       `json:"body"`
	Keys    []docKeyJSON `json:"keys"`
	Example string       `json:"example"`
}

type docCommandJSON struct {
	Name  string `json:"name"`
	Usage string `json:"usage"`
	Help  string `json:"help"`
}

// docCommands are the commands in the order of the main help, with their
// help. The help comes from the constants: commands refers to docCommand.
var docCommands = []struct{ name, help string }{
	{"validate", validateHelp}, {"fmt", fmtHelp}, {"plan", planHelp}, {"apply", applyHelp}, {"run", runHelp}, {"exec", execHelp},
	{"secret", secretHelp}, {"secret init", initHelp}, {"secret generate", generateHelp}, {"secret encrypt", encryptHelp}, {"secret rekey", rekeyHelp},
	{"doc", docHelp},
}

// writeDocJSON writes everything that winch doc shows as one JSON document.
// Texts are as the code holds them, without the line breaks of wrap.
func writeDocJSON(out io.Writer) {
	var d struct {
		Intro    string           `json:"intro"`
		Topics   []docTopicJSON   `json:"topics"`
		Modules  []docModuleJSON  `json:"modules"`
		Commands []docCommandJSON `json:"commands"`
	}
	d.Intro = docIntro
	for _, t := range project.Topics() {
		functions := []docFunctionJSON{}
		for _, f := range t.Functions {
			functions = append(functions, docFunctionJSON{Name: f.Name, Line: f.Summary(), Text: f.Text})
		}
		d.Topics = append(d.Topics, docTopicJSON{
			Name:      t.Name,
			Line:      t.Text,
			Body:      markdown(t.Body),
			Keys:      docKeys(t.Name+".", t.Keys),
			Functions: functions,
			Example:   t.Example,
		})
	}
	for _, name := range module.Names() {
		m, _ := module.Reference(name)
		d.Modules = append(d.Modules, docModuleJSON{Name: name, Line: m.Text, Body: m.Body, Keys: docKeys(name+".", m.Keys), Example: m.Example})
	}
	for _, c := range docCommands {
		_, usage, _ := strings.Cut(c.help, "\nUsage: ")
		usage, _, _ = strings.Cut(usage, "\n")
		d.Commands = append(d.Commands, docCommandJSON{Name: c.name, Usage: usage, Help: c.help})
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	// Encode fails only on types that JSON cannot hold, and d has none.
	_ = enc.Encode(d)
}

func docKeys(prefix string, keys []doc.Key) []docKeyJSON {
	out := []docKeyJSON{}
	for _, k := range keys {
		j := docKeyJSON{Name: k.Name, Path: prefix + k.Name, Type: k.Type, Default: k.Default, Line: k.Line, Text: k.Text, Keys: docKeys(prefix+k.Name+".", k.Keys)}
		if k.Default == "required" {
			j.Default, j.Required = "", true
		}
		out = append(out, j)
	}
	return out
}

var (
	markdownEscape = strings.NewReplacer(`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "<", `\<`, ">", `\>`, "&", `\&`, "|", `\|`, "~", `\~`, "#", `\#`)
	// markdownMarker and markdownNumber are starts of a line that Markdown
	// reads as a list item or a heading underline.
	markdownMarker = regexp.MustCompile(`^[-+=]`)
	markdownNumber = regexp.MustCompile(`^(\d+)([.)])`)
	// listItem is the marker of a list item. A table row such as
	// "-  remove" has more spaces after it.
	listItem = regexp.MustCompile(`^(- |\d+\. )\S`)
)

// markdown converts a topic body from the page layout of winch doc to
// Markdown. A line that ends with a colon above an indented line is a
// section heading. Each block between empty lines is a paragraph, a list,
// or a code block: a block indented deeper than its section, or a table
// whose columns are runs of spaces, keeps its layout in a code block.
func markdown(body string) string {
	var blocks []string
	var block []string
	flush := func() {
		if len(block) > 0 {
			blocks = append(blocks, markdownBlock(block))
		}
		block = nil
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	for i, line := range lines {
		switch {
		case line == "":
			flush()
		case !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") && i+1 < len(lines) && strings.HasPrefix(lines[i+1], " "):
			flush()
			blocks = append(blocks, "## "+markdownEscape.Replace(strings.TrimSuffix(line, ":")))
		default:
			if len(block) > 0 && !isListItem(block[0]) && isListItem(line) && indentOf(line) == indentOf(block[0]) {
				flush()
			}
			block = append(block, line)
		}
	}
	flush()
	return strings.Join(blocks, "\n\n") + "\n"
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func isListItem(line string) bool {
	return listItem.MatchString(strings.TrimLeft(line, " "))
}

func markdownBlock(lines []string) string {
	indent := indentOf(lines[0])
	table := false
	for i, line := range lines {
		lines[i] = line[min(indent, indentOf(line)):]
		table = table || strings.Contains(strings.TrimLeft(line, " "), "  ")
	}
	list := isListItem(lines[0])
	if !list && (indent > 2 || table) {
		return "```\n" + strings.Join(lines, "\n") + "\n```"
	}
	for i, line := range lines {
		text := strings.TrimLeft(line, " ")
		lead := ""
		if list {
			var marker string
			if m := listItem.FindStringSubmatch(text); m != nil {
				marker = m[1]
			}
			lead, text = line[:len(line)-len(text)]+marker, text[len(marker):]
		}
		text = markdownEscape.Replace(text)
		if markdownMarker.MatchString(text) {
			text = `\` + text
		}
		lines[i] = lead + markdownNumber.ReplaceAllString(text, `$1\$2`)
	}
	return strings.Join(lines, "\n")
}
