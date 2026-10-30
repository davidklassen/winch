package cli

import (
	"encoding/json"
	"io"
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
	Blocks    []docBlockJSON    `json:"blocks"`
	Keys      []docKeyJSON      `json:"keys"`
	Functions []docFunctionJSON `json:"functions"`
}

// docBlockJSON is a block of a topic. Lists have items and ordered, tables
// rows, and the other blocks text.
type docBlockJSON struct {
	Type    doc.Kind   `json:"type"`
	Text    *string    `json:"text,omitempty"`
	Ordered *bool      `json:"ordered,omitempty"`
	Items   []string   `json:"items,omitempty"`
	Rows    [][]string `json:"rows,omitempty"`
}

type docGroupJSON struct {
	Title  string         `json:"title"`
	Topics []docTopicJSON `json:"topics"`
}

type docModuleJSON struct {
	Name    string       `json:"name"`
	Line    string       `json:"line"`
	Body    string       `json:"body"`
	Keys    []docKeyJSON `json:"keys"`
	Example string       `json:"example"`
}

// writeDocJSON writes everything that winch doc shows as one JSON document.
// Texts are on one line, without the line breaks of the terminal, except in
// code and examples.
func writeDocJSON(out io.Writer) {
	var d struct {
		Intro    string           `json:"intro"`
		Groups   []docGroupJSON   `json:"groups"`
		Modules  []docModuleJSON  `json:"modules"`
		Commands []docCommandJSON `json:"commands"`
	}
	d.Intro = oneLine(docIntro)
	for _, g := range project.Groups() {
		group := docGroupJSON{Title: g.Title}
		for _, t := range g.Topics {
			functions := []docFunctionJSON{}
			for _, f := range t.Functions {
				functions = append(functions, docFunctionJSON{Name: f.Name, Line: f.Summary(), Text: f.Text})
			}
			blocks := []docBlockJSON{}
			for _, b := range t.Blocks {
				blocks = append(blocks, docBlock(b))
			}
			group.Topics = append(group.Topics, docTopicJSON{
				Name:      t.Name,
				Line:      t.Text,
				Blocks:    blocks,
				Keys:      docKeys(t.Name+".", t.Keys),
				Functions: functions,
			})
		}
		d.Groups = append(d.Groups, group)
	}
	for _, name := range module.Names() {
		m, _ := module.Reference(name)
		d.Modules = append(d.Modules, docModuleJSON{Name: name, Line: m.Text, Body: m.Body, Keys: docKeys(name+".", m.Keys), Example: m.Example})
	}
	for _, c := range commands {
		d.Commands = append(d.Commands, commandJSON(c))
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	// Encode fails only on types that JSON cannot hold, and d has none.
	_ = enc.Encode(d)
}

type docExampleJSON struct {
	Comment string `json:"comment"`
	Command string `json:"command"`
}

type docFlagJSON struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Default string `json:"default"`
	Text    string `json:"text"`
}

type docCommandJSON struct {
	Name        string           `json:"name"`
	Summary     string           `json:"summary"`
	Usage       []string         `json:"usage"`
	Description []string         `json:"description"`
	Examples    []docExampleJSON `json:"examples"`
	Flags       []docFlagJSON    `json:"flags"`
	See         []string         `json:"see"`
}

func commandJSON(c command) docCommandJSON {
	j := docCommandJSON{Name: c.name, Summary: c.summary, Usage: c.usage, Description: []string{}, Examples: []docExampleJSON{}, Flags: []docFlagJSON{}, See: []string{}}
	for _, p := range c.description {
		j.Description = append(j.Description, oneLine(p))
	}
	for _, e := range c.examples {
		j.Examples = append(j.Examples, docExampleJSON{Comment: e.comment, Command: e.command})
	}
	for _, f := range c.flags {
		j.Flags = append(j.Flags, docFlagJSON{Name: f.name, Value: f.value, Default: f.def, Text: oneLine(f.text)})
	}
	j.See = append(j.See, c.see...)
	return j
}

func docBlock(b doc.Block) docBlockJSON {
	j := docBlockJSON{Type: b.Kind}
	switch b.Kind {
	case doc.KindList:
		j.Ordered = &b.Ordered
		for _, item := range b.Items {
			j.Items = append(j.Items, oneLine(item))
		}
	case doc.KindTable:
		for _, row := range b.Rows {
			var cells []string
			for _, cell := range row {
				cells = append(cells, oneLine(cell))
			}
			j.Rows = append(j.Rows, cells)
		}
	case doc.KindCode, doc.KindExample:
		j.Text = &b.Text
	default:
		text := oneLine(b.Text)
		j.Text = &text
	}
	return j
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

// oneLine joins the lines of text with spaces.
func oneLine(text string) string {
	return strings.ReplaceAll(text, "\n", " ")
}
