// Package doc holds the reference that winch doc shows: the keys of YAML
// maps and the topics.
package doc

import (
	"reflect"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

// Key is a key of a YAML map. Default is "required" for a required key, and
// "" for a key without a default. Line is the text of the key tables, and
// Text the full text. Keys are the keys of its value, or of each element of
// a list of maps.
type Key struct {
	Name, Type, Default, Line, Text string
	Keys                            []Key
}

func (k Key) Summary() string {
	if i := strings.Index(k.Text, ". "); i >= 0 {
		return k.Text[:i+1]
	}
	return k.Text
}

// Keys returns the keys of the struct type t, from the tags yaml, line, doc,
// default, and type. The type tag names the type of a field that the code
// decodes by hand.
func Keys(t reflect.Type) []Key {
	var out []Key
	for _, yf := range yamlx.Fields(t) {
		f := t.Field(yf.Index)
		k := Key{Name: yf.Name, Type: f.Tag.Get("type"), Default: f.Tag.Get("default"), Line: f.Tag.Get("line"), Text: f.Tag.Get("doc")}
		if k.Type == "" {
			k.Type = typeName(f.Type)
		}
		switch {
		case yf.Required:
			k.Default = "required"
		case k.Default == "" && f.Type.Kind() == reflect.Bool:
			k.Default = "false"
		}
		e := f.Type
		if e.Kind() == reflect.Pointer || e.Kind() == reflect.Slice {
			e = e.Elem()
		}
		if e.Kind() == reflect.Struct {
			k.Keys = Keys(e)
		}
		out = append(out, k)
	}
	return out
}

func typeName(t reflect.Type) string {
	switch t {
	case reflect.TypeFor[yamlx.Strings]():
		return "string or list of strings"
	case reflect.TypeFor[yamlx.Ints]():
		return "integer or list of integers"
	case reflect.TypeFor[yamlx.NameOrID]():
		return "name or ID"
	case reflect.TypeFor[yamlx.ID]():
		return "ID"
	}
	switch t.Kind() {
	case reflect.Pointer:
		return typeName(t.Elem())
	case reflect.Struct:
		return "map"
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int64:
		return "integer"
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Struct {
			return "list of maps"
		}
		return "list of " + typeName(t.Elem()) + "s"
	}
	panic("doc: no type name for " + t.String())
}

// Topic is a page of the reference. Text is its index line. Keys are the
// keys of the file or the map that it describes. The page prints the keys
// and the functions before an example block.
type Topic struct {
	Name, Text      string
	Blocks          []Block
	Keys, Functions []Key
}

// Group is a titled group of topics in the index.
type Group struct {
	Title  string
	Topics []Topic
}

type Kind string

const (
	KindHeading   Kind = "heading"
	KindParagraph Kind = "paragraph"
	KindList      Kind = "list"
	KindTable     Kind = "table"
	KindCode      Kind = "code"
	KindExample   Kind = "example"
)

// Block is a part of a topic page. The line breaks of Text, Items, and Rows
// are the line breaks of the terminal.
type Block struct {
	Kind    Kind
	Text    string
	Ordered bool
	Items   []string
	Rows    [][]string
}

func Heading(text string) Block   { return Block{Kind: KindHeading, Text: text} }
func Paragraph(text string) Block { return Block{Kind: KindParagraph, Text: text} }
func List(items ...string) Block  { return Block{Kind: KindList, Items: items} }

func OrderedList(items ...string) Block {
	return Block{Kind: KindList, Ordered: true, Items: items}
}

func Table(rows [][]string) Block { return Block{Kind: KindTable, Rows: rows} }
func Code(text string) Block      { return Block{Kind: KindCode, Text: text} }

// Example is the example of a topic. It ends the page.
func Example(text string) Block { return Block{Kind: KindExample, Text: text} }
