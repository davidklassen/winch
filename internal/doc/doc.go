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
// and the functions between Body and Example.
type Topic struct {
	Name, Text, Body, Example string
	Keys, Functions           []Key
}

// NewTopic makes the topic name from its page: the first line is the index
// line, and an "Example:" section ends the page.
func NewTopic(name, page string, keys []Key) Topic {
	text, body, _ := strings.Cut(page, "\n\n")
	var example string
	if i := strings.Index(body, "\nExample:\n"); i >= 0 {
		body, example = body[:i], body[i+1:]
	}
	return Topic{Name: name, Text: text, Body: body, Example: example, Keys: keys}
}
