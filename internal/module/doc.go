package module

import (
	"embed"
	"reflect"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

//go:embed examples
var examples embed.FS

type Doc struct {
	Text, Example string
	Keys          []Key
}

// Key is a module key. Default is "required" for a required key, and "" for
// a key without a default. Keys are the keys of each element of a list of
// maps.
type Key struct {
	Name, Type, Default, Text string
	Keys                      []Key
}

func (k Key) Summary() string {
	if i := strings.Index(k.Text, ". "); i >= 0 {
		return k.Text[:i+1]
	}
	return k.Text
}

// Reference returns the reference of the module name.
func Reference(name string) (Doc, bool) {
	m, ok := modules[name]
	if !ok {
		return Doc{}, false
	}
	example, _ := examples.ReadFile("examples/" + name + ".yaml")
	return Doc{Text: m.text, Example: string(example), Keys: keys(reflect.TypeOf(m.new()).Elem())}, true
}

func keys(t reflect.Type) []Key {
	var out []Key
	for _, yf := range yamlx.Fields(t) {
		f := t.Field(yf.Index)
		k := Key{Name: yf.Name, Type: typeName(f.Type), Default: f.Tag.Get("default"), Text: f.Tag.Get("doc")}
		switch {
		case yf.Required:
			k.Default = "required"
		case k.Default == "" && f.Type.Kind() == reflect.Bool:
			k.Default = "false"
		}
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Struct {
			k.Keys = keys(f.Type.Elem())
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
	panic("module: no type name for " + t.String())
}
