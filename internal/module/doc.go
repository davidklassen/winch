package module

import (
	"embed"
	"reflect"

	"github.com/davidklassen/winch/internal/doc"
)

//go:embed examples
var examples embed.FS

type Doc struct {
	Text, Example string
	Keys          []doc.Key
}

// Reference returns the reference of the module name.
func Reference(name string) (Doc, bool) {
	m, ok := modules[name]
	if !ok {
		return Doc{}, false
	}
	example, _ := examples.ReadFile("examples/" + name + ".yaml")
	return Doc{Text: m.text, Example: string(example), Keys: doc.Keys(reflect.TypeOf(m.new()).Elem())}, true
}
