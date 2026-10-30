package project

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"text/template"

	"github.com/expr-lang/expr/builtin"

	"github.com/davidklassen/winch/internal/doc"
)

// spec: CLI
func TestTopicText(t *testing.T) {
	var check func(t *testing.T, prefix string, keys []doc.Key)
	check = func(t *testing.T, prefix string, keys []doc.Key) {
		for _, k := range keys {
			if k.Text == "" {
				t.Errorf("key %s%s has no text", prefix, k.Name)
			}
			check(t, prefix+k.Name+".", k.Keys)
		}
	}
	for _, topic := range Topics() {
		if topic.Text == "" || topic.Body == "" {
			t.Errorf("topic %s has no text", topic.Name)
		}
		check(t, topic.Name+".", topic.Keys)
	}
}

// spec: Templates and expressions
func TestFunctionText(t *testing.T) {
	where := func(name string) string {
		i := slices.IndexFunc(functions, func(k doc.Key) bool { return k.Name == name })
		if i < 0 {
			return ""
		}
		return functions[i].Type
	}
	goFuncs := []string{"and", "call", "eq", "ge", "gt", "html", "index", "js", "le", "len", "lt", "ne", "not", "or", "print", "printf", "println", "slice", "urlquery"}
	for _, name := range append(slices.Collect(maps.Keys(funcs)), goFuncs...) {
		if !strings.Contains(where(name), "template") {
			t.Errorf("template function %s has no text", name)
		}
	}
	own := []string{"quote", "sqlquote", "json", "match"}
	for _, name := range append(slices.Clone(builtin.Names), own...) {
		if name != "toJSON" && name != "now" && !strings.Contains(where(name), "expression") {
			t.Errorf("expression function %s has no text", name)
		}
	}
	for _, f := range functions {
		if strings.Contains(f.Type, "template") {
			if _, err := template.New("").Funcs(funcs).Parse("{{ " + f.Name + " }}"); err != nil {
				t.Errorf("%s is not a template function: %v", f.Name, err)
			}
		}
		if strings.Contains(f.Type, "expression") && !slices.Contains(builtin.Names, f.Name) && !slices.Contains(own, f.Name) {
			t.Errorf("%s is not an expression function", f.Name)
		}
	}
}
