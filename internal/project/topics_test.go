package project

import (
	"maps"
	"slices"
	"testing"

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
		check(t, topic.Name+".", topic.Functions)
	}
}

// spec: Remote execution/Facts
func TestFactsHaveNoDefault(t *testing.T) {
	topics := Topics()
	i := slices.IndexFunc(topics, func(t doc.Topic) bool { return t.Name == "facts" })
	if i < 0 {
		t.Fatal("no topic facts")
	}
	for _, k := range topics[i].Keys {
		for _, k := range append(k.Keys, k) {
			if k.Default != "" {
				t.Errorf("fact %s has the default %q", k.Name, k.Default)
			}
		}
	}
}

// spec: CLI; Templates and expressions
func TestFunctionText(t *testing.T) {
	topics := Topics()
	page := func(name string) []string {
		i := slices.IndexFunc(topics, func(t doc.Topic) bool { return t.Name == name })
		if i < 0 {
			t.Fatalf("no topic %s", name)
		}
		var names []string
		for _, f := range topics[i].Functions {
			names = append(names, f.Name)
		}
		return names
	}
	goFuncs := []string{"and", "call", "eq", "ge", "gt", "html", "index", "js", "le", "len", "lt", "ne", "not", "or", "print", "printf", "println", "slice", "urlquery"}
	templates := append(slices.Collect(maps.Keys(funcs)), goFuncs...)
	own := []string{"quote", "sqlquote", "json", "match"}
	var expressions []string
	for _, name := range append(slices.Clone(builtin.Names), own...) {
		if name != "toJSON" && name != "now" {
			expressions = append(expressions, name)
		}
	}
	for _, tt := range []struct {
		page string
		want []string
	}{{"templates", templates}, {"expressions", expressions}} {
		got := page(tt.page)
		for _, name := range tt.want {
			if !slices.Contains(got, name) {
				t.Errorf("function %s is not on the page %s", name, tt.page)
			}
		}
		for _, name := range got {
			if !slices.Contains(tt.want, name) {
				t.Errorf("the page %s lists %s, which is not one of its functions", tt.page, name)
			}
		}
	}
}
