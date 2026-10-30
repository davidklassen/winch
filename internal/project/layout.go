package project

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

// part is an inventory, a pipeline, or a recipe: a file, or a key in
// winch.yaml.
type part struct {
	name string
	// file is relative to the project. For a key, it is the project file.
	file string
	// node is the value of the key, and pos the position of the key, or nil
	// for a file.
	node *yamlx.Node
	pos  yamlx.Pos
	// top is true for the inventory or the pipeline at the top of winch.yaml.
	top bool
}

// label names the part in messages.
func (p part) label(kind string) string {
	if p.node != nil && !p.top {
		return kind + "." + p.name + " of " + p.file
	}
	return p.file
}

// layout holds the inventories, the pipelines, and the recipes of a project,
// each sorted by name.
type layout struct {
	inventories, pipelines, recipes []part
}

// readLayout lists the parts in the directories of dir and in the keys of
// cfg. A name both as a key and as a file is an error.
func readLayout(dir string, cfg *Config) (layout, error) {
	var ly layout
	var errs []error
	files, err := list(dir, "inventories")
	errs = append(errs, err)
	for _, f := range files {
		errs = append(errs, addFile(&ly.inventories, strings.TrimSuffix(path.Base(f), path.Ext(f)), f, "inventory"))
	}
	files, err = list(dir, "pipelines")
	errs = append(errs, err)
	for _, f := range files {
		errs = append(errs, addFile(&ly.pipelines, strings.TrimSuffix(path.Base(f), path.Ext(f)), f, "pipeline"))
	}
	files, err = recipeFiles(dir)
	errs = append(errs, err)
	for _, f := range files {
		errs = append(errs, addFile(&ly.recipes, path.Base(path.Dir(f)), f, "recipe"))
	}
	entries, err := os.ReadDir(filepath.Join(dir, "recipes"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("read recipes: %w", err))
	}
	for _, e := range entries {
		if e.IsDir() && !slices.ContainsFunc(ly.recipes, func(p part) bool { return p.name == e.Name() }) {
			ly.recipes = append(ly.recipes, part{name: e.Name(), file: "recipes/" + e.Name() + "/recipe.yaml"})
		}
	}
	for _, parts := range [][]part{ly.inventories, ly.pipelines, ly.recipes} {
		slices.SortFunc(parts, func(a, b part) int { return strings.Compare(a.name, b.name) })
	}
	errs = append(errs,
		addKeys(&ly.inventories, cfg.Inventories, cfg.file, "inventories", "inventory"),
		addKeys(&ly.pipelines, cfg.Pipelines, cfg.file, "pipelines", "pipeline"),
		addKeys(&ly.recipes, cfg.Recipes, cfg.file, "recipes", "recipe"),
		addTop(&ly.inventories, cfg, "inventories", "hosts", "groups"),
		addTop(&ly.pipelines, cfg, "pipelines", "steps", "handlers", "parallelism", "health"))
	return ly, errors.Join(errs...)
}

// addFile adds the part name in file to parts. A second file for one name is
// an error.
func addFile(parts *[]part, name, file, kind string) error {
	if i := slices.IndexFunc(*parts, func(p part) bool { return p.name == name }); i >= 0 {
		return fmt.Errorf("%s %q is both %s and %s; keep one of the two", kind, name, (*parts)[i].file, file)
	}
	*parts = append(*parts, part{name: name, file: file})
	return nil
}

// addTop makes the keys of winch.yaml in keys the only part, with the name of
// the project. Another part is an error; the top part replaces it, so the
// load reports no error that follows from it.
func addTop(parts *[]part, cfg *Config, kind string, keys ...string) error {
	if cfg.root == nil {
		return nil
	}
	n := &yamlx.Node{Kind: yamlx.Map}
	for _, p := range cfg.root.Pairs {
		if slices.Contains(keys, p.Key) {
			n.Pairs = append(n.Pairs, p)
		}
	}
	if len(n.Pairs) == 0 {
		return nil
	}
	first := n.Pairs[0]
	n.Pos = first.KeyPos
	var err error
	if len(*parts) > 0 {
		err = yamlx.Errorf(first.KeyPos, "%s: the %s at the top of %s and %s are two %s; keep one of the two", first.Key, first.Key, cfg.file, (*parts)[0].label(kind), kind)
	}
	*parts = []part{{name: cfg.Name, file: cfg.file, node: n, pos: first.KeyPos, top: true}}
	return err
}

// addKeys adds the keys of n, the field key of the project file, to parts.
func addKeys(parts *[]part, n *yamlx.Node, file, key, kind string) error {
	if n == nil || n.Kind == yamlx.Null {
		return nil
	}
	if n.Kind != yamlx.Map {
		return yamlx.Errorf(n.Pos, "%s: expected a map, got %s", key, yamlx.Describe(n))
	}
	var errs []error
	for _, p := range n.Pairs {
		if i := slices.IndexFunc(*parts, func(o part) bool { return o.name == p.Key }); i >= 0 {
			other := (*parts)[i].file
			if kind == "recipe" {
				// A recipe directory without a recipe file clashes too.
				other = path.Dir(other) + "/"
			}
			errs = append(errs, yamlx.Errorf(p.KeyPos, "%s %q is also %s; keep one of the two", kind, p.Key, other))
			continue
		}
		*parts = append(*parts, part{name: p.Key, file: file, node: p.Value, pos: p.KeyPos})
	}
	slices.SortFunc(*parts, func(a, b part) int { return strings.Compare(a.name, b.name) })
	return errors.Join(errs...)
}

// partNames returns the names of parts.
func partNames(parts []part) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p.name)
	}
	return out
}

// only returns the name of the only inventory, or "".
func (ly layout) only() string {
	if len(ly.inventories) == 1 {
		return ly.inventories[0].name
	}
	return ""
}

// inventory returns the inventory name.
func (ly layout) inventory(name string) (part, error) {
	if i := slices.IndexFunc(ly.inventories, func(p part) bool { return p.name == name }); i >= 0 {
		return ly.inventories[i], nil
	}
	base := strings.TrimSuffix(strings.TrimSuffix(path.Base(name), ".yaml"), ".yml")
	if strings.ContainsRune(name, '/') || base != path.Base(name) {
		return part{}, fmt.Errorf("unknown inventory %q; name an inventory without its directory and extension, such as %q", name, base)
	}
	return part{}, fmt.Errorf("unknown inventory %q%s", name, yamlx.Suggest(name, partNames(ly.inventories)))
}

// parse returns the content of p.
func (p part) parse(dir string) (*yamlx.Node, error) {
	if p.node != nil {
		return p.node, nil
	}
	return parse(dir, p.file)
}
