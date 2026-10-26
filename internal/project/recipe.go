package project

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"syscall"
	"text/template"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Recipe struct {
	Name string
	// Dir is relative to the project.
	Dir     string
	Require []Require
	Vars    []*Var
	Steps   []Step
	// Handlers are in declared order.
	Handlers  []*Handler
	root      string
	templates map[string]*tmplFile
}

type Handler struct {
	Name   string
	Recipe *Recipe
	Steps  []Step
	Pos    yamlx.Pos
}

// FullName is <recipe>.<handler>.
func (h *Handler) FullName() string { return h.Recipe.Name + "." + h.Name }

// Require is one requirement of a recipe: an expression on facts.
type Require struct {
	Text    string
	Pos     yamlx.Pos
	program *vm.Program
}

type requireEnv struct {
	Facts facts.Facts `expr:"facts"`
}

type recipeFile struct {
	Require  []*yamlx.Node `yaml:"require"`
	Vars     *yamlx.Node   `yaml:"vars"`
	Steps    []*yamlx.Node `yaml:"steps,required"`
	Handlers *yamlx.Node   `yaml:"handlers"`
}

var recipeNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// errReported is the error of a step that uses a recipe whose recipe.yaml
// failed to load. That error was reported once.
var errReported = errors.New("the recipe failed to load")

// readRecipes reads the recipe.yaml of every recipe and declares its
// variables.
func (l *loader) readRecipes() error {
	entries, err := os.ReadDir(filepath.Join(l.dir, "recipes"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read recipes: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		l.recipes[name] = nil
		dir := "recipes/" + name
		if !recipeNameRe.MatchString(name) {
			errs = append(errs, fmt.Errorf("%s: a recipe name has only lowercase letters, digits, and _", dir))
			continue
		}
		n, err := parse(l.dir, dir+"/recipe.yaml")
		if errors.Is(err, fs.ErrNotExist) {
			hint := ""
			if _, err := os.Stat(filepath.Join(l.dir, dir, "recipe.yml")); err == nil {
				hint = "; rename recipe.yml to recipe.yaml"
			}
			errs = append(errs, fmt.Errorf("%s: a recipe needs a recipe.yaml%s", dir, hint))
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var rf recipeFile
		if err := yamlx.Decode(n, &rf); err != nil {
			errs = append(errs, err)
			continue
		}
		errs = append(errs, l.declare(rf.Vars, name)...)
		l.files[name] = &rf
	}
	return errors.Join(errs...)
}

// loadRecipes loads the recipes that readRecipes read. A recipe that fails
// stays nil in l.recipes.
func (l *loader) loadRecipes() error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(l.files)) {
		rf := l.files[name]
		r := &Recipe{Name: name, Dir: "recipes/" + name, root: filepath.Join(l.dir, "recipes", name)}
		for _, v := range l.decls {
			if v.Recipe == name {
				r.Vars = append(r.Vars, v)
			}
		}
		rerrs := []error{l.parseTemplates(r)}
		for _, rn := range rf.Require {
			req, err := compileRequire(rn)
			rerrs = append(rerrs, err)
			r.Require = append(r.Require, req)
		}
		for _, sn := range rf.Steps {
			st, err := l.loadStep(sn, r, false)
			rerrs = append(rerrs, err)
			r.Steps = append(r.Steps, st)
		}
		rerrs = append(rerrs, l.loadHandlers(rf.Handlers, r))
		if err := errors.Join(rerrs...); err != nil {
			errs = append(errs, err)
			continue
		}
		l.recipes[name] = r
	}
	return errors.Join(errs...)
}

// loadHandlers loads the handlers of r from n, a map of names to lists of
// steps.
func (l *loader) loadHandlers(n *yamlx.Node, r *Recipe) error {
	if n == nil || n.Kind == yamlx.Null {
		return nil
	}
	if n.Kind != yamlx.Map {
		return yamlx.Errorf(n.Pos, "handlers: expected a map, got %s", yamlx.Describe(n))
	}
	var errs []error
	for _, p := range n.Pairs {
		switch {
		case !varNameRe.MatchString(p.Key):
			errs = append(errs, yamlx.Errorf(p.KeyPos, "handler %q: a handler name has only lowercase letters, digits, and _", p.Key))
			continue
		case p.Value.Kind != yamlx.List:
			errs = append(errs, yamlx.Errorf(p.Value.Pos, "handler %q: expected a list of steps, got %s", p.Key, yamlx.Describe(p.Value)))
			continue
		case len(p.Value.Items) == 0:
			errs = append(errs, yamlx.Errorf(p.Value.Pos, "handler %q: a handler needs at least one step", p.Key))
			continue
		}
		h := &Handler{Name: p.Key, Recipe: r, Pos: p.KeyPos}
		for _, sn := range p.Value.Items {
			st, err := l.loadStep(sn, r, true)
			errs = append(errs, err)
			h.Steps = append(h.Steps, st)
		}
		r.Handlers = append(r.Handlers, h)
	}
	return errors.Join(errs...)
}

// parseTemplates parses every file in the templates directory of r.
func (l *loader) parseTemplates(r *Recipe) error {
	r.templates = map[string]*tmplFile{}
	root, err := os.OpenRoot(filepath.Join(r.root, "templates"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s/templates: %w", r.Dir, err)
	}
	defer root.Close()
	var errs []error
	sc := scope{vars: l.vars}
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		file := r.Dir + "/templates/" + name
		text, err := fs.ReadFile(root.FS(), name)
		if err != nil {
			errs = append(errs, readError(file, err))
			return nil
		}
		t, err := parseTemplate(file, text, sc)
		errs = append(errs, err)
		r.templates[name] = t
		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("%s/templates: %w", r.Dir, err))
	}
	return errors.Join(errs...)
}

func (l *loader) recipe(name string, pos yamlx.Pos) (*Recipe, error) {
	r, ok := l.recipes[name]
	switch {
	case !ok:
		return nil, yamlx.Errorf(pos, "unknown recipe %q%s", name, yamlx.Suggest(name, slices.Sorted(maps.Keys(l.recipes))))
	case r == nil:
		return nil, errReported
	}
	return r, nil
}

// content sets the data of a file step of r from content or source, or
// returns its template. loops is true when the step has loop.
func (r *Recipe) content(f *module.File, loops bool) (*template.Template, error) {
	switch {
	case f.Content != nil:
		f.Data = []byte(*f.Content)
	case f.Source != "":
		data, err := r.readFile("files", f.Source)
		if err != nil {
			return nil, yamlx.Errorf(f.SourcePos, "source: %v", err)
		}
		f.Data = data
	case f.Template != "":
		t, ok := r.templates[f.Template]
		switch {
		case ok && t == nil:
			// The template failed to parse, and its error is reported.
			return nil, nil
		case !ok:
			return nil, yamlx.Errorf(f.TemplatePos, "template: %s/templates/%s does not exist", r.Dir, f.Template)
		case t.item && !loops:
			return nil, yamlx.Errorf(f.TemplatePos, "template: %s reads .item; %s", f.Template, itemOutsideLoop)
		}
		return t.t, nil
	}
	return nil, nil
}

// key sets the key data of a repo step of r from its key file, and returns
// its warnings.
func (r *Recipe) key(k *module.Repo) ([]*yamlx.Error, error) {
	if k.Key == "" {
		return nil, nil
	}
	data, err := r.readFile("files", k.Key)
	var warnings []string
	if err == nil {
		warnings, err = k.SetKey(r.Dir+"/files/"+k.Key, data, time.Now())
	}
	if err != nil {
		return nil, yamlx.Errorf(k.KeyPos, "key: %v", err)
	}
	var out []*yamlx.Error
	for _, w := range warnings {
		out = append(out, yamlx.Errorf(k.KeyPos, "key: %s", w))
	}
	return out, nil
}

// templateReads returns the variables that the template of the file
// arguments n read by name.
func (r *Recipe) templateReads(n *yamlx.Node) []string {
	i := slices.IndexFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "template" })
	if i < 0 {
		return nil
	}
	if v := n.Pairs[i].Value; v.Tag == "" {
		name, _ := v.Value.(string)
		if t := r.templates[name]; t != nil {
			return t.reads
		}
		return nil
	}
	var out []string
	for _, t := range r.templates {
		if t != nil {
			out = append(out, t.reads...)
		}
	}
	return out
}

// readFile reads name in the directory sub of r. It does not follow a
// symbolic link out of that directory.
func (r *Recipe) readFile(sub, name string) ([]byte, error) {
	file := r.Dir + "/" + sub + "/" + name
	f, err := os.OpenInRoot(filepath.Join(r.root, sub), name)
	if err != nil {
		return nil, readError(file, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, readError(file, err)
	}
	return data, nil
}

func readError(file string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s does not exist", file)
	case errors.Is(err, syscall.EISDIR):
		return fmt.Errorf("%s is a directory", file)
	}
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		err = pe.Err
	}
	return fmt.Errorf("read %s: %w", file, err)
}

func compileRequire(n *yamlx.Node) (Require, error) {
	text, ok := n.Value.(string)
	if n.Tag != "!expr" || !ok {
		return Require{}, yamlx.Errorf(n.Pos, `require: an item is an expression with the !expr tag, such as !expr 'facts.os.id == "debian"'`)
	}
	prog, err := expr.Compile(text, expr.Env(requireEnv{}), expr.AsBool())
	if err != nil {
		return Require{}, yamlx.Errorf(n.Pos, "require: %s", exprMessage(err, []string{"facts"}))
	}
	return Require{Text: text, Pos: n.Pos, program: prog}, nil
}

// Check returns an error for the first requirement that the facts do not meet.
func (r *Recipe) Check(f facts.Facts) error {
	for _, req := range r.Require {
		out, err := expr.Run(req.program, requireEnv{Facts: f})
		if err != nil {
			return yamlx.Errorf(req.Pos, "require: %s", exprMessage(err, []string{"facts"}))
		}
		if ok, _ := out.(bool); !ok {
			return yamlx.Errorf(req.Pos, "recipe %s requires %s; the host has os.id %q, os.version %q, os.codename %q",
				r.Name, req.Text, f.OS.ID, f.OS.Version, f.OS.Codename)
		}
	}
	return nil
}
