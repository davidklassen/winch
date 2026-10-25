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
	// needs are the variables of the recipe and the variables that its
	// steps and templates read by name.
	needs     []string
	root      string
	templates map[string]*tmplFile
}

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
	Require []*yamlx.Node `yaml:"require"`
	Vars    *yamlx.Node   `yaml:"vars"`
	Steps   []*yamlx.Node `yaml:"steps,required"`
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
			errs = append(errs, fmt.Errorf("%s: a recipe needs a recipe.yaml", dir))
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
			st, err := l.loadStep(sn, r)
			rerrs = append(rerrs, err)
			r.Steps = append(r.Steps, st)
		}
		if err := errors.Join(rerrs...); err != nil {
			errs = append(errs, err)
			continue
		}
		for _, v := range r.Vars {
			r.needs = append(r.needs, v.Name)
		}
		for _, st := range r.Steps {
			r.needs = append(r.needs, st.reads()...)
		}
		for _, t := range r.templates {
			r.needs = append(r.needs, t.reads...)
		}
		l.recipes[name] = r
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
