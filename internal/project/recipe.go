package project

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/vm"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Recipe struct {
	Name string
	// Dir is relative to the project.
	Dir     string
	Require []Require
	Steps   []Step
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
	Steps   []*yamlx.Node `yaml:"steps,required"`
}

var recipeNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// errReported is the error of a step that uses a recipe whose recipe.yaml
// failed to load for an earlier step. That error was reported once.
var errReported = errors.New("the recipe failed to load")

// recipe returns the recipe name. The errors of recipe.yaml come once, for the
// first step that uses the recipe.
func (l *loader) recipe(name string, pos yamlx.Pos) (*Recipe, error) {
	if r, ok := l.recipes[name]; ok {
		if r == nil {
			return nil, errReported
		}
		return r, nil
	}
	if !recipeNameRe.MatchString(name) {
		return nil, yamlx.Errorf(pos, "recipe %q: a recipe name has only lowercase letters, digits, and _", name)
	}
	dir := "recipes/" + name
	fi, err := os.Stat(filepath.Join(l.dir, dir))
	if errors.Is(err, fs.ErrNotExist) || err == nil && !fi.IsDir() {
		names, err := l.recipeNames()
		if err != nil {
			return nil, err
		}
		return nil, yamlx.Errorf(pos, "unknown recipe %q%s", name, yamlx.Suggest(name, names))
	}
	if err != nil {
		return nil, fmt.Errorf("recipe %s: %w", name, err)
	}
	n, err := parse(l.dir, dir+"/recipe.yaml")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, yamlx.Errorf(pos, "recipe %q has no %s/recipe.yaml", name, dir)
	}
	l.recipes[name] = nil
	if err != nil {
		return nil, err
	}
	var rf recipeFile
	if err := yamlx.Decode(n, &rf); err != nil {
		return nil, err
	}
	r := &Recipe{Name: name, Dir: dir}
	var errs []error
	for _, rn := range rf.Require {
		req, err := compileRequire(rn)
		errs = append(errs, err)
		r.Require = append(r.Require, req)
	}
	for _, sn := range rf.Steps {
		st, err := l.loadStep(sn, r)
		errs = append(errs, err)
		r.Steps = append(r.Steps, st)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	l.recipes[name] = r
	return r, nil
}

func (l *loader) recipeNames() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(l.dir, "recipes"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read recipes: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func compileRequire(n *yamlx.Node) (Require, error) {
	text, ok := n.Value.(string)
	if n.Tag != "!expr" || !ok {
		return Require{}, yamlx.Errorf(n.Pos, `require: an item is an expression with the !expr tag, such as !expr 'facts.os.id == "debian"'`)
	}
	prog, err := expr.Compile(text, expr.Env(requireEnv{}), expr.AsBool())
	if err != nil {
		return Require{}, yamlx.Errorf(n.Pos, "require: %s", exprMessage(err))
	}
	return Require{Text: text, Pos: n.Pos, program: prog}, nil
}

var (
	unknownNameRe  = regexp.MustCompile(`^unknown name (\w+)$`)
	unknownFieldRe = regexp.MustCompile(`^type facts\.(\w+) has no field (\w+)$`)
	factFields     = map[string][]string{"Facts": exprNames(facts.Facts{}), "OS": exprNames(facts.OS{})}
)

// exprMessage returns the message of an expr error, with a suggestion for an
// unknown name.
func exprMessage(err error) string {
	msg := err.Error()
	if fe, ok := errors.AsType[*file.Error](err); ok {
		msg = fe.Message
	}
	if m := unknownNameRe.FindStringSubmatch(msg); m != nil {
		return fmt.Sprintf("unknown name %q%s", m[1], yamlx.Suggest(m[1], []string{"facts"}))
	}
	if m := unknownFieldRe.FindStringSubmatch(msg); m != nil {
		return fmt.Sprintf("unknown fact %q%s", m[2], yamlx.Suggest(m[2], factFields[m[1]]))
	}
	return msg
}

func exprNames(v any) []string {
	t := reflect.TypeOf(v)
	var names []string
	for i := range t.NumField() {
		names = append(names, t.Field(i).Tag.Get("expr"))
	}
	return names
}

// Check returns an error for the first requirement that the facts do not meet.
func (r *Recipe) Check(f facts.Facts) error {
	for _, req := range r.Require {
		out, err := expr.Run(req.program, requireEnv{Facts: f})
		if err != nil {
			return yamlx.Errorf(req.Pos, "require: %s", exprMessage(err))
		}
		if ok, _ := out.(bool); !ok {
			return yamlx.Errorf(req.Pos, "recipe %s requires %s; the host has os.id %q, os.version %q, os.codename %q",
				r.Name, req.Text, f.OS.ID, f.OS.Version, f.OS.Codename)
		}
	}
	return nil
}
