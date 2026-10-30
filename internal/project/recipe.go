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
	"github.com/expr-lang/expr/ast"
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
	Steps   []Step
	// Handlers are in declared order.
	Handlers  []*Handler
	root      string
	templates map[string]*tmplFile
	// inline is true for a recipe in winch.yaml.
	inline bool
}

// Handler is a handler of a recipe, or of a stage with Recipe nil.
type Handler struct {
	Name     string
	Recipe   *Recipe
	Pipeline string
	Stage    string
	Steps    []Step
	Pos      yamlx.Pos
}

// ConfirmsAccess reports whether a step or a handler step of the recipe has
// confirm_access.
func (r *Recipe) ConfirmsAccess() bool {
	return slices.ContainsFunc(r.Steps, confirms) || slices.ContainsFunc(r.Handlers, (*Handler).ConfirmsAccess)
}

// ConfirmsAccess reports whether a step of the handler has confirm_access.
func (h *Handler) ConfirmsAccess() bool { return slices.ContainsFunc(h.Steps, confirms) }

func confirms(st Step) bool { return st.ConfirmAccess }

// Owner is the name of the recipe or the stage of the handler.
func (h *Handler) Owner() string {
	if h.Recipe == nil {
		return h.Stage
	}
	return h.Recipe.Name
}

// FullName is <recipe>.<handler>, or <stage>.<handler>.
func (h *Handler) FullName() string { return h.Owner() + "." + h.Name }

// Record names the handler in the pending handlers on a host. A handler of a
// stage is <pipeline>\t<stage>\t<handler>: neither a stage name nor a handler
// name holds a tab.
func (h *Handler) Record() string {
	if h.Recipe == nil {
		return h.Pipeline + "\t" + h.Stage + "\t" + h.Name
	}
	return h.FullName()
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
	Require  []*yamlx.Node `yaml:"require" type:"list of expressions" line:"conditions on facts" doc:"Conditions on facts, each an !expr. Every host where the recipe runs in the pipeline meets all of them, or it fails at plan. They see only facts."`
	Vars     *yamlx.Node   `yaml:"vars" type:"map" line:"defaults of the recipe's own variables" doc:"Defaults of the recipe's own variables. Their names start with the recipe name and _."`
	Steps    []*yamlx.Node `yaml:"steps,required" type:"list of steps" line:"module steps, in order" doc:"Module steps, in order. A recipe cannot run another recipe."`
	Handlers *yamlx.Node   `yaml:"handlers" type:"map of lists of steps" line:"steps that run after a change" doc:"Steps that run after a change. They run after the last step of the recipe, when a step notified them. Run winch doc handlers."`
	inline   bool
}

var recipeNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// errReported is the error of a step that uses a recipe whose recipe.yaml
// failed to load. That error was reported once.
var errReported = errors.New("the recipe failed to load")

// readRecipes reads every recipe and adds its defaults.
func (l *loader) readRecipes() error {
	var errs []error
	for _, p := range l.layout.recipes {
		name := p.name
		l.recipes[name] = nil
		dir := "recipes/" + name
		switch {
		case recipeNameRe.MatchString(name):
		case p.node != nil:
			errs = append(errs, yamlx.Errorf(p.pos, "recipe %q: a recipe name has only lowercase letters, digits, and _", name))
			continue
		default:
			errs = append(errs, fmt.Errorf("%s: a recipe name has only lowercase letters, digits, and _", dir))
			continue
		}
		n, err := p.parse(l.dir)
		if errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("%s: a recipe needs a recipe.yaml or recipe.yml", dir))
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
		rf.inline = p.node != nil
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
		r := &Recipe{Name: name, Dir: "recipes/" + name, root: filepath.Join(l.dir, "recipes", name), inline: rf.inline}
		rerrs := []error{l.parseTemplates(r)}
		for _, rn := range rf.Require {
			req, err := compileRequire(rn)
			rerrs = append(rerrs, err)
			r.Require = append(r.Require, req)
		}
		for _, sn := range rf.Steps {
			st, err := l.loadStep(sn, r, plainStep)
			rerrs = append(rerrs, err)
			r.Steps = append(r.Steps, st)
		}
		var err error
		r.Handlers, err = l.loadHandlers(rf.Handlers, r)
		rerrs = append(rerrs, err)
		if err := errors.Join(rerrs...); err != nil {
			errs = append(errs, err)
			continue
		}
		l.recipes[name] = r
	}
	return errors.Join(errs...)
}

// loadHandlers loads the handlers of r, or of a stage when r is nil, from n,
// a map of names to lists of steps.
func (l *loader) loadHandlers(n *yamlx.Node, r *Recipe) ([]*Handler, error) {
	if n == nil || n.Kind == yamlx.Null {
		return nil, nil
	}
	if n.Kind != yamlx.Map {
		return nil, yamlx.Errorf(n.Pos, "handlers: expected a map, got %s", yamlx.Describe(n))
	}
	var out []*Handler
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
			st, err := l.loadStep(sn, r, handlerStep)
			errs = append(errs, err)
			h.Steps = append(h.Steps, st)
		}
		out = append(out, h)
	}
	return out, errors.Join(errs...)
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
	sc := scope{reads: &l.reads}
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
		if err := module.CheckRelative("source", f.Source); err != nil {
			return nil, yamlx.Errorf(f.SourcePos, "%v", err)
		}
		data, err := r.readFile("files", f.Source)
		if err != nil {
			return nil, yamlx.Errorf(f.SourcePos, "source: %v", err)
		}
		f.Data = data
	case f.Template != "":
		if err := module.CheckRelative("template", f.Template); err != nil {
			return nil, yamlx.Errorf(f.TemplatePos, "%v", err)
		}
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

// unitContent sets the data of a unit step of r from its content or its
// source file.
func (r *Recipe) unitContent(u *module.Unit) error {
	switch {
	case u.Content != nil:
		u.Data = []byte(*u.Content)
	case u.Source != "":
		if err := module.CheckRelative("source", u.Source); err != nil {
			return yamlx.Errorf(u.SourcePos, "%v", err)
		}
		data, err := r.readFile("files", u.Source)
		if err != nil {
			return yamlx.Errorf(u.SourcePos, "source: %v", err)
		}
		u.Data = data
	}
	return nil
}

// key sets the key data of a repo step of r from key_content or its key
// file, and returns its warnings.
func (r *Recipe) key(k *module.Repo) ([]*yamlx.Error, error) {
	var warnings []string
	var err error
	pos, prefix := k.KeyPos, "key: "
	switch {
	case k.KeyContent != nil:
		pos, prefix = k.KeyContentPos, ""
		warnings, err = k.SetKey("key_content", []byte(*k.KeyContent), time.Now())
	case k.Key != "":
		var data []byte
		data, err = r.readFile("files", k.Key)
		if err == nil {
			warnings, err = k.SetKey(r.Dir+"/files/"+k.Key, data, time.Now())
		}
	}
	if err != nil {
		return nil, yamlx.Errorf(pos, "%s%v", prefix, err)
	}
	var out []*yamlx.Error
	for _, w := range warnings {
		out = append(out, yamlx.Errorf(pos, "%s%s", prefix, w))
	}
	return out, nil
}

// fileTemplates returns the templates of the file step st with the
// arguments n. A computed template name gives all templates of the recipe,
// unless it reads only item and the loop is a literal list: then it gives the
// templates that the items name.
func (r *Recipe) fileTemplates(st Step, n *yamlx.Node) []*tmplFile {
	i := slices.IndexFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "template" })
	if i < 0 {
		return nil
	}
	v := n.Pairs[i].Value
	var names []string
	if v.Tag == "" {
		name, _ := v.Value.(string)
		names = []string{name}
	} else if l, ok := loopNames(st, v); ok {
		names = l
	} else {
		names = slices.Collect(maps.Keys(r.templates))
	}
	var out []*tmplFile
	for _, name := range names {
		if t := r.templates[name]; t != nil {
			out = append(out, t)
		}
	}
	return out
}

// loopNames returns the value of the computed scalar v of the step st for
// each item, when v reads only item and the loop is a literal list.
func loopNames(st Step, v *yamlx.Node) ([]string, bool) {
	c := st.args.computed[v]
	if st.loop == nil || st.loop.computed != nil || c.data {
		return nil, false
	}
	var out []string
	for _, item := range st.loop.node.Items {
		name, err := c.evalItem(yamlx.Value(item))
		s, ok := name.(string)
		if err != nil || !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
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
	prog, err := expr.Compile(text, expr.Env(requireEnv{}), expr.AsBool(), expr.Optimize(false))
	if err != nil {
		return Require{}, yamlx.Errorf(n.Pos, "require: %s", exprMessage(err, []string{"facts"}))
	}
	check := &exprCheck{src: prog.Source(), named: map[ast.Node]bool{}}
	ast.Walk(new(prog.Node()), check)
	if len(check.errs) > 0 {
		return Require{}, yamlx.Errorf(n.Pos, "require: %s", check.errs[0])
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
