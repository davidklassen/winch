// Package project loads a winch project: winch.yaml, an inventory, recipes,
// and pipelines.
package project

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Project struct {
	Name      string
	Inventory *Inventory
	Pipeline  *Pipeline
	// vars are the declarations in the order in which defaults evaluate.
	vars []*Var
}

type Config struct {
	Name         string `yaml:"name,required"`
	Inventory    string `yaml:"inventory"`
	InventoryPos yamlx.Pos
	Vars         *yamlx.Node `yaml:"vars"`
}

type Pipeline struct {
	Name   string
	Stages []Stage
}

type Stage struct {
	Name     string
	Hosts    string
	HostsPos yamlx.Pos
	Steps    []Step
	// Targets are the hosts of the stage in the loaded inventory.
	Targets []Host
}

// Step is a module step, or a recipe step with Recipe set.
type Step struct {
	Name   string
	Module string
	// Args are the module arguments. A step whose arguments hold computed
	// values has them only after Eval.
	Args   module.Module
	Pos    yamlx.Pos
	Recipe *Recipe
	// in is the recipe that holds the step, or nil in a stage.
	in   *Recipe
	args *value
	when *computed
	loop *value
	tmpl *template.Template
}

// Load reads the project in dir with one inventory and one pipeline. The
// inventory is the path in inventory, or the default from winch.yaml. set
// holds the --set flags.
func Load(dir, inventory, pipeline string, set []string) (*Project, error) {
	cfg, cfgErr := loadConfig(dir)
	if cfg == nil {
		return nil, cfgErr
	}
	l, lErr := newLoader(dir, cfg)
	sets, setErr := l.parseSets(set)
	invs, invErr := l.loadInventories(inventory, cfg, false, sets)
	pl, plErr := l.loadPipeline(pipeline)
	if err := errors.Join(cfgErr, lErr, setErr, invErr, plErr); err != nil {
		return nil, err
	}
	if err := resolve(invs[0], pl); err != nil {
		return nil, err
	}
	return &Project{Name: cfg.Name, Inventory: invs[0], Pipeline: pl, vars: l.order}, nil
}

// Validate loads every pipeline in dir against an inventory: the one in
// inventory, the default from winch.yaml, or else every file in
// inventories/. set holds the --set flags.
func Validate(dir, inventory string, set []string) error {
	cfg, cfgErr := loadConfig(dir)
	if cfg == nil {
		return cfgErr
	}
	l, lErr := newLoader(dir, cfg)
	sets, setErr := l.parseSets(set)
	invs, invErr := l.loadInventories(inventory, cfg, true, sets)
	errs := []error{cfgErr, lErr, setErr, invErr}
	files, err := list(dir, "pipelines")
	if err != nil {
		return err
	}
	for _, file := range files {
		pl, err := l.decodePipeline(file)
		errs = append(errs, err)
		if err != nil {
			continue
		}
		for _, inv := range invs {
			errs = append(errs, resolve(inv, pl))
		}
	}
	return errors.Join(errs...)
}

type loader struct {
	dir string
	// vars are the declarations by name, decls in file order, and order in
	// the order in which defaults evaluate.
	vars  map[string]*Var
	decls []*Var
	order []*Var
	files map[string]*recipeFile
	// recipes holds nil for a recipe that failed to load.
	recipes map[string]*Recipe
}

// newLoader declares the variables of winch.yaml and of every recipe, then
// loads the recipes.
func newLoader(dir string, cfg *Config) (*loader, error) {
	l := &loader{dir: dir, vars: map[string]*Var{}, files: map[string]*recipeFile{}, recipes: map[string]*Recipe{}}
	errs := l.declare(cfg.Vars, "")
	errs = append(errs, l.readRecipes(), l.compileDefaults(), l.loadRecipes())
	return l, errors.Join(errs...)
}

// loadInventories loads the inventory in flag, or the default from
// winch.yaml. Without both, it loads every file in inventories/ when all is
// true. It returns the inventories that loaded.
func (l *loader) loadInventories(flag string, cfg *Config, all bool, set []setValue) ([]*Inventory, error) {
	switch {
	case flag != "":
		inv, err := l.loadInventory(flag, set)
		if err != nil {
			return nil, err
		}
		return []*Inventory{inv}, nil
	case cfg.Inventory != "":
		inv, err := l.loadInventory(cfg.Inventory, set)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, yamlx.Errorf(cfg.InventoryPos, "inventory %q does not exist", cfg.Inventory)
		}
		if err != nil {
			return nil, err
		}
		return []*Inventory{inv}, nil
	case !all:
		return nil, errors.New("no inventory: use --inventory, or set inventory in winch.yaml")
	}
	files, err := list(l.dir, "inventories")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no inventory: use --inventory, set inventory in winch.yaml, or add a file to inventories/")
	}
	var invs []*Inventory
	var errs []error
	for _, file := range files {
		inv, err := l.loadInventory(file, set)
		errs = append(errs, err)
		if err == nil {
			invs = append(invs, inv)
		}
	}
	return invs, errors.Join(errs...)
}

// resolve sets the targets of every stage from the inventory. It checks that
// a recipe runs at most once per host, and that a recipe step without when
// has the required variables of its recipe.
func resolve(inv *Inventory, pl *Pipeline) error {
	var errs []error
	first := map[[2]string]yamlx.Pos{}
	for i := range pl.Stages {
		s := &pl.Stages[i]
		var err error
		s.Targets, err = inv.match(s.Hosts, s.HostsPos)
		errs = append(errs, err)
		for _, st := range s.Steps {
			if st.Recipe == nil {
				continue
			}
			if st.when == nil {
				errs = append(errs, st.missing(s.Targets))
			}
			for _, h := range s.Targets {
				key := [2]string{h.Name, st.Recipe.Name}
				if pos, ok := first[key]; ok {
					errs = append(errs, yamlx.Errorf(st.Pos, "recipe %s runs twice on host %s; it runs first at %s", st.Recipe.Name, h.Name, pos))
					break
				}
				first[key] = st.Pos
			}
		}
	}
	return errors.Join(errs...)
}

// list returns the .yaml files in a directory of the project, relative to dir.
func list(dir, sub string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(dir, sub))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, sub+"/"+e.Name())
		}
	}
	return out, nil
}

func parse(dir, file string) (*yamlx.Node, error) {
	path := file
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, file)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, notFound(file)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	return yamlx.Parse(file, data)
}

type notFound string

func (f notFound) Error() string        { return string(f) + ": no such file" }
func (f notFound) Is(target error) bool { return target == fs.ErrNotExist }

func loadConfig(dir string) (*Config, error) {
	n, err := parse(dir, "winch.yaml")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w; run winch in the project directory", err)
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	return &cfg, yamlx.Decode(n, &cfg)
}

type pipelineFile struct {
	Stages []stageFile `yaml:"stages,required"`
}

type stageFile struct {
	Name     string `yaml:"name,required"`
	Hosts    string `yaml:"hosts,required"`
	HostsPos yamlx.Pos
	Steps    []*yamlx.Node `yaml:"steps,required"`
	Pos      yamlx.Pos
}

func (l *loader) loadPipeline(name string) (*Pipeline, error) {
	files, err := list(l.dir, "pipelines")
	if err != nil {
		return nil, err
	}
	file := "pipelines/" + name + ".yaml"
	if !slices.Contains(files, file) {
		var names []string
		for _, f := range files {
			names = append(names, pipelineName(f))
		}
		return nil, fmt.Errorf("unknown pipeline %q%s", name, yamlx.Suggest(name, names))
	}
	return l.decodePipeline(file)
}

func pipelineName(file string) string {
	return strings.TrimSuffix(filepath.Base(file), ".yaml")
}

func (l *loader) decodePipeline(file string) (*Pipeline, error) {
	n, err := parse(l.dir, file)
	if err != nil {
		return nil, err
	}
	var pf pipelineFile
	if err := yamlx.Decode(n, &pf); err != nil {
		return nil, err
	}
	pl := &Pipeline{Name: pipelineName(file)}
	var errs []error
	seen := map[string]bool{}
	for _, sf := range pf.Stages {
		if seen[sf.Name] {
			errs = append(errs, yamlx.Errorf(sf.Pos, "duplicate stage name %q", sf.Name))
		}
		seen[sf.Name] = true
		s := Stage{Name: sf.Name, Hosts: sf.Hosts, HostsPos: sf.HostsPos}
		for _, sn := range sf.Steps {
			st, err := l.loadStep(sn, nil)
			switch {
			case errors.Is(err, errReported):
			case err != nil:
				errs = append(errs, err)
			default:
				s.Steps = append(s.Steps, st)
			}
		}
		pl.Stages = append(pl.Stages, s)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return pl, nil
}

var stepFields = []string{"name", "recipe", "when", "loop"}

// loadStep loads a step of a stage, or of the recipe r.
func (l *loader) loadStep(n *yamlx.Node, r *Recipe) (Step, error) {
	if n.Kind != yamlx.Map {
		return Step{}, yamlx.Errorf(n.Pos, "a step must be a map, got %s", yamlx.Describe(n))
	}
	st := Step{Pos: n.Pos, in: r}
	isRecipe := slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "recipe" })
	hasLoop := slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "loop" })
	sc := scope{vars: l.vars}
	if !hasLoop {
		sc.noItem = itemOutsideLoop
	}
	var recipe string
	var recipePos yamlx.Pos
	var argsNode *yamlx.Node
	var errs []error
	for _, p := range n.Pairs {
		switch {
		case p.Key == "name":
			errs = append(errs, yamlx.Decode(p.Value, &st.Name))
			continue
		case p.Key == "when":
			var err error
			st.when, err = l.compileWhen(p.Value)
			errs = append(errs, err)
			continue
		case p.Key == "recipe" && r != nil:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a recipe cannot run another recipe; recipe steps belong in stages"))
			continue
		case p.Key == "recipe":
			errs = append(errs, yamlx.Decode(p.Value, &recipe))
			recipePos = p.Value.Pos
			continue
		case isRecipe:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a recipe step has only name, recipe, and when, not %q", p.Key))
			continue
		case p.Key == "loop":
			var err error
			st.loop, err = l.compileLoop(p.Value)
			errs = append(errs, err)
			continue
		}
		m, ok := module.New(p.Key)
		if !ok {
			errs = append(errs, yamlx.Errorf(p.KeyPos, "unknown module %q%s", p.Key, yamlx.Suggest(p.Key, append(module.Names(), stepFields...))))
			continue
		}
		if st.Module != "" {
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a step has one module; this one also has %q", st.Module))
			continue
		}
		if p.Value.Tag != "" {
			errs = append(errs, yamlx.Errorf(p.Value.Pos, "%s: the arguments are a map; put %s on single values", p.Key, p.Value.Tag))
			continue
		}
		st.Module, argsNode = p.Key, p.Value
		if err := l.loadArgs(&st, m, p.Value, sc); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Step{}, err
	}
	if isRecipe {
		var err error
		st.Recipe, err = l.recipe(recipe, recipePos)
		return st, err
	}
	if st.Module == "" {
		return Step{}, yamlx.Errorf(n.Pos, "a step needs a module")
	}
	if r == nil && st.Module == "file" {
		for _, p := range argsNode.Pairs {
			if p.Key == "template" || p.Key == "source" {
				return Step{}, yamlx.Errorf(p.Value.Pos, "%s: a step in a stage cannot use %s; use it in a recipe", p.Key, p.Key)
			}
		}
	}
	if f, ok := st.Args.(*module.File); ok {
		var err error
		if st.tmpl, err = r.content(f, st.loop != nil); err != nil {
			return Step{}, err
		}
	}
	return st, nil
}

// loadArgs decodes the arguments of a module step into m. Arguments with
// computed values decode again for each host; the load checks their keys
// and the types of the other values.
func (l *loader) loadArgs(st *Step, m module.Module, n *yamlx.Node, sc scope) error {
	v, err := compileValue(n, sc)
	if err != nil {
		return err
	}
	if v == nil {
		if err := yamlx.Decode(n, m); err != nil {
			return err
		}
		st.Args = m
		return nil
	}
	st.args = v
	return yamlx.DecodeLazy(n, m)
}

func (l *loader) compileWhen(n *yamlx.Node) (*computed, error) {
	if n.Tag != "!expr" {
		return nil, yamlx.Errorf(n.Pos, "when: use an expression with the !expr tag, such as when: !expr vars.mail_server")
	}
	return compile(n, scope{vars: l.vars, noItem: "when runs before loop; it cannot use item"})
}

func (l *loader) compileLoop(n *yamlx.Node) (*value, error) {
	if n.Tag != "!expr" && n.Kind != yamlx.List {
		return nil, yamlx.Errorf(n.Pos, "loop: use a list, or an expression with the !expr tag, such as loop: !expr vars.sites")
	}
	v, err := compileValue(n, scope{vars: l.vars, noItem: "loop cannot use item"})
	if v == nil && err == nil {
		v = &value{node: n}
	}
	return v, err
}

// reads returns the variables that the step reads by name.
func (st Step) reads() []string {
	var out []string
	if st.when != nil {
		out = append(out, st.when.reads...)
	}
	if st.loop != nil {
		out = append(out, st.loop.reads()...)
	}
	if st.args != nil {
		out = append(out, st.args.reads()...)
	}
	return out
}

// Runs reports whether the step runs on the host of e: when is true or not
// set.
func (st Step) Runs(e *Env) (bool, error) {
	if st.when == nil {
		return true, nil
	}
	out, err := st.when.eval(e)
	if err != nil {
		return false, yamlx.Errorf(st.when.pos, "when: %s", err)
	}
	b, ok := out.(bool)
	if !ok {
		return false, yamlx.Errorf(st.when.pos, "when: must be true or false, got %s", describeValue(out))
	}
	return b, nil
}

// Eval returns a module step for the host of e: none when when is false, one
// per element with loop, else one.
func (st Step) Eval(e *Env) ([]Step, error) {
	ok, err := st.Runs(e)
	if err != nil || !ok {
		return nil, err
	}
	if st.loop == nil {
		s, err := st.instance(e)
		if err != nil {
			return nil, err
		}
		return []Step{s}, nil
	}
	n, err := st.loop.eval(e, "loop")
	if err != nil {
		return nil, err
	}
	if n.Kind != yamlx.List {
		return nil, yamlx.Errorf(n.Pos, "loop: must be a list, got %s", yamlx.Describe(n))
	}
	var out []Step
	for _, item := range n.Items {
		s, err := st.instance(e.with(yamlx.Value(item)))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// instance returns the step with its arguments and content for e.
func (st Step) instance(e *Env) (Step, error) {
	if st.args != nil {
		n, err := st.args.eval(e, "")
		if err != nil {
			return Step{}, err
		}
		m, _ := module.New(st.Module)
		if err := yamlx.Decode(n, m); err != nil {
			return Step{}, err
		}
		st.Args = m
		if f, ok := m.(*module.File); ok {
			if st.tmpl, err = st.in.content(f, st.loop != nil); err != nil {
				return Step{}, err
			}
		}
	}
	if st.tmpl == nil {
		return st, nil
	}
	var b strings.Builder
	if err := st.tmpl.Execute(&b, e.templateData()); err != nil {
		return Step{}, templateError(st.tmpl.Name(), err)
	}
	f := *st.Args.(*module.File)
	// Empty output is empty content, not missing content.
	f.Data = append([]byte{}, b.String()...)
	st.Args = &f
	return st, nil
}
