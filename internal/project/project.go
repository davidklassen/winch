// Package project loads a winch project: winch.yaml, an inventory, recipes,
// and pipelines.
package project

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Project struct {
	Name      string
	Inventory *Inventory
	Pipeline  *Pipeline
	Warnings  []*yamlx.Error
	// vars are the declarations in the order in which defaults evaluate.
	vars []*Var
	// filter learns the secret values that the evaluation derives.
	filter *secret.Filter
	// secrets is true when the inventory or a default holds a !secret.
	secrets bool
	// set holds the names that --set gives.
	set map[string]bool
	// peers are the vars of each host for match(), with sealed values.
	peers map[string]map[string]any
}

type Config struct {
	Name         string `yaml:"name,required"`
	Inventory    string `yaml:"inventory"`
	InventoryPos yamlx.Pos
	Recipients   []string    `yaml:"recipients"`
	Vars         *yamlx.Node `yaml:"vars"`
}

var projectNameRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

// Validate checks the project name, which names a file on each host, and the
// recipients.
func (c *Config) Validate() error {
	if !projectNameRe.MatchString(c.Name) {
		return &yamlx.FieldError{Field: "name", Msg: `a project name has only letters, digits, ".", "_", and "-", and does not start with "."`}
	}
	if _, err := secret.ParseRecipients(c.Recipients); err != nil {
		return &yamlx.FieldError{Field: "recipients", Msg: err.Error()}
	}
	return nil
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
	Targets     []Host
	Parallelism int
	Health      *Health
	// Skipped is true for a stage that the selection leaves out.
	Skipped bool
}

// Health is the health gate of a stage. Stable and Timeout are seconds.
type Health struct {
	Command string
	Stable  int
	Timeout int
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
	// Notify are the handlers that the step notifies.
	Notify []*Handler
	// Then is the command of then, after Eval.
	Then string
	// Shown is set after Eval when the output shows a part of the step as
	// a secret.
	Shown *Shown
	// Secret is true after Eval when the evaluation of the step reads a
	// secret.
	Secret bool
	// in is the recipe that holds the step, or nil in a stage.
	in *Recipe
	// vars are the vars of a recipe step.
	vars []*Var
	args *value
	when *computed
	loop *value
	// then is the command of then, or nil.
	then *value
	// notifyNames are the handler names as written.
	notifyNames []nameAt
	tmpl        *template.Template
	// tmplReads are the variables that the template file of the step reads
	// by name. A computed file name reads those of all templates of the recipe.
	tmplReads []string
	// open is set for a file step whose mode lets others read the file.
	open *openFile
}

type openFile struct {
	pos yamlx.Pos
	// reads are the variables that the content of the file reads.
	reads []string
}

// nameAt is a handler name of notify, with the handler after the load.
type nameAt struct {
	name    string
	pos     yamlx.Pos
	handler *Handler
}

// Load reads the project in dir with one inventory and one pipeline. The
// inventory is the path in inventory, or the default from winch.yaml. set
// holds the --set flags.
func Load(ctx context.Context, dir, inventory, pipeline string, set []string, keys Keys) (*Project, error) {
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
	if err := resolve(invs[0], pl, map[*Recipe]bool{}); err != nil {
		return nil, err
	}
	if err := l.unsealAll(ctx, keys); err != nil {
		return nil, err
	}
	warnings, err := scanProject(dir, inventory, cfg)
	if err != nil {
		return nil, err
	}
	warnings = slices.Concat(warnings, l.warnings, l.secretFileWarnings(invs, []*Pipeline{pl}))
	setNames := map[string]bool{}
	for _, v := range sets {
		setNames[v.name] = true
	}
	return &Project{Name: cfg.Name, Inventory: invs[0], Pipeline: pl, Warnings: warnings, vars: l.order, filter: keys.Filter, secrets: len(l.sealed) > 0,
		set: setNames, peers: peerVars(invs[0], l.decls)}, nil
}

// Validate loads every pipeline in dir against an inventory: the one in
// inventory, the default from winch.yaml, or else every file in
// inventories/. set holds the --set flags.
func Validate(dir, inventory string, set []string) ([]*yamlx.Error, error) {
	cfg, cfgErr := loadConfig(dir)
	if cfg == nil {
		return nil, cfgErr
	}
	l, lErr := newLoader(dir, cfg)
	sets, setErr := l.parseSets(set)
	invs, invErr := l.loadInventories(inventory, cfg, true, sets)
	errs := []error{cfgErr, lErr, setErr, invErr}
	files, err := list(dir, "pipelines")
	if err != nil {
		return nil, err
	}
	var pls []*Pipeline
	checked := map[*Inventory]map[*Recipe]bool{}
	for _, inv := range invs {
		checked[inv] = map[*Recipe]bool{}
	}
	for _, file := range files {
		pl, err := l.decodePipeline(file)
		errs = append(errs, err)
		if err != nil {
			continue
		}
		pls = append(pls, pl)
		for _, inv := range invs {
			errs = append(errs, resolve(inv, pl, checked[inv]))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	warnings, err := scanProject(dir, inventory, cfg)
	if err != nil {
		return nil, err
	}
	yml, err := ymlFiles(dir)
	return slices.Concat(warnings, l.warnings, l.secretFileWarnings(invs, pls), yml), err
}

// ymlFiles returns a warning for each .yml file in pipelines/ and in a recipe
// directory. winch reads neither.
func ymlFiles(dir string) ([]*yamlx.Error, error) {
	fsys := os.DirFS(dir)
	pipelines, err := fs.Glob(fsys, "pipelines/*.yml")
	if err != nil {
		return nil, err
	}
	recipes, err := fs.Glob(fsys, "recipes/*/*.yml")
	if err != nil {
		return nil, err
	}
	var out []*yamlx.Error
	for _, file := range pipelines {
		out = append(out, yamlx.Errorf(yamlx.Pos{File: file, Line: 1, Col: 1}, "winch reads only .yaml files in pipelines/; rename it to %s.yaml", strings.TrimSuffix(path.Base(file), ".yml")))
	}
	for _, file := range recipes {
		out = append(out, yamlx.Errorf(yamlx.Pos{File: file, Line: 1, Col: 1}, "winch reads only recipe.yaml in a recipe directory"))
	}
	return out, nil
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
	// sealed are the !secret values of the variables.
	sealed   []sealedAt
	warnings []*yamlx.Error
}

// newLoader declares the variables of winch.yaml and of every recipe, then
// loads the recipes.
func newLoader(dir string, cfg *Config) (*loader, error) {
	l := &loader{dir: dir, vars: map[string]*Var{}, files: map[string]*recipeFile{}, recipes: map[string]*Recipe{}}
	errs := l.declare(cfg.Vars, "")
	errs = append(errs, l.readRecipes(), l.compileDefaults(), l.loadRecipes(), l.resolveRecipeNotify())
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
// has the required variables of its recipe. It checks the match() patterns of
// each recipe that checked does not hold yet, and adds the recipe to checked.
func resolve(inv *Inventory, pl *Pipeline, checked map[*Recipe]bool) error {
	var errs []error
	first := map[[2]string]yamlx.Pos{}
	for i := range pl.Stages {
		s := &pl.Stages[i]
		var err error
		if s.Targets, err = inv.Match(s.Hosts); err != nil {
			errs = append(errs, yamlx.Errorf(s.HostsPos, "%s", err))
		}
		for _, st := range s.Steps {
			errs = append(errs, st.checkMatches(inv))
			if st.Recipe == nil {
				continue
			}
			if !checked[st.Recipe] {
				checked[st.Recipe] = true
				for _, rs := range st.Recipe.Steps {
					errs = append(errs, rs.checkMatches(inv))
				}
				for _, h := range st.Recipe.Handlers {
					for _, hs := range h.Steps {
						errs = append(errs, hs.checkMatches(inv))
					}
				}
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
	return errors.Join(append(errs, notifyHosts(pl))...)
}

// checkMatches checks that each constant match() pattern of st matches a
// host of inv.
func (st Step) checkMatches(inv *Inventory) error {
	var cs []*computed
	if st.when != nil {
		cs = append(cs, st.when)
	}
	for _, v := range []*value{st.args, st.loop, st.then} {
		if v != nil {
			cs = slices.AppendSeq(cs, maps.Values(v.computed))
		}
	}
	for _, v := range st.vars {
		if v.computed != nil {
			cs = slices.AppendSeq(cs, maps.Values(v.computed.computed))
		}
	}
	slices.SortFunc(cs, func(a, b *computed) int {
		return cmp.Or(cmp.Compare(a.pos.Line, b.pos.Line), cmp.Compare(a.pos.Col, b.pos.Col))
	})
	var errs []error
	for _, c := range cs {
		for _, m := range c.matches {
			hosts, err := inv.Match(m.pattern)
			switch {
			case err != nil:
				errs = append(errs, yamlx.Errorf(c.pos, "match(%q): %s%s", m.pattern, err, m.snippet))
			case len(hosts) == 0:
				errs = append(errs, yamlx.Errorf(c.pos, "match(%q): the host pattern matches no host in %s%s", m.pattern, inv.File, m.snippet))
			}
		}
	}
	return errors.Join(errs...)
}

// notifyHosts checks that the recipe of each handler that a step notifies
// runs on a host of the step's stage. A stage without hosts runs nothing.
func notifyHosts(pl *Pipeline) error {
	runs := map[*Recipe]map[string]bool{}
	for _, s := range pl.Stages {
		for _, st := range s.Steps {
			if st.Recipe == nil {
				continue
			}
			if runs[st.Recipe] == nil {
				runs[st.Recipe] = map[string]bool{}
			}
			for _, h := range s.Targets {
				runs[st.Recipe][h.Name] = true
			}
		}
	}
	var errs []error
	for _, s := range pl.Stages {
		if len(s.Targets) == 0 {
			continue
		}
		for _, st := range s.Steps {
			todo := []Step{st}
			if st.Recipe != nil {
				todo = st.Recipe.Steps
			}
			for _, ts := range todo {
				errs = append(errs, notifyStage(ts, s, runs, pl.Name))
			}
		}
	}
	return errors.Join(errs...)
}

// notifyStage checks the handlers of other recipes that st in stage s
// notifies. runs holds the hosts of each recipe.
func notifyStage(st Step, s Stage, runs map[*Recipe]map[string]bool, pipeline string) error {
	var errs []error
	for _, n := range st.notifyNames {
		r := n.handler.Recipe
		if r == st.in {
			continue
		}
		onStageHost := slices.ContainsFunc(s.Targets, func(t Host) bool { return runs[r][t.Name] })
		if !onStageHost {
			errs = append(errs, yamlx.Errorf(n.pos, "notify: recipe %s runs on no host of stage %s in pipeline %s", r.Name, s.Name, pipeline))
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
	data, err := os.ReadFile(projectPath(dir, file))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, notFound(file)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	return yamlx.Parse(file, data)
}

// projectPath returns the path of file, which is absolute or relative to dir.
func projectPath(dir, file string) string {
	if filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(dir, file)
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
	Name           string `yaml:"name,required"`
	Hosts          string `yaml:"hosts,required"`
	HostsPos       yamlx.Pos
	Parallelism    *int `yaml:"parallelism"`
	ParallelismPos yamlx.Pos
	Health         *healthFile   `yaml:"health"`
	Steps          []*yamlx.Node `yaml:"steps,required"`
	Pos            yamlx.Pos
}

type healthFile struct {
	Command string `yaml:"command,required"`
	Stable  int    `yaml:"stable"`
	Timeout *int   `yaml:"timeout"`
}

// defaultTimeout is the timeout of a health gate in seconds.
const defaultTimeout = 60

func (h *healthFile) Validate() error {
	timeout := defaultTimeout
	if h.Timeout != nil {
		timeout = *h.Timeout
	}
	switch {
	case strings.TrimSpace(h.Command) == "":
		return &yamlx.FieldError{Field: "command", Msg: "must not be empty"}
	case h.Stable < 0:
		return &yamlx.FieldError{Field: "stable", Msg: "must be 0 or more seconds"}
	case timeout < 1:
		return &yamlx.FieldError{Field: "timeout", Msg: "must be 1 or more seconds"}
	case h.Stable >= timeout:
		return fmt.Errorf("health: stable must be less than timeout (%d seconds); the gate could never pass", timeout)
	}
	return nil
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
		yml := "pipelines/" + name + ".yml"
		if _, err := os.Stat(filepath.Join(l.dir, yml)); err == nil {
			return nil, fmt.Errorf("unknown pipeline %q; winch reads only .yaml files: rename %s to %s.yaml", name, yml, name)
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
	if len(pf.Stages) == 0 {
		i := slices.IndexFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "stages" })
		errs = append(errs, yamlx.Errorf(n.Pairs[i].Value.Pos, "stages: a pipeline needs at least one stage"))
	}
	seen := map[string]bool{}
	for _, sf := range pf.Stages {
		if seen[sf.Name] {
			errs = append(errs, yamlx.Errorf(sf.Pos, "duplicate stage name %q", sf.Name))
		}
		seen[sf.Name] = true
		errs = append(errs, printableName("stage", sf.Name, sf.Pos))
		s := Stage{Name: sf.Name, Hosts: sf.Hosts, HostsPos: sf.HostsPos}
		if sf.Parallelism != nil {
			if *sf.Parallelism < 1 {
				errs = append(errs, yamlx.Errorf(sf.ParallelismPos, "parallelism: must be 1 or more"))
			}
			s.Parallelism = *sf.Parallelism
		}
		if h := sf.Health; h != nil {
			s.Health = &Health{Command: h.Command, Stable: h.Stable, Timeout: defaultTimeout}
			if h.Timeout != nil {
				s.Health.Timeout = *h.Timeout
			}
		}
		for _, sn := range sf.Steps {
			st, err := l.loadStep(sn, nil, false)
			if err == nil {
				err = l.resolveNotify(&st)
			}
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

var stepFields = []string{"name", "recipe", "vars", "when", "loop", "then", "notify"}

const thenInLoop = "then runs once after the last element; it cannot use item"

// loadStep loads a step of a stage, or of the recipe r. handler is true for a
// step of a handler.
func (l *loader) loadStep(n *yamlx.Node, r *Recipe, handler bool) (Step, error) {
	if n.Kind != yamlx.Map {
		return Step{}, yamlx.Errorf(n.Pos, "a step must be a map, got %s", yamlx.Describe(n))
	}
	st := Step{Pos: n.Pos, in: r}
	isRecipe := slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "recipe" })
	hasLoop := slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "loop" })
	sc := scope{vars: l.vars}
	thenScope := scope{vars: l.vars, noItem: thenInLoop}
	if !hasLoop {
		sc.noItem = itemOutsideLoop
		thenScope.noItem = itemOutsideLoop
	}
	var recipe string
	var recipePos yamlx.Pos
	var argsNode *yamlx.Node
	// args holds the arguments without tags, also when st.Args is unset
	// because an argument is computed.
	var args module.Module
	var errs []error
	for _, p := range n.Pairs {
		switch {
		case p.Key == "name":
			errs = append(errs, yamlx.Decode(p.Value, &st.Name))
			errs = append(errs, printableName("step", st.Name, p.Value.Pos))
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
		case p.Key == "vars" && isRecipe:
			var err error
			st.vars, err = l.stepVars(p.Value)
			errs = append(errs, err)
			continue
		case p.Key == "vars":
			errs = append(errs, yamlx.Errorf(p.KeyPos, "vars: only a recipe step has vars"))
			continue
		case isRecipe:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a recipe step has only name, recipe, vars, and when, not %q", p.Key))
			continue
		case p.Key == "loop":
			var err error
			st.loop, err = l.compileLoop(p.Value)
			errs = append(errs, err)
			continue
		case p.Key == "then":
			var err error
			st.then, err = compileThen(p.Value, thenScope)
			errs = append(errs, err)
			continue
		case p.Key == "notify" && handler:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a handler step cannot notify"))
			continue
		case p.Key == "notify":
			var err error
			st.notifyNames, err = notifyNames(p.Value)
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
		st.Module, argsNode, args = p.Key, p.Value, m
		if err := l.loadArgs(&st, m, p.Value, sc); err != nil {
			errs = append(errs, err)
		}
		if p.Key == "service" && !handler {
			for _, a := range p.Value.Pairs {
				if a.Key == "restarted" || a.Key == "reloaded" {
					errs = append(errs, yamlx.Errorf(a.KeyPos, "%s: only handler steps can use %s", a.Key, a.Key))
				}
			}
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
	if r == nil {
		for _, p := range argsNode.Pairs {
			if st.Module == "file" && (p.Key == "template" || p.Key == "source") || st.Module == "repo" && p.Key == "key" {
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
	if k, ok := args.(*module.Repo); ok {
		warnings, err := r.key(k)
		if err != nil {
			return Step{}, err
		}
		l.warnings = append(l.warnings, warnings...)
	}
	if d, ok := args.(*module.Dir); ok {
		if w := d.ModeWarning(); w != "" {
			l.warnings = append(l.warnings, yamlx.Errorf(d.ModePos, "mode: %s", w))
		}
	}
	if w := skippedName(args); w != "" {
		for _, p := range argsNode.Pairs {
			if p.Key == "path" {
				l.warnings = append(l.warnings, yamlx.Errorf(p.Value.Pos, "path: %s", w))
			}
		}
	}
	if st.Module == "file" {
		st.tmplReads = r.templateReads(argsNode)
		st.open = openContent(st, args.(*module.File), argsNode)
	}
	return st, nil
}

// skippedName returns a warning for a file or a link that cron or sudo skip
// because its name has a ".", or "".
func skippedName(m module.Module) string {
	var p string
	var absent bool
	switch m := m.(type) {
	case *module.File:
		p, absent = m.Path, m.Absent
	case *module.Link:
		p, absent = m.Path, m.Absent
	}
	dir, name := path.Split(p)
	switch {
	case absent || !strings.Contains(name, "."):
		return ""
	case dir == "/etc/cron.d/":
		return `cron skips a file in /etc/cron.d whose name has a "."`
	case dir == "/etc/sudoers.d/":
		return `sudo skips a file in /etc/sudoers.d whose name has a "."`
	default:
		return ""
	}
}

// openContent returns the content reads of the file step st when its mode
// lets others read the file, or nil.
func openContent(st Step, f *module.File, n *yamlx.Node) *openFile {
	if f.Absent || !f.OthersRead() {
		return nil
	}
	pos := st.Pos
	var reads []string
	computed := false
	for _, p := range n.Pairs {
		switch {
		case p.Key == "template":
			computed = true
		case p.Key == "mode" && p.Value.Tag != "":
			return nil
		case p.Key == "mode":
			pos = p.Value.Pos
		case p.Key == "content" && st.args != nil && st.args.computed[p.Value] != nil:
			reads = st.args.computed[p.Value].reads
			computed = true
		}
	}
	reads = slices.Concat(reads, st.tmplReads)
	if computed && st.loop != nil {
		reads = append(reads, st.loop.reads()...)
	}
	if len(reads) == 0 {
		return nil
	}
	return &openFile{pos, reads}
}

// secretFileWarnings returns a warning for each file step whose content
// reads a secret variable and whose mode lets others read the file. The steps
// are those of the stages of pls and of every recipe. A variable is secret
// when a value or a default holds a !secret, or when a default or a value of
// a recipe step reads a secret variable.
func (l *loader) secretFileWarnings(invs []*Inventory, pls []*Pipeline) []*yamlx.Error {
	secret := map[string]bool{}
	for _, inv := range invs {
		for _, h := range inv.Hosts {
			for name, v := range h.Vars {
				if hasSealed(v) {
					secret[name] = true
				}
			}
		}
	}
	var steps []Step
	for _, pl := range pls {
		for _, s := range pl.Stages {
			steps = append(steps, s.Steps...)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(l.recipes)) {
		if r := l.recipes[name]; r != nil {
			steps = append(steps, r.Steps...)
			for _, h := range r.Handlers {
				steps = append(steps, h.Steps...)
			}
		}
	}
	vars := slices.Clone(l.decls)
	for _, v := range l.decls {
		if v.node == nil {
			continue
		}
		walkTags(v.node, func(t *yamlx.Node) {
			if t.Tag == "!secret" {
				secret[v.Name] = true
			}
		})
	}
	for _, st := range steps {
		vars = append(vars, st.vars...)
	}
	isSecret := func(name string) bool { return secret[name] }
	for changed := true; changed; {
		changed = false
		for _, v := range vars {
			if !secret[v.Name] && v.computed != nil && slices.ContainsFunc(v.computed.reads(), isSecret) {
				secret[v.Name], changed = true, true
			}
		}
	}
	var out []*yamlx.Error
	for _, st := range steps {
		if st.open != nil && slices.ContainsFunc(st.open.reads, isSecret) {
			out = append(out, yamlx.Errorf(st.open.pos, "the file holds a secret and others can read it; set mode"))
		}
	}
	return out
}

// stepVars loads the vars of a recipe step: declared variables and their
// values, which can be computed.
func (l *loader) stepVars(n *yamlx.Node) ([]*Var, error) {
	if n.Kind != yamlx.Map {
		return nil, yamlx.Errorf(n.Pos, "vars: expected a map, got %s", yamlx.Describe(n))
	}
	var out []*Var
	var errs []error
	for _, p := range n.Pairs {
		switch {
		case l.vars[p.Key] == nil:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "%s", unknownVariable(p.Key, l.vars)))
			continue
		case p.Value.Kind == yamlx.Null:
			errs = append(errs, yamlx.Errorf(p.Value.Pos, "variable %q: null is not a value", p.Key))
			continue
		}
		if t := findTag(p.Value); t != nil && t.Tag == "!secret" {
			errs = append(errs, yamlx.Errorf(t.Pos, "variable %q: a recipe step gives no !secret values; put the secret in the inventory", p.Key))
			continue
		}
		c, err := compileValue(p.Value, scope{vars: l.vars, noItem: itemOutsideLoop})
		errs = append(errs, err)
		out = append(out, &Var{Name: p.Key, Pos: p.KeyPos, node: p.Value, computed: c})
	}
	return out, errors.Join(errs...)
}

// sets reports whether the vars of the recipe step st set the variable name.
func (st Step) sets(name string) bool {
	return slices.ContainsFunc(st.vars, func(v *Var) bool { return v.Name == name })
}

// loadArgs decodes the arguments of a module step into m. Arguments with
// computed values decode again for each host; the load checks their keys
// and the types of the other values.
func (l *loader) loadArgs(st *Step, m module.Module, n *yamlx.Node, sc scope) error {
	sc.args = true
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

func compileThen(n *yamlx.Node, sc scope) (*value, error) {
	if n.Tag != "" {
		return compileValue(n, sc)
	}
	if _, err := thenText(n); err != nil {
		return nil, err
	}
	return &value{node: n}, nil
}

// thenText returns the command of a then node without tags.
func thenText(n *yamlx.Node) (string, error) {
	text, ok := n.Value.(string)
	switch {
	case n.Kind != yamlx.Scalar || !ok:
		return "", yamlx.Errorf(n.Pos, "then: expected a string, got %s", yamlx.Describe(n))
	case text == "":
		return "", yamlx.Errorf(n.Pos, "then: must not be empty")
	}
	return text, nil
}

// notifyNames returns the handler names of notify: a string or a list.
func notifyNames(n *yamlx.Node) ([]nameAt, error) {
	items := []*yamlx.Node{n}
	if n.Kind == yamlx.List {
		items = n.Items
	}
	var out []nameAt
	for _, it := range items {
		name, ok := it.Value.(string)
		switch {
		case it.Tag != "":
			return nil, yamlx.Errorf(it.Pos, "notify: %s is not allowed here", it.Tag)
		case it.Kind != yamlx.Scalar || !ok:
			return nil, yamlx.Errorf(it.Pos, "notify: expected a string or a list of strings, got %s", yamlx.Describe(it))
		}
		out = append(out, nameAt{name: name, pos: it.Pos})
	}
	return out, nil
}

// resolveRecipeNotify resolves the notify names of the steps of every recipe
// that loaded.
func (l *loader) resolveRecipeNotify() error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(l.recipes)) {
		r := l.recipes[name]
		if r == nil {
			continue
		}
		for i := range r.Steps {
			errs = append(errs, l.resolveNotify(&r.Steps[i]))
		}
	}
	return errors.Join(errs...)
}

// resolveNotify finds the handlers that st names: <handler> of its own
// recipe, or <recipe>.<handler>.
func (l *loader) resolveNotify(st *Step) error {
	var errs []error
	for j := range st.notifyNames {
		n := &st.notifyNames[j]
		recipe, handler, cross := strings.Cut(n.name, ".")
		r := st.in
		switch {
		case !cross && r == nil:
			errs = append(errs, yamlx.Errorf(n.pos, "notify: a step in a stage names a handler as <recipe>.<handler>, such as nginx.reload"))
			continue
		case !cross:
			handler = recipe
		default:
			var ok bool
			if r, ok = l.recipes[recipe]; !ok {
				errs = append(errs, yamlx.Errorf(n.pos, "notify: unknown recipe %q%s", recipe, yamlx.Suggest(recipe, slices.Sorted(maps.Keys(l.recipes)))))
				continue
			}
			if r == nil {
				// Its load error is reported.
				continue
			}
		}
		i := slices.IndexFunc(r.Handlers, func(h *Handler) bool { return h.Name == handler })
		if i < 0 {
			var names []string
			for _, h := range r.Handlers {
				names = append(names, h.Name)
			}
			errs = append(errs, yamlx.Errorf(n.pos, "notify: recipe %s has no handler %q%s", r.Name, handler, yamlx.Suggest(handler, names)))
			continue
		}
		n.handler = r.Handlers[i]
		if !slices.Contains(st.Notify, n.handler) {
			st.Notify = append(st.Notify, n.handler)
		}
	}
	return errors.Join(errs...)
}

func (l *loader) compileWhen(n *yamlx.Node) (*computed, error) {
	if n.Tag != "!expr" {
		return nil, yamlx.Errorf(n.Pos, "when: use an expression with the !expr tag, such as when: !expr vars.mail_server")
	}
	return compile(n, scope{
		vars:   l.vars,
		noItem: "when runs before loop; it cannot use item",
		byName: "a when reads vars only by name, such as vars.nginx_port",
	})
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
	if st.then != nil {
		out = append(out, st.then.reads()...)
	}
	out = append(out, st.tmplReads...)
	return out
}

// Runs reports whether the step runs on the host of e: when is true or not
// set.
func (st Step) Runs(e *Env) (bool, error) {
	ok, err := st.runs(e)
	return ok, e.masked(err, func(v *Env) error {
		_, err := st.runs(v)
		return err
	})
}

func (st Step) runs(e *Env) (bool, error) {
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
// per element with loop, else one. Each step that reads a secret gets Shown.
// An error shows each part that comes from a secret as secret.Mark.
func (st Step) Eval(e *Env) ([]Step, error) {
	out, err := st.eval(e)
	return out, e.masked(err, func(v *Env) error {
		_, err := st.eval(v)
		return err
	})
}

// eval returns the steps for the variant of e. In the real variant of a
// project with secrets, it also evaluates the placeholder variants for Shown.
func (st Step) eval(e *Env) ([]Step, error) {
	ok, err := st.runs(e)
	if err != nil || !ok {
		return nil, err
	}
	count := 1
	var lists [3][]any
	if st.loop != nil {
		if lists[e.n], err = st.items(e); err != nil || len(lists[e.n]) == 0 {
			return nil, err
		}
		count = len(lists[e.n])
	}
	then, err := st.thenFor(e)
	if err != nil {
		return nil, err
	}
	var thens [3]string
	variants := e.n == 0 && e.secrets
	if variants {
		thens[0] = then
		for n := 1; n < 3; n++ {
			if lists[0] != nil {
				if l, err := st.items(e.variant(n)); err == nil && len(l) == count {
					lists[n] = l
				}
			}
			if thens[n], err = st.thenFor(e.variant(n)); err != nil {
				thens[n] = secret.Placeholder(n)
			}
		}
	}
	var out []Step
	for i := range count {
		ie := e
		if st.loop != nil {
			// A variant whose loop differs uses its placeholder as item.
			var items [3]any
			for n := range items {
				items[n] = secret.Placeholder(n)
				if lists[n] != nil {
					items[n] = lists[n][i]
				}
			}
			ie = e.with(items)
		}
		s, args, err := st.instance(ie)
		if c, ok := err.(errContent); ok {
			err = c.error
		}
		if err != nil {
			return nil, err
		}
		s.Then = then
		if variants {
			s.Shown, s.Secret = st.shown(ie, s, args, thens)
		}
		out = append(out, s)
	}
	return out, nil
}

// Loops reports whether the step has loop.
func (st Step) Loops() bool { return st.loop != nil }

// items returns the elements of loop for e.
func (st Step) items(e *Env) ([]any, error) {
	n, err := st.loop.eval(e, "loop")
	if err != nil {
		return nil, err
	}
	if n.Kind != yamlx.List {
		return nil, yamlx.Errorf(n.Pos, "loop: must be a list, got %s", yamlx.Describe(n))
	}
	var out []any
	for i, item := range n.Items {
		if item.Kind == yamlx.Null {
			return nil, yamlx.Errorf(item.Pos, "loop: element %d is null", i+1)
		}
		out = append(out, yamlx.Value(item))
	}
	return out, nil
}

// thenFor returns the command of then for e, or "".
func (st Step) thenFor(e *Env) (string, error) {
	if st.then == nil {
		return "", nil
	}
	n, err := st.then.eval(e, "then")
	if err != nil {
		return "", err
	}
	return thenText(n)
}

// errContent is the error of instance when only the content fails.
type errContent struct{ error }

// instance returns the step with its arguments and content for e, and the
// computed arguments as a value, or nil. When only the content fails, the
// step has its arguments.
func (st Step) instance(e *Env) (Step, any, error) {
	var args any
	if st.args != nil {
		n, err := st.args.eval(e, "")
		if err != nil {
			return Step{}, nil, err
		}
		m, _ := module.New(st.Module)
		if err := yamlx.Decode(n, m); err != nil {
			return Step{}, nil, err
		}
		st.Args = m
		args = yamlx.Value(n)
		if f, ok := m.(*module.File); ok {
			if st.tmpl, err = st.in.content(f, st.loop != nil); err != nil {
				return Step{}, nil, err
			}
		}
		if k, ok := m.(*module.Repo); ok {
			if _, err := st.in.key(k); err != nil {
				return Step{}, nil, err
			}
		}
	}
	if st.tmpl == nil {
		return st, args, nil
	}
	out, err := e.render(st.tmpl)
	if err != nil {
		return st, args, errContent{templateError(st.tmpl.Name(), err)}
	}
	f := *st.Args.(*module.File)
	// Empty output is empty content, not missing content.
	f.Data = append([]byte{}, out...)
	st.Args = &f
	return st, args, nil
}

// shown returns how the output shows s, the step for the real variant of e,
// or nil when no part of it comes from a secret. It also reports whether the
// step reads a secret: a part comes from a secret, or a placeholder variant
// fails. real are the computed
// arguments of s, and thens the commands of then in the three variants. The
// parts that come from a secret go to the filter.
func (st Step) shown(e *Env, s Step, real any, thens [3]string) (*Shown, bool) {
	mods := [3]module.Module{s.Args}
	args := [3]any{real}
	argsOK, contentOK := true, true
	for n := 1; n < 3; n++ {
		ev := e.variant(n)
		var failed bool
		ev.failed = &failed
		v, a, err := st.instance(ev)
		if _, ok := err.(errContent); ok || failed {
			contentOK = false
		}
		if _, ok := err.(errContent); !ok && err != nil {
			argsOK, contentOK = false, false
			continue
		}
		mods[n], args[n] = v.Args, a
	}
	sh := &Shown{Main: secret.Mark}
	var parts []string
	if argsOK {
		sh.Main, _ = secret.Mask(mods[0].Main(), mods[1].Main(), mods[2].Main())
		parts = secret.Parts(args[0], args[1], args[2])
	}
	var part string
	sh.Then, part = secret.Mask(thens[0], thens[1], thens[2])
	parts = append(parts, part)
	if f, ok := s.Args.(*module.File); ok && f.Data != nil {
		var data [3][]byte
		for n := range mods {
			if g, ok := mods[n].(*module.File); ok {
				data[n] = g.Data
			}
		}
		switch {
		case !contentOK:
			sh.Hidden = true
		case !bytes.Equal(data[0], data[1]) || !bytes.Equal(data[0], data[2]):
			lines, ok := secret.Lines(data[0], data[1], data[2])
			sh.Hidden = !ok
			sh.Lines = lines
			for _, l := range lines {
				parts = append(parts, l.Part())
			}
		}
	}
	e.learn(parts)
	reads := !argsOK || !contentOK || slices.ContainsFunc(parts, func(p string) bool { return p != "" })
	if sh.Main == s.Args.Main() && sh.Then == s.Then && sh.Lines == nil && !sh.Hidden {
		return nil, reads
	}
	return sh, reads
}
