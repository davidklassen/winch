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
	"reflect"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Project struct {
	Name      string
	Inventory *Inventory
	Pipeline  *Pipeline
	// others are the other pipelines of the project, and othersErr their load
	// errors. Only dir purge needs them.
	others    []*Pipeline
	othersErr error
	Warnings  []*yamlx.Error
	// vars are the defaults in the order in which they evaluate, and defaults
	// the same by name.
	vars     []*Var
	defaults map[string]*Var
	// filter learns the secret values that the evaluation derives.
	filter *secret.Filter
	// secrets is true when the inventory or a default holds a !secret.
	secrets bool
	// set holds the names that --set gives.
	set map[string]bool
	// peers are the vars of each host for match(), with sealed values.
	peers map[string]map[string]any
	// sums are the SHA-256 of the project files by path.
	sums map[string]string
}

type Config struct {
	Name         string `yaml:"name,required" line:"letters, digits, ., _, and -" doc:"Letters, digits, ., _, and -. It does not start with a dot. Hosts keep pending handlers and other state of the project under this name."`
	Inventory    string `yaml:"inventory" line:"default for --inventory" doc:"Default for --inventory. A project with more than one inventory and no default makes every run name its inventory with --inventory."`
	InventoryPos yamlx.Pos
	Recipients   []string    `yaml:"recipients" line:"age public keys" doc:"Age public keys. winch encrypts each secret for all of them. winch secret init adds a key."`
	Vars         *yamlx.Node `yaml:"vars" type:"map" line:"shared variable defaults" doc:"Shared variable defaults, by name. A default can be a !secret, an !expr, or a !tpl. Run winch doc variables."`
	Inventories  *yamlx.Node `yaml:"inventories" type:"map" line:"inventories kept in winch.yaml" doc:"Inventories kept in winch.yaml, by name. The value of each is the content of an inventory file, as in inventories/<name>.yaml."`
	Pipelines    *yamlx.Node `yaml:"pipelines" type:"map" line:"pipelines kept in winch.yaml" doc:"Pipelines kept in winch.yaml, by name. The value of each is the content of a pipeline file, as in pipelines/<name>.yaml."`
	Recipes      *yamlx.Node `yaml:"recipes" type:"map" line:"recipes kept in winch.yaml" doc:"Recipes kept in winch.yaml, by name. The value of each is the content of a recipe file, as in recipes/<name>/recipe.yaml. Such a recipe has no templates/ or files/ directory. Its steps cannot use template, source, or the key of repo."`
	// The top-level inventory and pipeline. readLayout takes them from root.
	Hosts       *yamlx.Node `yaml:"hosts" type:"map" line:"hosts of the only inventory" doc:"Hosts of the only inventory, as in an inventory file. The project then has no other inventory. It can have any number of pipelines."`
	Groups      *yamlx.Node `yaml:"groups" type:"map" line:"groups of the only inventory" doc:"Groups of the only inventory, as in an inventory file."`
	Steps       *yamlx.Node `yaml:"steps" type:"list of steps" line:"steps of the only pipeline" doc:"Steps of the only pipeline. It has one stage on all hosts, and both have the name of the project. The project then has no other pipeline. Plan and apply take no pipeline name."`
	Handlers    *yamlx.Node `yaml:"handlers" type:"map of lists of steps" line:"handlers of the only pipeline" doc:"Handlers of the only pipeline, as in a pipeline file."`
	Parallelism *yamlx.Node `yaml:"parallelism" type:"integer" line:"parallelism of the only pipeline" doc:"Parallelism of the only pipeline, as in a pipeline file."`
	Health      *yamlx.Node `yaml:"health" type:"map" line:"health gate of the only pipeline" doc:"Health gate of the only pipeline, as in a pipeline file."`
	root        *yamlx.Node
	// file is winch.yaml or winch.yml.
	file string
}

var projectNameRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

// Validate checks the project name, which names a file on each host, and the
// recipients.
func (c *Config) Validate() error {
	if !projectNameRe.MatchString(c.Name) {
		return &yamlx.FieldError{Field: "name", Msg: "a project name has only letters, digits, ., _, and -, and does not start with ."}
	}
	if _, err := secret.ParseRecipients(c.Recipients); err != nil {
		return &yamlx.FieldError{Field: "recipients", Msg: err.Error()}
	}
	return nil
}

type Pipeline struct {
	Name   string
	Stages []Stage
	// AdHoc is true for the pipeline of winch run or winch exec.
	AdHoc bool
}

type Stage struct {
	Name     string
	Pipeline string
	Hosts    string
	HostsPos yamlx.Pos
	Steps    []Step
	// Targets are the hosts of the stage in the loaded inventory.
	Targets     []Host
	Parallelism int
	Health      *Health
	// Handlers are in declared order.
	Handlers []*Handler
	// Skipped is true for a stage that the selection leaves out.
	Skipped bool
}

// ConfirmsAccess reports whether a module step or a handler step of the
// stage has confirm_access.
func (s *Stage) ConfirmsAccess() bool {
	return slices.ContainsFunc(s.Steps, confirms) || slices.ContainsFunc(s.Handlers, (*Handler).ConfirmsAccess)
}

// handlerSteps returns the steps of the handlers of the stage.
func (s *Stage) handlerSteps() []Step {
	var out []Step
	for _, h := range s.Handlers {
		out = append(out, h.Steps...)
	}
	return out
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
	// ConfirmAccess is the confirm_access of a service step.
	ConfirmAccess bool
	// Shown is set after Eval when the output shows a part of the step as
	// a secret.
	Shown *Shown
	// Secret is true after Eval when the evaluation of the step reads a
	// secret.
	Secret bool
	// HashArgs and HashThen are the arguments and the command of then in
	// the first placeholder variant of a step that reads a secret. HashArgs
	// is the module, or the computed arguments when the module rejects them.
	HashArgs any
	HashThen string
	// in is the recipe that holds the step, or nil in a stage.
	in *Recipe
	// actions is set on a handler step and on the step of winch run.
	actions bool
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
	// open is set for a file step whose mode lets others read the file. Its
	// reads are those of the content.
	open *readsAt
	// hooks are the computed hooks of a certbot step.
	hooks []readsAt
}

// readsAt is the variables that the value at pos reads.
type readsAt struct {
	pos   yamlx.Pos
	reads []string
}

// nameAt is a handler name of notify, with the handler after the load.
type nameAt struct {
	name    string
	pos     yamlx.Pos
	handler *Handler
}

// Load reads the project in dir with one inventory and one pipeline. The
// inventory is the one named inventory, or the default from winch.yaml. set
// holds the --set flags.
func Load(ctx context.Context, dir, inventory, pipeline string, set []string, keys Keys) (*Project, error) {
	return load(ctx, dir, inventory, set, keys, true, func(l *loader) (*Pipeline, error) { return l.loadPipeline(pipeline) })
}

// Command is a winch run or winch exec on the command line: a host pattern,
// and for winch run, a module with its key=value arguments.
type Command struct {
	Name    string
	Pattern string
	Module  string
	Args    []string
}

// LoadCommand reads the project in dir with one inventory and a pipeline run.
// Its one stage run holds the step of c on the hosts of its pattern; without a
// module, the stage has no steps.
func LoadCommand(ctx context.Context, dir, inventory string, keys Keys, c Command) (*Project, error) {
	return load(ctx, dir, inventory, nil, keys, false, func(l *loader) (*Pipeline, error) { return l.commandPipeline(c) })
}

// load loads the project with the pipeline that pipeline returns, and every
// other pipeline. With own, that pipeline is one of the project and not one
// of the others.
func load(ctx context.Context, dir, inventory string, set []string, keys Keys, own bool, pipeline func(*loader) (*Pipeline, error)) (*Project, error) {
	cfg, cfgErr := loadConfig(dir)
	if cfg == nil {
		return nil, cfgErr
	}
	l, lErr := newLoader(dir, cfg)
	sets, setErr := l.parseSets(set)
	invs, invErr := l.loadInventories(inventory, cfg, false, sets)
	pl, plErr := pipeline(l)
	if err := errors.Join(cfgErr, lErr, setErr, invErr, plErr); err != nil {
		return nil, err
	}
	if err := resolve(invs[0], pl, map[*Recipe]bool{}); err != nil {
		return nil, err
	}
	// The other pipelines count only for dir purge; their warnings show in
	// winch validate.
	n := len(l.warnings)
	skip := ""
	if own {
		skip = pl.Name
	}
	others, othersErr := l.otherPipelines(skip)
	l.warnings = l.warnings[:n]
	for _, o := range others {
		othersErr = errors.Join(othersErr, resolve(invs[0], o, map[*Recipe]bool{}))
	}
	// A pipeline that fails to load logs no reads; winch validate reports it.
	if othersErr == nil {
		if err := l.checkNames(sets); err != nil {
			return nil, err
		}
	}
	plain := func([]byte) {}
	if len(l.sealed) > 0 {
		plain = keys.Filter.Plain
	}
	warnings, sums, err := scanProject(dir, cfg.file, plain)
	if err != nil {
		return nil, err
	}
	if err := l.unsealAll(ctx, keys, cfg.Recipients); err != nil {
		return nil, err
	}
	secretWarnings, err := l.secretChecks(invs, []*Pipeline{pl})
	if err != nil {
		return nil, err
	}
	warnings = slices.Concat(warnings, l.warnings, secretWarnings)
	warnings = append(warnings, purgeWarnings(invs, append([]*Pipeline{pl}, others...), []*Pipeline{pl})...)
	setNames := map[string]bool{}
	for _, v := range sets {
		setNames[v.name] = true
	}
	return &Project{Name: cfg.Name, Inventory: invs[0], Pipeline: pl, others: others, othersErr: othersErr, Warnings: warnings, vars: l.order, defaults: l.vars, filter: keys.Filter, secrets: len(l.sealed) > 0,
		set: setNames, peers: peerVars(invs[0], l.decls), sums: sums}, nil
}

// Sums returns the SHA-256 of each project file by its path.
func (p *Project) Sums() map[string]string { return p.sums }

// Filter returns the filter of the secret values.
func (p *Project) Filter() *secret.Filter { return p.filter }

// commandPipeline builds the pipeline of c. Errors name the argument as a
// position without a line, or have no position.
func (l *loader) commandPipeline(c Command) (*Pipeline, error) {
	s := Stage{Name: "run", Pipeline: "run", Hosts: c.Pattern}
	if c.Module == "" {
		return &Pipeline{Name: "run", Stages: []Stage{s}, AdHoc: true}, nil
	}
	if _, ok := module.New(c.Module); !ok {
		return nil, yamlx.Errorf(yamlx.Pos{}, "unknown module %q%s", c.Module, yamlx.Suggest(c.Module, module.Names()))
	}
	if c.Module == "assert" {
		return nil, yamlx.Errorf(yamlx.Pos{}, "assert changes nothing; run a check with winch exec")
	}
	args := &yamlx.Node{Kind: yamlx.Map, Pos: yamlx.Pos{File: c.Module}}
	var errs []error
	for _, a := range c.Args {
		pos := yamlx.Pos{File: a}
		key, text, ok := strings.Cut(a, "=")
		if !ok || key == "" {
			errs = append(errs, yamlx.Errorf(pos, "an argument is key=value, such as name=htop"))
			continue
		}
		if slices.ContainsFunc(args.Pairs, func(p yamlx.Pair) bool { return p.Key == key }) {
			errs = append(errs, yamlx.Errorf(pos, "%s is given twice", key))
			continue
		}
		n, err := parseValue(text, "winch "+c.Name, "", key)
		if err != nil {
			errs = append(errs, yamlx.Errorf(pos, "%s", err))
			continue
		}
		setPos(n, pos)
		args.Pairs = append(args.Pairs, yamlx.Pair{Key: key, KeyValue: key, KeyPos: pos, Value: n})
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	step := &yamlx.Node{Kind: yamlx.Map, Pairs: []yamlx.Pair{{Key: c.Module, KeyValue: c.Module, Value: args}}}
	st, err := l.loadStep(step, nil, runStep)
	if err != nil {
		return nil, err
	}
	s.Steps = []Step{st}
	return &Pipeline{Name: "run", Stages: []Stage{s}, AdHoc: true}, nil
}

func setPos(n *yamlx.Node, pos yamlx.Pos) {
	n.Pos = pos
	for _, item := range n.Items {
		setPos(item, pos)
	}
	for i := range n.Pairs {
		n.Pairs[i].KeyPos = pos
		setPos(n.Pairs[i].Value, pos)
	}
}

// Validate loads every pipeline in dir against an inventory: the one in
// inventory, the default from winch.yaml, or else every inventory. set holds
// the --set flags.
func Validate(dir, inventory string, set []string) ([]*yamlx.Error, error) {
	cfg, cfgErr := loadConfig(dir)
	if cfg == nil {
		return nil, cfgErr
	}
	l, lErr := newLoader(dir, cfg)
	sets, setErr := l.parseSets(set)
	invs, invErr := l.loadInventories(inventory, cfg, true, sets)
	errs := []error{cfgErr, lErr, setErr, invErr}
	var pls []*Pipeline
	checked := map[*Inventory]map[*Recipe]bool{}
	for _, inv := range invs {
		checked[inv] = map[*Recipe]bool{}
	}
	for _, p := range l.layout.pipelines {
		pl, err := l.decodePipeline(p)
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
	if err := l.checkNames(sets); err != nil {
		return nil, err
	}
	warnings, _, err := scanProject(dir, cfg.file, func([]byte) {})
	if err != nil {
		return nil, err
	}
	stale, err := l.staleSecrets(cfg.file, len(cfg.Recipients))
	if err != nil {
		return nil, err
	}
	secretWarnings, err := l.secretChecks(invs, pls)
	if err != nil {
		return nil, err
	}
	return slices.Concat(warnings, l.warnings, secretWarnings, purgeWarnings(invs, pls, pls), stale), nil
}

type loader struct {
	dir string
	// file is the project file: winch.yaml or winch.yml.
	file   string
	layout layout
	// vars are the defaults by name, decls in file order, and order in the
	// order in which they evaluate.
	vars  map[string]*Var
	decls []*Var
	order []*Var
	// reads are the reads that name a variable, and given the variable
	// values of the loaded inventories and of recipe steps.
	reads []varRead
	given []varRead
	files map[string]*recipeFile
	// recipes holds nil for a recipe that failed to load.
	recipes map[string]*Recipe
	// sealed are the !secret values of the variables.
	sealed   []sealedAt
	warnings []*yamlx.Error
}

// newLoader adds the defaults of winch.yaml and of every recipe, then
// loads the recipes.
func newLoader(dir string, cfg *Config) (*loader, error) {
	l := &loader{dir: dir, file: cfg.file, vars: map[string]*Var{}, files: map[string]*recipeFile{}, recipes: map[string]*Recipe{}}
	var err error
	l.layout, err = readLayout(dir, cfg)
	errs := append([]error{err}, l.declare(cfg.Vars, "")...)
	errs = append(errs, l.readRecipes(), l.compileDefaults(), l.loadRecipes(), l.resolveRecipeNotify())
	return l, errors.Join(errs...)
}

// noInventory is the error of a project without a default inventory and
// without exactly one inventory.
func (l *loader) noInventory() error {
	if len(l.layout.inventories) == 0 {
		return fmt.Errorf("the project has no hosts; add hosts to %s or a file to inventories/", l.file)
	}
	return fmt.Errorf("name an inventory with --inventory: %s; or set inventory in %s", strings.Join(partNames(l.layout.inventories), ", "), l.file)
}

// loadInventories loads the inventory flag, the default from winch.yaml, or
// the only inventory.
// Without any of them, it loads every inventory when all is true. It returns the
// inventories that loaded.
func (l *loader) loadInventories(flag string, cfg *Config, all bool, set []setValue) ([]*Inventory, error) {
	if name := cmp.Or(flag, cfg.Inventory, l.layout.only()); name != "" {
		p, err := l.layout.inventory(name)
		if err != nil && flag == "" {
			err = yamlx.Errorf(cfg.InventoryPos, "%s", err)
		}
		if err != nil {
			return nil, err
		}
		inv, err := l.loadInventory(p, set)
		if err != nil {
			return nil, err
		}
		return []*Inventory{inv}, nil
	}
	if len(l.layout.inventories) == 0 || !all {
		return nil, l.noInventory()
	}
	var invs []*Inventory
	var errs []error
	for _, p := range l.layout.inventories {
		inv, err := l.loadInventory(p, set)
		errs = append(errs, err)
		if err == nil {
			invs = append(invs, inv)
		}
	}
	return invs, errors.Join(errs...)
}

// resolve sets the targets of every stage from the inventory. It checks that
// a recipe runs at most once per host. It checks the match() patterns of
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
		for _, hs := range s.handlerSteps() {
			errs = append(errs, hs.checkMatches(inv))
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
				errs = append(errs, yamlx.Errorf(c.pos, "match(%q): %s%s", m.pattern, problem(err), m.snippet))
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
		if n.handler == nil {
			// Its load error is reported.
			continue
		}
		r := n.handler.Recipe
		if r == nil || r == st.in {
			continue
		}
		onStageHost := slices.ContainsFunc(s.Targets, func(t Host) bool { return runs[r][t.Name] })
		if !onStageHost {
			errs = append(errs, yamlx.Errorf(n.pos, "notify: recipe %s runs on no host of stage %s in pipeline %s", r.Name, s.Name, pipeline))
		}
	}
	return errors.Join(errs...)
}

// list returns the .yaml and .yml files in a directory of the project, relative to dir.
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
		if ext := path.Ext(e.Name()); !e.IsDir() && (ext == ".yaml" || ext == ".yml") {
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

func (f notFound) Error() string        { return string(f) + " does not exist" }
func (f notFound) Is(target error) bool { return target == fs.ErrNotExist }

func loadConfig(dir string) (*Config, error) {
	file, err := projectFile(dir)
	if err != nil {
		return nil, err
	}
	n, err := parse(dir, file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w; run winch in the project directory", err)
	}
	if err != nil {
		return nil, err
	}
	cfg := Config{root: n, file: file}
	return &cfg, yamlx.Decode(n, &cfg)
}

// projectFile returns the project file in dir: winch.yaml, or winch.yml when
// only that one exists.
func projectFile(dir string) (string, error) {
	isFile := func(name string) bool {
		info, err := os.Stat(projectPath(dir, name))
		return err == nil && !info.IsDir()
	}
	yaml, yml := isFile("winch.yaml"), isFile("winch.yml")
	switch {
	case yaml && yml:
		return "", errors.New("project file is both winch.yaml and winch.yml; keep one of the two")
	case yml:
		return "winch.yml", nil
	}
	return "winch.yaml", nil
}

// pipelineFile holds stages, or the fields of its one stage.
type pipelineFile struct {
	Stages         []stageFile `yaml:"stages" line:"stages in run order" doc:"Stages in run order. A stage starts when the previous stage finished on all its hosts. A pipeline with stages has no other key."`
	StagesPos      yamlx.Pos
	Hosts          string `yaml:"hosts" default:"all" line:"host pattern of a pipeline without stages" doc:"Host pattern of a pipeline without stages. Run winch doc inventory for the patterns."`
	HostsPos       yamlx.Pos
	Parallelism    *int `yaml:"parallelism" line:"maximum hosts at the same time" doc:"Maximum hosts at the same time. Hosts start in inventory order. The next host starts when a host finishes the stage and its health gate passes. A failure stops new hosts from starting. Running hosts finish the stage."`
	ParallelismPos yamlx.Pos
	Health         *healthFile   `yaml:"health" line:"check after a host changed in the stage" doc:"Check after a host changed in the stage. The gate runs on a host after it finishes the stage, when the stage has a change on that host. The plan marks it with * and does not run it. A gate that fails stays pending on the host, and the next apply runs it."`
	Steps          []*yamlx.Node `yaml:"steps" type:"list of steps" line:"steps of a pipeline without stages" doc:"Steps of a pipeline without stages: recipe steps and module steps, in order."`
	Handlers       *yamlx.Node   `yaml:"handlers" type:"map of lists of steps" line:"handlers of a pipeline without stages" doc:"Handlers of a pipeline without stages, as in a recipe. A module step of the stage notifies them."`
}

type stageFile struct {
	Name           string `yaml:"name,required" line:"unique in the pipeline" doc:"Unique in the pipeline. It follows the rule of host names. --stages selects stages by name."`
	Hosts          string `yaml:"hosts" default:"all" line:"host pattern" doc:"Host pattern. Run winch doc inventory for the patterns."`
	HostsPos       yamlx.Pos
	Parallelism    *int `yaml:"parallelism" line:"maximum hosts at the same time" doc:"Maximum hosts at the same time. Hosts start in inventory order. The next host starts when a host finishes the stage and its health gate passes. A failure stops new hosts from starting. Running hosts finish the stage."`
	ParallelismPos yamlx.Pos
	Health         *healthFile   `yaml:"health" line:"check after a host changed in the stage" doc:"Check after a host changed in the stage. The gate runs on a host after it finishes the stage, when the stage has a change on that host. The plan marks it with * and does not run it. A gate that fails stays pending on the host, and the next apply runs it."`
	Steps          []*yamlx.Node `yaml:"steps,required" type:"list of steps" line:"recipe steps and module steps, in order" doc:"Recipe steps and module steps, in order."`
	Handlers       *yamlx.Node   `yaml:"handlers" type:"map of lists of steps" line:"handlers of the stage" doc:"Handlers of the stage, as in a recipe. A module step of the stage notifies them."`
	Pos            yamlx.Pos
}

type healthFile struct {
	Command string `yaml:"command,required" line:"must exit 0" doc:"Must exit 0. winch runs it on the host once per second until it exits 0, then keeps running it for stable seconds. A failed run starts the wait again."`
	Stable  int    `yaml:"stable" default:"0" line:"seconds the command keeps passing" doc:"Seconds the command keeps passing. It is less than timeout."`
	Timeout *int   `yaml:"timeout" default:"60" line:"seconds the gate has to pass" doc:"Seconds the gate has to pass. Then the host fails, and the error shows the end of the last output."`
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
		return &yamlx.FieldError{Field: "command", Msg: "is empty"}
	case h.Stable < 0:
		return &yamlx.FieldError{Field: "stable", Msg: "must be 0 or more seconds"}
	}
	if err := module.CheckSeconds("timeout", timeout); err != nil {
		return err
	}
	if h.Stable >= timeout {
		return fmt.Errorf("health: stable must be less than timeout (%d seconds); the gate could never pass", timeout)
	}
	return nil
}

func (l *loader) loadPipeline(name string) (*Pipeline, error) {
	if pls := l.layout.pipelines; len(pls) > 0 && pls[0].top {
		if name != "" {
			return nil, yamlx.Errorf(yamlx.Pos{}, "pipeline %q: the steps at the top of %s are the only pipeline; leave out the pipeline name", name, l.file)
		}
		return l.decodePipeline(pls[0])
	}
	if len(l.layout.pipelines) == 0 {
		return nil, fmt.Errorf("no pipeline: add steps to %s, or a file to pipelines/", l.file)
	}
	if name == "" {
		return nil, yamlx.Errorf(yamlx.Pos{}, "name a pipeline: %s; only steps at the top of %s run without a name", strings.Join(partNames(l.layout.pipelines), ", "), l.file)
	}
	i := slices.IndexFunc(l.layout.pipelines, func(p part) bool { return p.name == name })
	if i < 0 {
		return nil, yamlx.Errorf(yamlx.Pos{}, "unknown pipeline %q%s", name, suggestOrList(name, partNames(l.layout.pipelines)))
	}
	return l.decodePipeline(l.layout.pipelines[i])
}

// otherPipelines loads every pipeline of the project other than skip.
func (l *loader) otherPipelines(skip string) ([]*Pipeline, error) {
	var out []*Pipeline
	var errs []error
	for _, p := range l.layout.pipelines {
		if p.name == skip {
			continue
		}
		pl, err := l.decodePipeline(p)
		errs = append(errs, err)
		if err == nil {
			out = append(out, pl)
		}
	}
	return out, errors.Join(errs...)
}

func (l *loader) decodePipeline(p part) (*Pipeline, error) {
	n, err := p.parse(l.dir)
	if err != nil {
		return nil, err
	}
	var pf pipelineFile
	if err := yamlx.Decode(n, &pf); err != nil {
		return nil, err
	}
	pl := &Pipeline{Name: p.name}
	var errs []error
	stages := pf.Stages
	switch {
	case pf.Stages != nil:
		if len(pf.Stages) == 0 {
			errs = append(errs, yamlx.Errorf(pf.StagesPos, "stages: a pipeline needs at least one stage"))
		}
		for _, f := range n.Pairs {
			if f.Key != "stages" {
				errs = append(errs, yamlx.Errorf(f.KeyPos, "%s: a pipeline with stages cannot have %s; put it in a stage", f.Key, f.Key))
			}
		}
	case pf.Steps == nil:
		errs = append(errs, yamlx.Errorf(n.Pos, "a pipeline needs steps or stages"))
	default:
		stages = []stageFile{{Name: p.name, Hosts: pf.Hosts, HostsPos: pf.HostsPos, Parallelism: pf.Parallelism, ParallelismPos: pf.ParallelismPos,
			Health: pf.Health, Steps: pf.Steps, Handlers: pf.Handlers, Pos: n.Pos}}
	}
	seen := map[string]bool{}
	for _, sf := range stages {
		if seen[sf.Name] {
			errs = append(errs, yamlx.Errorf(sf.Pos, "duplicate stage name %q", sf.Name))
		}
		seen[sf.Name] = true
		errs = append(errs, patternName("stage", sf.Name, sf.Pos), printableName("stage", sf.Name, sf.Pos))
		s := Stage{Name: sf.Name, Pipeline: pl.Name, Hosts: sf.Hosts, HostsPos: sf.HostsPos}
		if sf.HostsPos == (yamlx.Pos{}) {
			s.Hosts, s.HostsPos = "all", sf.Pos
		}
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
		hs, err := l.loadHandlers(sf.Handlers, nil)
		errs = append(errs, err)
		for _, h := range hs {
			h.Pipeline, h.Stage = s.Pipeline, s.Name
		}
		s.Handlers = hs
		for _, sn := range sf.Steps {
			st, err := l.loadStep(sn, nil, plainStep)
			if err == nil {
				err = l.resolveNotify(&st, &s)
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

// recipeOnly are the arguments of each module that read a recipe's files or
// templates, with the argument that a recipe in winch.yaml uses in their
// place.
var recipeOnly = map[string]map[string]string{
	"file": {"template": "content with !tpl", "source": "content"},
	"repo": {"key": "key_content"},
	"unit": {"source": "content"},
}

// stepKeys are the keys of a step other than its module, in the order of
// winch fmt. loadStep reads them by hand.
type stepKeys struct {
	Name          string        `yaml:"name" line:"label in the plan and the logs" doc:"Label in the plan and the logs. Without it, the plan shows the module and its main argument."`
	Recipe        string        `yaml:"recipe" line:"recipe to run, in place of a module" doc:"Recipe to run, in place of a module. A recipe step has only name, recipe, vars, and when. A recipe runs at most once per host in a run."`
	Vars          *yamlx.Node   `yaml:"vars" type:"map" line:"variable values for this recipe step" doc:"Variable values for this recipe step. A value can be an !expr or a !tpl, and an !expr can use match(). They beat the inventory, and --set beats them. Only a recipe step has vars."`
	When          *yamlx.Node   `yaml:"when" type:"expression" line:"skips the step when false" doc:"Skips the step when false. It is an !expr that gives true or false. winch evaluates none of the other keys of a skipped step. when runs once, before loop, and cannot use item."`
	Loop          *yamlx.Node   `yaml:"loop" type:"list or expression" line:"elements to run the step for, as item" doc:"Elements to run the step for, as item. An !expr gives the list. loop: [] runs nothing and notifies nothing. A null element fails the host."`
	Then          string        `yaml:"then" line:"command after a change" doc:"Command after a change. It runs right after the step changes something, before the next step. A failure of then fails the step. With loop, then runs once after the last element and cannot use item. A then that did not run stays pending on the host, and the next run runs it."`
	ConfirmAccess bool          `yaml:"confirm_access" line:"access check with rollback, for a service step" doc:"Access check with rollback, for a service step. Only a service step can use it, in steps or in handlers. A firewall step gets the same check without it.\n\nBefore the step, winch keeps the old state of each path that the changed steps of the recipe wrote or removed in this run. It starts a 60-second rollback timer in a process of its own.\n\nAfter the step, winch runs the access check: it opens a new SSH connection and runs a command, through sudo -n when the login user is not root. It tries twice, 5 seconds apart.\n\nWhen both tries fail, winch puts back the old files and runs daemon-reload after a unit file. It reverses a start or a stop of the step, and reloads or restarts the unit again. The host fails with the error \"the access check failed: <error>; the old files are back\". When the SSH connection ends first, winch rolls back as it ends. When the helper is gone, the timer rolls back.\n\nWhen a run ends before a notified handler with confirm_access ran, winch puts back the files of that handler at once. The next run applies the change again.\n\nA rollback puts back files only. It does not undo a change of a user or a group."`
	Notify        yamlx.Strings `yaml:"notify" line:"handlers to run after a change" doc:"Handlers to run after a change. Not a template or an expression. With loop, notify fires once when any element changed. Run winch doc handlers."`
}

var stepFields = func() []string {
	var out []string
	for _, f := range yamlx.Fields(reflect.TypeFor[stepKeys]()) {
		out = append(out, f.Name)
	}
	return out
}()

const thenInLoop = "then runs once after the last element; it cannot use item"

// stepKind tells where a step is: in a stage or a recipe, in a handler, or
// on the command line of winch run.
type stepKind int

const (
	plainStep stepKind = iota
	handlerStep
	runStep
)

// newModule returns the empty arguments of the module name for the step.
func (st Step) newModule(name string) (module.Module, bool) {
	m, ok := module.New(name)
	if s, isService := m.(*module.Service); isService {
		s.Actions = st.actions
	}
	return m, ok
}

// loadStep loads a step of a stage, or of the recipe r.
func (l *loader) loadStep(n *yamlx.Node, r *Recipe, kind stepKind) (Step, error) {
	if n.Kind != yamlx.Map {
		return Step{}, yamlx.Errorf(n.Pos, "expected a step as a map, got %s", yamlx.Describe(n))
	}
	st := Step{Pos: n.Pos, in: r, actions: kind != plainStep}
	isRecipe := slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "recipe" })
	hasLoop := slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "loop" })
	sc := scope{reads: &l.reads}
	thenScope := scope{reads: &l.reads, noItem: thenInLoop}
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
		case p.Key == "recipe" && kind == handlerStep:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a handler step cannot run a recipe"))
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
		case p.Key == "confirm_access":
			errs = append(errs, yamlx.Decode(p.Value, &st.ConfirmAccess))
			continue
		case p.Key == "notify" && kind == handlerStep:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a handler step cannot notify"))
			continue
		case p.Key == "notify":
			var err error
			st.notifyNames, err = notifyNames(p.Value)
			errs = append(errs, err)
			continue
		}
		m, ok := st.newModule(p.Key)
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
		if p.Key == "service" && kind == plainStep {
			for _, a := range p.Value.Pairs {
				if a.Key == "restarted" || a.Key == "reloaded" {
					errs = append(errs, yamlx.Errorf(a.KeyPos, "%s: only handler steps and winch run can use %s", a.Key, a.Key))
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
	if st.Module != "service" {
		for _, p := range n.Pairs {
			if p.Key == "confirm_access" {
				return Step{}, yamlx.Errorf(p.KeyPos, "confirm_access: only a service step can use it")
			}
		}
	}
	if st.Module == "assert" {
		for _, p := range n.Pairs {
			if p.Key == "then" || p.Key == "notify" {
				return Step{}, yamlx.Errorf(p.KeyPos, "an assert changes nothing; it cannot use %s", p.Key)
			}
		}
	}
	if r == nil || r.inline {
		for _, p := range argsNode.Pairs {
			alt, ok := recipeOnly[st.Module][p.Key]
			if !ok {
				continue
			}
			switch {
			case kind == runStep:
				return Step{}, yamlx.Errorf(p.Value.Pos, "works only in a recipe")
			case r != nil:
				return Step{}, yamlx.Errorf(p.Value.Pos, "a recipe in %s cannot use %s; use %s, or move the recipe to recipes/%s/", l.file, p.Key, alt, r.Name)
			}
			return Step{}, yamlx.Errorf(p.Value.Pos, "a step in a stage cannot use %s; use it in a recipe", p.Key)
		}
	}
	if f, ok := args.(*module.File); ok {
		var err error
		if st.tmpl, err = r.content(f, st.loop != nil); err != nil {
			return Step{}, err
		}
	}
	if u, ok := args.(*module.Unit); ok {
		if err := r.unitContent(u); err != nil {
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
	for _, p := range argsNode.Pairs {
		if p.Key == "path" || p.Key == "unpack" || p.Key == "creates" {
			if w := pathWarning(args); w != "" {
				l.warnings = append(l.warnings, yamlx.Errorf(p.Value.Pos, "%s: %s", p.Key, w))
			}
		}
	}
	if st.Module == "file" {
		var tmplValues []string
		for _, t := range r.fileTemplates(st, argsNode) {
			st.tmplReads = append(st.tmplReads, t.reads...)
			tmplValues = append(tmplValues, t.values...)
		}
		st.open = openContent(st, args.(*module.File), argsNode, tmplValues)
	}
	if st.Module == "certbot" {
		st.hooks = hookReads(st, argsNode)
	}
	return st, nil
}

// pathWarning returns a warning for the path of a step, or "": for a file or
// a link that cron or sudo skip because its name has a ".", and for a download
// or a cmd creates path in a directory that the host empties.
func pathWarning(m module.Module) string {
	var p string
	var absent bool
	switch m := m.(type) {
	case *module.File:
		p, absent = m.Path, m.Absent
	case *module.Link:
		p, absent = m.Path, m.Absent
	case *module.Download:
		return tempWarning(m.Main(), "downloads")
	case *module.Cmd:
		return tempWarning(m.Creates, "runs")
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

// tempWarning returns a warning for a path under a directory that the host
// empties, or "".
func tempWarning(p, verb string) string {
	for _, d := range []string{"/tmp", "/var/tmp", "/run", "/dev/shm"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return "the host removes files in " + d + ", so the step " + verb + " again; use a path such as /opt or /var/lib"
		}
	}
	return ""
}

// openContent returns the content reads of the file step st when its mode
// lets others read the file, or nil.
func openContent(st Step, f *module.File, n *yamlx.Node, tmplValues []string) *readsAt {
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
			reads = st.args.computed[p.Value].values
			computed = true
		}
	}
	reads = slices.Concat(reads, tmplValues)
	if computed && st.loop != nil {
		reads = append(reads, st.loop.values()...)
	}
	if len(reads) == 0 {
		return nil
	}
	return &readsAt{pos, reads}
}

// hookReads returns the value reads of each computed hook of the certbot
// step st.
func hookReads(st Step, n *yamlx.Node) []readsAt {
	if st.args == nil {
		return nil
	}
	var out []readsAt
	for _, p := range n.Pairs {
		c := st.args.computed[p.Value]
		if c == nil || !strings.HasSuffix(p.Key, "_hook") {
			continue
		}
		reads := c.values
		if st.loop != nil {
			reads = slices.Concat(reads, st.loop.values())
		}
		out = append(out, readsAt{p.Value.Pos, reads})
	}
	return out
}

// secretChecks returns a warning for each file step whose content reads a
// secret variable and whose mode lets others read the file, and an error for
// each certbot hook that reads a secret variable. The steps
// are those of the stages of pls and of every recipe. A variable is secret
// when a value or a default holds a !secret, or when a default or a value of
// a recipe step reads a secret variable. A read of a field of the elements of
// a variable is secret when that field holds a secret in an element.
func (l *loader) secretChecks(invs []*Inventory, pls []*Pipeline) ([]*yamlx.Error, error) {
	// whole is true for a secret variable whose secrets are not all in
	// fields of its elements. fields are the secret fields of each secret
	// variable.
	whole := map[string]bool{}
	fields := map[string]map[string]bool{}
	for _, inv := range invs {
		for _, h := range inv.Hosts {
			for name, v := range h.Vars {
				if !hasSealed(v) {
					continue
				}
				if fields[name] == nil {
					fields[name] = map[string]bool{}
				}
				if !sealedFields(v, fields[name]) {
					whole[name] = true
				}
			}
		}
	}
	var steps []Step
	for _, pl := range pls {
		for _, s := range pl.Stages {
			steps = append(steps, s.Steps...)
			steps = append(steps, s.handlerSteps()...)
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
		walkTags(v.node, func(t *yamlx.Node) {
			if t.Tag == "!secret" {
				whole[v.Name] = true
			}
		})
	}
	for _, st := range steps {
		vars = append(vars, st.vars...)
	}
	isSecret := func(read string) bool {
		name, field, ok := strings.Cut(read, ".")
		if !ok {
			return whole[name] || fields[name] != nil
		}
		return whole[name] || fields[name][field]
	}
	for changed := true; changed; {
		changed = false
		for _, v := range vars {
			if !whole[v.Name] && v.computed != nil && slices.ContainsFunc(v.computed.values(), isSecret) {
				whole[v.Name], changed = true, true
			}
		}
	}
	var out []*yamlx.Error
	var errs []error
	for _, st := range steps {
		if st.open != nil && slices.ContainsFunc(st.open.reads, isSecret) {
			out = append(out, yamlx.Errorf(st.open.pos, "the file holds a secret and others can read it; set mode"))
		}
		for _, h := range st.hooks {
			if slices.ContainsFunc(h.reads, isSecret) {
				errs = append(errs, yamlx.Errorf(h.pos, "certbot stores its hooks in a file that other users can read"))
			}
		}
	}
	return out, errors.Join(errs...)
}

// stepVars loads the vars of a recipe step: variables and their values, which
// can be computed.
func (l *loader) stepVars(n *yamlx.Node) ([]*Var, error) {
	if n.Kind != yamlx.Map {
		return nil, yamlx.Errorf(n.Pos, "vars: expected a map, got %s", yamlx.Describe(n))
	}
	var out []*Var
	var errs []error
	for _, p := range n.Pairs {
		l.given = append(l.given, varRead{name: p.Key, pos: p.KeyPos})
		if p.Value.Kind == yamlx.Null {
			errs = append(errs, yamlx.Errorf(p.Value.Pos, "vars.%s: null is not a value", p.Key))
			continue
		}
		if t := findTag(p.Value); t != nil && t.Tag == "!secret" {
			errs = append(errs, yamlx.Errorf(t.Pos, "vars.%s: a recipe step gives no !secret values; put the secret in the inventory", p.Key))
			continue
		}
		c, err := compileValue(p.Value, scope{reads: &l.reads, noItem: itemOutsideLoop})
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
		return "", yamlx.Errorf(n.Pos, "then: is empty")
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
			errs = append(errs, l.resolveNotify(&r.Steps[i], nil))
		}
	}
	return errors.Join(errs...)
}

// resolveNotify finds the handlers that st names: <handler> of its own
// recipe, or of stage for a step of a stage, or <recipe>.<handler>.
func (l *loader) resolveNotify(st *Step, stage *Stage) error {
	var errs []error
	for j := range st.notifyNames {
		n := &st.notifyNames[j]
		recipe, handler, cross := strings.Cut(n.name, ".")
		var handlers []*Handler
		var owner string
		switch {
		case !cross && st.in == nil:
			handler, handlers, owner = recipe, stage.Handlers, "stage "+stage.Name
		case !cross:
			handler, handlers, owner = recipe, st.in.Handlers, "recipe "+st.in.Name
		default:
			r, ok := l.recipes[recipe]
			if !ok {
				errs = append(errs, yamlx.Errorf(n.pos, "notify: unknown recipe %q%s", recipe, yamlx.Suggest(recipe, slices.Sorted(maps.Keys(l.recipes)))))
				continue
			}
			if r == nil {
				// Its load error is reported.
				continue
			}
			handlers, owner = r.Handlers, "recipe "+r.Name
		}
		i := slices.IndexFunc(handlers, func(h *Handler) bool { return h.Name == handler })
		if i < 0 {
			var names []string
			for _, h := range handlers {
				names = append(names, h.Name)
			}
			errs = append(errs, yamlx.Errorf(n.pos, "notify: %s has no handler %q%s", owner, handler, yamlx.Suggest(handler, names)))
			continue
		}
		n.handler = handlers[i]
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
	return compile(n, scope{reads: &l.reads, noItem: "when runs before loop; it cannot use item"})
}

func (l *loader) compileLoop(n *yamlx.Node) (*value, error) {
	if n.Tag != "!expr" && n.Kind != yamlx.List {
		return nil, yamlx.Errorf(n.Pos, "loop: use a list, or an expression with the !expr tag, such as loop: !expr vars.sites")
	}
	v, err := compileValue(n, scope{reads: &l.reads, noItem: "loop cannot use item"})
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
		return false, yamlx.Errorf(st.when.pos, "when: expected true or false, got %s", describeValue(out))
	}
	return b, nil
}

// Eval returns a module step for the host of e: none when when is false, one
// per element with loop, else one. Each step that reads a secret gets Shown.
// An error shows each part that comes from a secret as secret.Mark.
func (st Step) Eval(e *Env) ([]Step, error) {
	out, err := st.eval(e)
	if err != nil {
		return nil, e.masked(err, func(v *Env) error {
			_, err := st.eval(v)
			return err
		})
	}
	for _, s := range out {
		if s.Shown == nil || s.Shown.Public == "" {
			continue
		}
		pos := st.Pos
		if st.args != nil {
			if p := find(st.args.node, []string{s.Shown.Public}); p != nil {
				pos = p.Value.Pos
			}
		}
		if _, ok := s.Args.(*module.Certbot); ok {
			return nil, yamlx.Errorf(pos, "certbot stores its hooks in a file that other users can read")
		}
		return nil, yamlx.Errorf(pos, "%s: holds a secret, and every user of the host can read the source file", s.Shown.Public)
	}
	return out, nil
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
			var hash any
			s.Shown, s.Secret, hash = st.shown(ie, s, args, thens)
			if s.Secret {
				s.HashArgs, s.HashThen = hash, thens[1]
			}
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
		return nil, yamlx.Errorf(n.Pos, "loop: expected a list, got %s", yamlx.Describe(n))
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
		args = yamlx.Value(n)
		m, _ := st.newModule(st.Module)
		if err := yamlx.Decode(n, m); err != nil {
			return Step{}, args, err
		}
		st.Args = m
		if f, ok := m.(*module.File); ok {
			if st.tmpl, err = st.in.content(f, st.loop != nil); err != nil {
				return Step{}, nil, err
			}
		}
		if u, ok := m.(*module.Unit); ok {
			if err := st.in.unitContent(u); err != nil {
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
// fails, and it returns the HashArgs of s. real are the computed arguments
// of s, and thens the commands of then in the three variants. The parts that
// come from a secret go to the filter.
func (st Step) shown(e *Env, s Step, real any, thens [3]string) (*Shown, bool, any) {
	mods := [3]module.Module{s.Args}
	args := [3]any{real}
	argsOK, contentOK := true, true
	for n := 1; n < 3; n++ {
		ev := e.variant(n)
		var failed bool
		ev.failed = &failed
		v, a, err := st.instance(ev)
		args[n] = a
		if _, ok := err.(errContent); ok || failed {
			contentOK = false
		}
		if _, ok := err.(errContent); !ok && err != nil {
			argsOK, contentOK = false, false
			continue
		}
		mods[n] = v.Args
	}
	if u, ok := s.Args.(*module.User); ok && u.AuthorizedKeys != nil {
		u.SecretKeys = secretKeys(args)
	}
	sh := &Shown{Main: secret.Mark}
	validate := s.ShownValidate()
	if validate != "" {
		sh.Validate = secret.Mark
	}
	unless := s.ShownUnless()
	if unless != "" {
		sh.Unless = secret.Mark
	}
	var parts []string
	if argsOK {
		sh.Main, _ = secret.MaskLines(mods[0].Main(), mods[1].Main(), mods[2].Main())
		if validate != "" {
			sh.Validate, _ = secret.MaskLines(validate, mods[1].(module.WithValidate).ValidateCommand(), mods[2].(module.WithValidate).ValidateCommand())
		}
		if unless != "" {
			sh.Unless, _ = secret.MaskLines(unless, mods[1].(*module.Cmd).UnlessCommand(), mods[2].(*module.Cmd).UnlessCommand())
		}
		parts = secret.Parts(args[0], args[1], args[2])
	}
	var thenParts []string
	sh.Then, thenParts = secret.MaskLines(thens[0], thens[1], thens[2])
	parts = append(parts, thenParts...)
	var data [3][]byte
	for n := range mods {
		if t, ok := mods[n].(module.WithText); ok {
			data[n], _ = t.Text()
		}
	}
	if data[0] != nil {
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
	switch a := s.Args.(type) {
	case *module.Repo:
		sh.Public = publicRepo(a, mods, argsOK)
	case *module.Certbot:
		sh.Public = st.publicHook(e)
	}
	e.learn(parts)
	reads := !argsOK || !contentOK || slices.ContainsFunc(parts, func(p string) bool { return p != "" })
	hash := args[1]
	if mods[1] != nil {
		hash = mods[1]
	}
	if sh.Main == s.Args.Main() && sh.Then == s.Then && sh.Validate == validate && sh.Unless == unless && sh.Lines == nil && !sh.Hidden && sh.Public == "" {
		return nil, reads, hash
	}
	return sh, reads, hash
}

// secretKeys marks the authorized_keys elements of the arguments real that
// differ from the placeholder variants. When a variant has another number of
// elements, each element is from a secret.
func secretKeys(args [3]any) []bool {
	var lists [3][]any
	for n, a := range args {
		m, _ := a.(map[string]any)
		lists[n], _ = m["authorized_keys"].([]any)
	}
	var out []bool
	same := len(lists[1]) == len(lists[0]) && len(lists[2]) == len(lists[0])
	for i, k := range lists[0] {
		out = append(out, !same || k != lists[1][i] || k != lists[2][i])
	}
	return out
}

// publicRepo returns the argument of r, the repo of the real variant, that
// holds a secret: one that differs in the variants mods. When a variant
// fails, it returns "repo".
func publicRepo(r *module.Repo, mods [3]module.Module, argsOK bool) string {
	if !argsOK {
		return "repo"
	}
	for _, m := range mods[1:] {
		v := m.(*module.Repo)
		switch {
		case v.URL != r.URL:
			return "url"
		case v.Suite != r.Suite:
			return "suite"
		case !slices.Equal(v.Components, r.Components):
			return "components"
		}
	}
	return ""
}

// publicHook returns the hook of st, a certbot step, that holds a secret: one
// that differs in the variants of e, or fails to evaluate in one. It
// evaluates each hook on its own: a placeholder in another argument, such as
// email, can fail that argument.
func (st Step) publicHook(e *Env) string {
	if st.args == nil {
		return ""
	}
	for _, p := range st.args.node.Pairs {
		if st.args.computed[p.Value] == nil || !strings.HasSuffix(p.Key, "_hook") {
			continue
		}
		real, _ := st.args.evalNode(p.Value, e, p.Key)
		for n := 1; n < 3; n++ {
			v, err := st.args.evalNode(p.Value, e.variant(n), p.Key)
			if err != nil || !reflect.DeepEqual(yamlx.Value(real), yamlx.Value(v)) {
				return p.Key
			}
		}
	}
	return ""
}

// Writes are the paths that the steps for a host write, sorted. Trees are
// the unpack directories of download steps: a step writes everything in
// them.
type Writes struct {
	Paths, Trees []string
}

// Written returns the paths that the steps for the host h write, in every
// pipeline of the project. A stage that the selection leaves out counts. A
// step that when skips does not count, and neither does an absent one.
func (p *Project) Written(h Host, f facts.Facts) (Writes, error) {
	if p.othersErr != nil {
		return Writes{}, p.othersErr
	}
	seen, trees := map[string]bool{}, map[string]bool{}
	add := func(e *Env, st Step) error {
		steps, err := st.Eval(e)
		if err != nil {
			return err
		}
		for _, s := range steps {
			if w, ok := s.Args.(module.Writer); ok {
				for _, p := range w.Writes() {
					seen[p] = true
				}
			}
			if d, ok := s.Args.(*module.Download); ok && d.Unpack != "" {
				trees[d.Unpack] = true
			}
		}
		return nil
	}
	for _, pl := range append([]*Pipeline{p.Pipeline}, p.others...) {
		all := *pl
		all.Stages = slices.Clone(pl.Stages)
		for i := range all.Stages {
			all.Stages[i].Skipped = false
		}
		q := *p
		q.Pipeline = &all
		e, err := q.Start(h, f)
		if err != nil {
			return Writes{}, fmt.Errorf("pipeline %s: %w", pl.Name, err)
		}
		for _, s := range all.Stages {
			if !slices.ContainsFunc(s.Targets, func(t Host) bool { return t.Name == h.Name }) {
				continue
			}
			for _, hs := range s.handlerSteps() {
				if err := add(e, hs); err != nil {
					return Writes{}, err
				}
			}
			for i := range s.Steps {
				st := &s.Steps[i]
				if st.Recipe == nil {
					if err := add(e, *st); err != nil {
						return Writes{}, err
					}
					continue
				}
				ok, err := st.Runs(e)
				if err != nil {
					return Writes{}, err
				}
				if !ok {
					continue
				}
				re := e.For(st)
				steps := slices.Clone(st.Recipe.Steps)
				for _, hd := range st.Recipe.Handlers {
					steps = append(steps, hd.Steps...)
				}
				for _, rs := range steps {
					if err := add(re, rs); err != nil {
						return Writes{}, err
					}
				}
			}
		}
	}
	return Writes{slices.Sorted(maps.Keys(seen)), slices.Sorted(maps.Keys(trees))}, nil
}
