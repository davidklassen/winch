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
	"unicode/utf8"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Project struct {
	Name string
	// SSHConfig is empty, or the absolute path of the ssh_config file.
	SSHConfig string
	Inventory *Inventory
	Pipeline  *Pipeline
	// others are the other pipelines of the project, and othersErr their load
	// errors. Only dir purge and gone records need them. lost is true when a
	// pipeline did not decode, so others misses it.
	others    []*Pipeline
	othersErr error
	lost      bool
	Warnings  []*yamlx.Error
	// vars are the defaults in the order in which they evaluate, and defaults
	// the same by name.
	vars     []*Var
	defaults map[string]*Var
	// filter knows the lines of plain project text, which a line of a
	// multi-line part does not count as.
	filter *secret.Filter
	// secrets is true when the inventory or a default holds a !secret.
	secrets bool
	// set holds the names that --set gives.
	set map[string]bool
	// peers are the vars of each host for hosts and match(), with sealed
	// values.
	peers map[string]map[string]any
	reach reach
	// sums are the SHA-256 of the project files by path.
	sums     map[string]string
	setFlags []string
}

type Config struct {
	Name         string `yaml:"name,required" line:"letters, digits, ., _, and -" doc:"Letters, digits, ., _, and -. It does not start with a dot. Hosts keep pending records and other state of the project under this name."`
	Inventory    string `yaml:"inventory" line:"default for --inventory" doc:"Default for --inventory. A project with more than one inventory and no default makes every run name its inventory with --inventory."`
	InventoryPos yamlx.Pos
	Recipients   []string    `yaml:"recipients" line:"age public keys" doc:"Age public keys. winch encrypts each secret for all of them. winch secret init adds a key."`
	SSHConfig    string      `yaml:"ssh_config" line:"SSH config file for ssh -F" doc:"Path of an SSH config file, relative to the project directory. winch passes it to every ssh with -F, and ssh reads it instead of ~/.ssh/config. The file can have the line Include ~/.ssh/config. Run winch doc remote."`
	Vars         *yamlx.Node `yaml:"vars" type:"map" line:"shared variable defaults" doc:"Shared variable defaults, by name. A default can be a !secret, an !expr, or a !tpl. Run winch doc variables."`
	Inventories  *yamlx.Node `yaml:"inventories" type:"map" line:"inventories kept in winch.yaml" doc:"Inventories kept in winch.yaml, by name. The value of each is the content of an inventory file, as in inventories/<name>.yaml."`
	Pipelines    *yamlx.Node `yaml:"pipelines" type:"map" line:"pipelines kept in winch.yaml" doc:"Pipelines kept in winch.yaml, by name. The value of each is the content of a pipeline file, as in pipelines/<name>.yaml."`
	Recipes      *yamlx.Node `yaml:"recipes" type:"map" line:"recipes kept in winch.yaml" doc:"Recipes kept in winch.yaml, by name. The value of each is the content of a recipe file, as in recipes/<name>/recipe.yaml. Such a recipe has no templates/ or files/ directory. Its steps cannot use template, source, or the key of repo."`
	// The top-level inventory and pipeline. readLayout takes them from root.
	Hosts       *yamlx.Node `yaml:"hosts" type:"map" line:"hosts of the only inventory" doc:"Hosts of the only inventory, as in an inventory file. The project then has no other inventory. It can have any number of pipelines."`
	Groups      *yamlx.Node `yaml:"groups" type:"map" line:"groups of the only inventory" doc:"Groups of the only inventory, as in an inventory file."`
	Steps       *yamlx.Node `yaml:"steps" type:"list of steps" line:"steps of the only pipeline" doc:"Steps of the only pipeline. It has one stage on all hosts, and both have the name of the project. The project then has no other pipeline. Plan and apply take no pipeline name."`
	Parallelism *yamlx.Node `yaml:"parallelism" type:"integer" line:"parallelism of the only pipeline" doc:"Parallelism of the only pipeline, as in a pipeline file."`
	Health      *yamlx.Node `yaml:"health" type:"map" line:"health gate of the only pipeline" doc:"Health gate of the only pipeline, as in a pipeline file."`
	root        *yamlx.Node
	// file is winch.yaml or winch.yml.
	file string
}

const hookSecret = "a certbot hook cannot hold a secret: certbot stores its hooks in a file that other users can read; read the secret in the hook from a root-only file that a file step writes"

func (*Config) Noun() string { return "the project file" }

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
	// OnChange are the paths of on_change, after Eval.
	OnChange []string
	// Then is the command of then, after Eval.
	Then string
	// ConfirmAccess is the confirm_access of a service step.
	ConfirmAccess bool
	// Lines are the lines of the content with their masks, in the masked
	// copy of a step whose content reads a secret.
	Lines []secret.Line
	// Hidden is true in the masked copy when the output shows no part of
	// the content.
	Hidden bool
	// Parts are the parts of the arguments, then, and content that come
	// from a secret, and the lines of a multi-line part that count on their
	// own, after Eval.
	Parts []string
	// in is the recipe that holds the step, or nil in a stage.
	in *Recipe
	// masked is the copy of the step that the output shows, set after Eval
	// when the evaluation reads a secret.
	masked *Step
	// actions is set on a step with on_change and on the step of winch run.
	actions bool
	// vars are the vars of a recipe step.
	vars []*Var
	args *value
	when *computed
	loop *value
	// then is the command of then, or nil.
	then *value
	// onChange are the paths of on_change, or nil.
	onChange *value
	tmpl     *template
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
	if err := errors.Join(resolve(invs[0], pl, l.decls, map[*Recipe]bool{}), defaultMatches(invs[0], l.decls, "")); err != nil {
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
	lost := othersErr != nil
	l.warnings = l.warnings[:n]
	for _, o := range others {
		othersErr = errors.Join(othersErr, resolve(invs[0], o, l.decls, map[*Recipe]bool{}))
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
	sshConfig := cfg.SSHConfig
	if sshConfig != "" && !filepath.IsAbs(sshConfig) {
		if sshConfig, err = filepath.Abs(projectPath(dir, sshConfig)); err != nil {
			return nil, fmt.Errorf("ssh_config: %w", err)
		}
	}
	return &Project{Name: cfg.Name, SSHConfig: sshConfig, Inventory: invs[0], Pipeline: pl, others: others, othersErr: othersErr, lost: lost, Warnings: warnings, vars: l.order, defaults: l.vars, filter: keys.Filter, secrets: len(l.sealed) > 0,
		set: setNames, peers: peerVars(invs[0], l.decls), reach: l.reach, sums: sums, setFlags: set}, nil
}

// Sums returns the SHA-256 of each project file by its path.
func (p *Project) Sums() map[string]string { return p.sums }

// SetFlags returns the --set flags.
func (p *Project) SetFlags() []string { return p.setFlags }

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
			errs = append(errs, resolve(inv, pl, l.decls, checked[inv]))
		}
	}
	for _, inv := range invs {
		errs = append(errs, defaultMatches(inv, l.decls, ""))
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
	reach    reach
}

// newLoader adds the defaults of winch.yaml and of every recipe, then
// loads the recipes.
func newLoader(dir string, cfg *Config) (*loader, error) {
	l := &loader{dir: dir, file: cfg.file, vars: map[string]*Var{}, files: map[string]*recipeFile{}, recipes: map[string]*Recipe{}}
	var err error
	l.layout, err = readLayout(dir, cfg)
	errs := append([]error{err}, l.declare(cfg.Vars, "")...)
	errs = append(errs, l.readRecipes(), l.compileDefaults(), l.loadRecipes())
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
// inventories that loaded. When all is false, an inventory without hosts is an
// error; winch validate passes a new project that has no hosts yet.
func (l *loader) loadInventories(flag string, cfg *Config, all bool, set []setValue) ([]*Inventory, error) {
	var only string
	if len(l.layout.inventories) == 1 {
		only = l.layout.inventories[0].name
	}
	if name := cmp.Or(flag, cfg.Inventory, only); name != "" {
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
		if !all && len(inv.Hosts) == 0 {
			pos := cmp.Or(inv.HostsPos, p.pos, yamlx.Pos{File: p.file, Line: 1, Col: 1})
			if p.top {
				return nil, yamlx.Errorf(pos, "the project has no hosts")
			}
			return nil, yamlx.Errorf(pos, "inventory %s has no hosts", name)
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
// each recipe that checked does not hold yet, also of its defaults in decls,
// and adds the recipe to checked.
func resolve(inv *Inventory, pl *Pipeline, decls []*Var, checked map[*Recipe]bool) error {
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
				errs = append(errs, defaultMatches(inv, decls, st.Recipe.Name))
				for _, name := range slices.Sorted(maps.Keys(st.Recipe.templates)) {
					if t := st.Recipe.templates[name]; t != nil {
						errs = append(errs, matchErrors(inv, t.matches)...)
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
	return errors.Join(errs...)
}

// checkMatches checks that each constant match() pattern of st matches a
// host of inv.
func (st Step) checkMatches(inv *Inventory) error {
	var cs []*computed
	if st.when != nil {
		cs = append(cs, st.when)
	}
	for _, v := range []*value{st.args, st.loop, st.then, st.onChange} {
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
		errs = append(errs, matchErrors(inv, c.matches)...)
	}
	return errors.Join(errs...)
}

// defaultMatches checks the constant match() patterns of the defaults of the
// recipe, or of winch.yaml when recipe is empty.
func defaultMatches(inv *Inventory, decls []*Var, recipe string) error {
	var errs []error
	for _, v := range decls {
		if v.computed == nil || v.recipe != recipe {
			continue
		}
		cs := slices.SortedFunc(maps.Values(v.computed.computed), func(a, b *computed) int {
			return cmp.Or(cmp.Compare(a.pos.Line, b.pos.Line), cmp.Compare(a.pos.Col, b.pos.Col))
		})
		for _, c := range cs {
			errs = append(errs, matchErrors(inv, c.matches)...)
		}
	}
	return errors.Join(errs...)
}

// matchErrors returns an error for each constant match() pattern of calls
// that matches no host of inv.
func matchErrors(inv *Inventory, calls []matchCall) []error {
	var errs []error
	for _, m := range calls {
		hosts, err := inv.Match(m.pattern)
		switch {
		case err != nil:
			errs = append(errs, yamlx.Errorf(m.pos, "match(%q): %s%s", m.pattern, problem(err), m.snippet))
		case len(hosts) == 0:
			errs = append(errs, yamlx.Errorf(m.pos, "match(%q): the host pattern matches no host in %s%s", m.pattern, inv.File, m.snippet))
		}
	}
	return errs
}

// Reach returns the hosts that a read of hosts or match() can reach, in
// inventory order.
func (p *Project) Reach() []Host {
	if p.reach.all {
		return p.Inventory.Hosts
	}
	reached := map[string]bool{}
	for _, pattern := range p.reach.patterns {
		// A pattern that fails is a load error, or in a recipe that no
		// pipeline runs.
		hosts, _ := p.Inventory.Match(pattern)
		for _, h := range hosts {
			reached[h.Name] = true
		}
	}
	var out []Host
	for _, h := range p.Inventory.Hosts {
		if reached[h.Name] {
			out = append(out, h)
		}
	}
	return out
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

// projectPath returns the path of file, which is relative to dir.
func projectPath(dir, file string) string {
	return filepath.Join(dir, file)
}

// readProjectFile returns the path of file after links, and its content.
func readProjectFile(dir, file string) (string, []byte, error) {
	real, err := filepath.EvalSymlinks(projectPath(dir, file))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, notFound(file)
	}
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return "", nil, fmt.Errorf("read %s: %w", file, err)
	}
	return real, data, nil
}

func projectFiles(dir string) (invs, pipelines, recipes []string, err error) {
	if invs, err = list(dir, "inventories"); err != nil {
		return nil, nil, nil, err
	}
	if pipelines, err = list(dir, "pipelines"); err != nil {
		return nil, nil, nil, err
	}
	if recipes, err = recipeFiles(dir); err != nil {
		return nil, nil, nil, err
	}
	return invs, pipelines, recipes, nil
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
		return "", errors.New("the project file is both winch.yaml and winch.yml; keep one of the two")
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
}

type stageFile struct {
	Name           string `yaml:"name,required" line:"unique in the pipeline" doc:"Unique in the pipeline. It follows the rule of host names. --stages selects stages by name."`
	Hosts          string `yaml:"hosts" default:"all" line:"host pattern" doc:"Host pattern. Run winch doc inventory for the patterns."`
	HostsPos       yamlx.Pos
	Parallelism    *int `yaml:"parallelism" line:"maximum hosts at the same time" doc:"Maximum hosts at the same time. Hosts start in inventory order. The next host starts when a host finishes the stage and its health gate passes. A failure stops new hosts from starting. Running hosts finish the stage."`
	ParallelismPos yamlx.Pos
	Health         *healthFile   `yaml:"health" line:"check after a host changed in the stage" doc:"Check after a host changed in the stage. The gate runs on a host after it finishes the stage, when the stage has a change on that host. The plan marks it with * and does not run it. A gate that fails stays pending on the host, and the next apply runs it."`
	Steps          []*yamlx.Node `yaml:"steps,required" type:"list of steps" line:"recipe steps and module steps, in order" doc:"Recipe steps and module steps, in order."`
	Pos            yamlx.Pos
}

func (*stageFile) Noun() string { return "a stage" }

type healthFile struct {
	Command string `yaml:"command,required" line:"must exit 0" doc:"Must exit 0. winch runs it on the host once per second until it exits 0, then keeps running it for stable seconds. A failed run starts the wait again. An exit of 126 or 127, when sh cannot find or run the command, fails the gate at once."`
	Stable  int    `yaml:"stable" default:"0" line:"seconds the command keeps passing" doc:"Seconds the command keeps passing. It is less than timeout."`
	Timeout *int   `yaml:"timeout" default:"60" line:"seconds the gate has to pass" doc:"Seconds the gate has to pass. Then the host fails, and the error shows the end of the last output."`
}

func (*healthFile) Noun() string { return "a health gate" }

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
			Health: pf.Health, Steps: pf.Steps, Pos: n.Pos}}
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
		for _, sn := range sf.Steps {
			st, err := l.loadStep(sn, nil, plainStep)
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
	Name          string      `yaml:"name" line:"label in the plan and the logs" doc:"Label in the plan and the logs. Without it, the plan shows the module and its main argument."`
	Recipe        string      `yaml:"recipe" line:"recipe to run, in place of a module" doc:"Recipe to run, in place of a module. A recipe step has only name, recipe, vars, and when. A recipe runs at most once per host in a run."`
	Vars          *yamlx.Node `yaml:"vars" type:"map" line:"variable values for this recipe step" doc:"Variable values for this recipe step. A value can be an !expr or a !tpl, and an !expr can use match(). They beat the inventory, and --set beats them. Only a recipe step has vars."`
	When          *yamlx.Node `yaml:"when" type:"expression" line:"skips the step when false" doc:"Skips the step when false. It is an !expr that gives true or false. winch evaluates none of the other keys of a skipped step. when runs once, before loop, and cannot use item."`
	Loop          *yamlx.Node `yaml:"loop" type:"list or expression" line:"elements to run the step for, as item" doc:"Elements to run the step for, as item. An !expr gives the list. loop: [] runs nothing and changes nothing. A null element fails the host."`
	OnChange      *yamlx.Node `yaml:"on_change" type:"list of paths" line:"paths whose change the step reacts to" doc:"Absolute paths, as a list or one string. The step acts only when an earlier step of the run on its host changed one of them, or a path below one. Otherwise it checks as ok. A step changes the paths that its module writes, such as the path of a file step or /var/lib/dpkg/status for a pkg step. Every earlier step of the host counts, in any recipe or stage. A step that changes such a path after this step is a plan error. Run winch doc reactions."`
	Then          string      `yaml:"then" line:"command after a change" doc:"Command after a change. It runs right after the step changes something, before the next step: a cmd step with on_change set to the paths of the step. A failure of then fails the step. With loop, then runs once after the last element and cannot use item. A then that did not run stays pending on the host, and the next run runs it. A step whose module changes no path cannot have then; use a cmd step with on_change."`
	ConfirmAccess bool        `yaml:"confirm_access" line:"access check with rollback, for a service step" doc:"Access check with rollback, for a service step. Only a service step can use it. A firewall step gets the same check without it.\n\nBefore an earlier step changes a path that this step reacts to with on_change, winch keeps the old state of the path. Before the step, winch starts a 60-second rollback timer in a process of its own.\n\nAfter the step, winch runs the access check: it opens a new SSH connection and runs a command, through sudo -n when the login user is not root. It tries twice, 5 seconds apart.\n\nWhen both tries fail, winch puts back the old files and runs daemon-reload after a unit file. It reverses a start or a stop of the step, and reloads or restarts the unit again. The host fails with the error \"the access check failed: <error>; the old files are back\". When the SSH connection ends first, winch rolls back as it ends. When the helper is gone, the timer rolls back.\n\nWhen a run ends before a step with confirm_access that reacts to a change of the run ran, winch puts back the files of that change at once, and prints a line that names them. The next run applies the change again.\n\nA rollback puts back files only. It does not undo a change of a user or a group."`
}

var stepFields = func() []string {
	var out []string
	for _, f := range yamlx.Fields(reflect.TypeFor[stepKeys]()) {
		out = append(out, f.Name)
	}
	return out
}()

const thenInLoop = "then runs once after the last element; it cannot use item"

// stepKind tells where a step is: in a stage or a recipe, or on the command
// line of winch run.
type stepKind int

const (
	plainStep stepKind = iota
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
	has := func(key string) bool {
		return slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == key })
	}
	st := Step{Pos: n.Pos, in: r, actions: kind == runStep || has("on_change")}
	isRecipe := has("recipe")
	hasLoop := has("loop")
	sc := scope{reads: &l.reads, reach: &l.reach}
	thenScope := scope{reads: &l.reads, reach: &l.reach, noItem: thenInLoop}
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
		case p.Key == "on_change":
			var err error
			st.onChange, err = compileOnChange(p.Value, sc)
			errs = append(errs, err)
			continue
		case p.Key == "confirm_access":
			errs = append(errs, yamlx.Decode(p.Value, &st.ConfirmAccess))
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
		if p.Key == "service" && !st.actions {
			for _, a := range p.Value.Pairs {
				if a.Key == "restarted" || a.Key == "reloaded" {
					errs = append(errs, yamlx.Errorf(a.KeyPos, "%s: a step with %s needs on_change; add on_change with the paths whose change it reacts to", a.Key, a.Key))
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
	for _, p := range n.Pairs {
		if p.Key == "then" && !changesPaths(st.Module, argsNode) {
			return Step{}, yamlx.Errorf(p.KeyPos, "then needs a step that changes a path; use a cmd step")
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
	warnings, err := st.fileData(args)
	if err != nil {
		return Step{}, err
	}
	l.warnings = append(l.warnings, warnings...)
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
		if !slices.ContainsFunc(argsNode.Pairs, func(p yamlx.Pair) bool { return p.Key == "mode" }) {
			names, pos := fileSources(st, args.(*module.File), argsNode)
			for _, name := range names {
				if r.executable(name) {
					l.warnings = append(l.warnings, yamlx.Errorf(pos, `source: %s/files/%s is executable, but the step has no mode, so the host file gets 0644; set mode: "0755"`, r.Dir, name))
				}
			}
		}
		var tmplValues []string
		for _, t := range r.fileTemplates(st, argsNode) {
			st.tmplReads = append(st.tmplReads, t.reads...)
			tmplValues = slices.Concat(tmplValues, t.values, t.peerReads)
		}
		st.open = openContent(st, args.(*module.File), argsNode, tmplValues)
	}
	if st.Module == "certbot" {
		st.hooks = hookReads(st, argsNode)
	}
	return st, nil
}

// pathWarning returns a warning for the path of a step, or "": for a file or
// a link that cron or sudo skip because of its name, and for a download
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
	if absent {
		return ""
	}
	dir, name := path.Split(p)
	switch dir {
	case "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/":
		if strings.ContainsFunc(name, notRunPartsChar) {
			return "cron skips a file in " + path.Dir(p) + ` whose name has a character other than letters, digits, "_", and "-"`
		}
	case "/etc/sudoers.d/":
		if strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			return `sudo skips a file in /etc/sudoers.d whose name has a "." or ends in "~"`
		}
	}
	return ""
}

func notRunPartsChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		return false
	}
	return true
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

// openContent returns the content reads of the file step st, also of other
// hosts, when its mode lets others read the file, or nil.
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
			c := st.args.computed[p.Value]
			reads = slices.Concat(c.values, c.peerReads)
			computed = true
		}
	}
	reads = slices.Concat(reads, tmplValues)
	if computed && st.loop != nil {
		reads = slices.Concat(reads, st.loop.values(), st.loop.peerReads())
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
// a recipe step reads a secret variable, also of another host. A read of a
// field of the elements of a variable is secret when that field holds a
// secret in an element.
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
		}
	}
	for _, name := range slices.Sorted(maps.Keys(l.recipes)) {
		if r := l.recipes[name]; r != nil {
			steps = append(steps, r.Steps...)
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
			if !whole[v.Name] && v.computed != nil && (slices.ContainsFunc(v.computed.values(), isSecret) || slices.ContainsFunc(v.computed.peerReads(), isSecret)) {
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
				errs = append(errs, yamlx.Errorf(h.pos, "%s", hookSecret))
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
		l.warnNumbers(p.Key, p.Value)
		c, err := compileValue(p.Value, scope{reads: &l.reads, reach: &l.reach, noItem: itemOutsideLoop})
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

// changesPaths reports whether a step of the module with the arguments n
// changes a path: a cmd step changes only its creates and changes.
func changesPaths(name string, n *yamlx.Node) bool {
	switch name {
	case "service", "debconf", "reboot":
		return false
	case "cmd":
		return slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "creates" || p.Key == "changes" })
	}
	return true
}

// compileOnChange compiles the paths of on_change: a list, a string, or a
// value with a tag. It checks the paths that it can see at load.
func compileOnChange(n *yamlx.Node, sc scope) (*value, error) {
	if n.Tag != "" && n.Kind != yamlx.List {
		return compileValue(n, sc)
	}
	items := []*yamlx.Node{n}
	if n.Kind == yamlx.List {
		items = n.Items
		if len(items) == 0 {
			return nil, yamlx.Errorf(n.Pos, "on_change: needs at least one path")
		}
	}
	for _, it := range items {
		if it.Tag != "" {
			continue
		}
		if _, err := onChangePath(it); err != nil {
			return nil, err
		}
	}
	v, err := compileValue(n, sc)
	if v == nil && err == nil {
		v = &value{node: n}
	}
	return v, err
}

// onChangePath returns the path of an element of on_change without tags.
func onChangePath(n *yamlx.Node) (string, error) {
	text, ok := n.Value.(string)
	switch {
	case n.Kind != yamlx.Scalar || !ok:
		return "", yamlx.Errorf(n.Pos, "on_change: expected a path, got %s", yamlx.Describe(n))
	case !path.IsAbs(text):
		return "", yamlx.Errorf(n.Pos, "on_change: %q is not an absolute path", text)
	}
	return path.Clean(text), nil
}

func (l *loader) compileWhen(n *yamlx.Node) (*computed, error) {
	if n.Tag != "!expr" {
		return nil, yamlx.Errorf(n.Pos, "when: use an expression with the !expr tag, such as when: !expr vars.mail_server")
	}
	return compile(n, scope{reads: &l.reads, reach: &l.reach, noItem: "when runs before loop; it cannot use item"})
}

func (l *loader) compileLoop(n *yamlx.Node) (*value, error) {
	if n.Tag != "!expr" && n.Kind != yamlx.List {
		return nil, yamlx.Errorf(n.Pos, "loop: use a list, or an expression with the !expr tag, such as loop: !expr vars.sites")
	}
	v, err := compileValue(n, scope{reads: &l.reads, reach: &l.reach, noItem: "loop cannot use item"})
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
	if st.onChange != nil {
		out = append(out, st.onChange.reads()...)
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
// per element with loop, else one. Each step that reads a secret gets a
// masked copy. An error shows each part that comes from a secret as
// secret.Mark.
func (st Step) Eval(e *Env) ([]Step, error) {
	out, err := st.eval(e)
	if err != nil {
		return nil, e.masked(err, func(v *Env) error {
			_, err := st.eval(v)
			return err
		})
	}
	for _, s := range out {
		key := public(s)
		if key == "" {
			continue
		}
		pos := st.Pos
		if st.args != nil {
			if p := find(st.args.node, []string{key}); p != nil {
				pos = p.Value.Pos
			}
		}
		switch a := s.Args.(type) {
		case *module.Certbot:
			return nil, yamlx.Errorf(pos, "%s", hookSecret)
		case *module.Repo:
			fix := ""
			if key == "url" {
				fix = fmt.Sprintf("; for a user name and password, put them in /etc/apt/auth.conf.d/%s.conf with mode 0600", a.Name)
			}
			return nil, yamlx.Errorf(pos, "%s: a repo step cannot hold a secret: every user of the host can read %s%s", key, a.SourcePath(), fix)
		}
	}
	return out, nil
}

// Shown returns the step as the output shows it: each part that comes from a
// secret is secret.Mark.
func (st Step) Shown() Step {
	if st.masked != nil {
		return *st.masked
	}
	return st
}

// HostText returns text from the host of the step with each of the secret
// parts of its host as secret.Mark. A part of 1 or 2 characters can match text
// that does not hold it, so with such a part of its own the step shows only
// secret.Mark.
func (st Step) HostText(s string, host []string) string {
	if s == "" {
		return s
	}
	for _, p := range st.Parts {
		if utf8.RuneCountInString(p) < 3 {
			return secret.Mark
		}
	}
	return secret.Hide(s, host)
}

// public returns the argument of s that holds a secret and goes into a file
// that every user of the host can read, or "": a repo source or a certbot
// hook.
func public(s Step) string {
	switch a := s.Args.(type) {
	case *module.Repo:
		m := s.Shown().Args.(*module.Repo)
		switch {
		case m.URL != a.URL:
			return "url"
		case m.Suite != a.Suite:
			return "suite"
		case !slices.Equal(m.Components, a.Components):
			return "components"
		}
	case *module.Certbot:
		m := s.Shown().Args.(*module.Certbot)
		for _, h := range []struct {
			key         string
			real, shown *string
		}{{"pre_hook", a.PreHook, m.PreHook}, {"post_hook", a.PostHook, m.PostHook}, {"deploy_hook", a.DeployHook, m.DeployHook}} {
			if h.real != nil && *h.real != *h.shown {
				return h.key
			}
		}
	}
	return ""
}

// eval returns the steps for the variant of e. In the real variant of a
// project with secrets, it also evaluates the placeholder variants for the
// masked copy.
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
		s, args, err := st.instance(ie, yamlx.Decode)
		if err != nil {
			return nil, err
		}
		if s.OnChange, err = st.onChangeFor(ie); err != nil {
			return nil, err
		}
		s.Then = then
		if variants {
			if s.masked, err = st.shown(ie, s, args, thens); err != nil {
				return nil, err
			}
			if s.masked != nil {
				s.Parts = s.masked.Parts
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

// onChangeFor returns the paths of on_change for e, or nil.
func (st Step) onChangeFor(e *Env) ([]string, error) {
	if st.onChange == nil {
		return nil, nil
	}
	n, err := st.onChange.eval(e, "on_change")
	if err != nil {
		return nil, err
	}
	items := []*yamlx.Node{n}
	if n.Kind == yamlx.List {
		items = n.Items
	}
	if len(items) == 0 {
		return nil, yamlx.Errorf(n.Pos, "on_change: needs at least one path")
	}
	var out []string
	for _, it := range items {
		p, err := onChangePath(it)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// fileData sets the data of a file, unit, or repo step from its arguments m,
// and the template of a file step. It returns the warnings of a repo key.
func (st *Step) fileData(m module.Module) ([]*yamlx.Error, error) {
	var err error
	switch a := m.(type) {
	case *module.File:
		st.tmpl, err = st.in.content(a, st.loop != nil)
	case *module.Unit:
		err = st.in.unitContent(a)
	case *module.Repo:
		return st.in.key(a)
	}
	return nil, err
}

// instance returns the step with its arguments and content for e, and the
// computed arguments as a value, or nil. When only the content fails, the
// step has its arguments.
func (st Step) instance(e *Env, decode func(*yamlx.Node, any) error) (Step, any, error) {
	var args any
	if st.args != nil {
		n, err := st.args.eval(e, "")
		if err != nil {
			return Step{}, nil, err
		}
		args = yamlx.Value(n)
		m, _ := st.newModule(st.Module)
		if err := decode(n, m); err != nil {
			return Step{}, args, err
		}
		st.Args = m
		if _, err := st.fileData(m); err != nil {
			return Step{}, args, err
		}
	}
	if st.tmpl == nil {
		return st, args, nil
	}
	env, err := e.exprEnv(st.tmpl.hosts)
	if err != nil {
		return st, args, err
	}
	out, err := st.tmpl.exec(env)
	if err != nil {
		return st, args, err
	}
	f := *st.Args.(*module.File)
	// Empty output is empty content, not missing content.
	f.Data = append([]byte{}, out...)
	st.Args = &f
	return st, args, nil
}

// shown returns the masked copy of s, the step for the real variant of e,
// or nil when the step reads no secret: a part comes from a secret, or a
// placeholder variant fails. real are the computed arguments of s, and thens
// the commands of then in the three variants. The placeholder variants skip
// the checks of the module, which can reject a placeholder.
func (st Step) shown(e *Env, s Step, real any, thens [3]string) (*Step, error) {
	mods := [3]module.Module{s.Args}
	args := [3]any{real}
	contentOK := true
	for n := 1; n < 3; n++ {
		ev := e.variant(n)
		var failed bool
		ev.failed = &failed
		v, a, err := st.instance(ev, yamlx.DecodeUnchecked)
		if err != nil || failed {
			contentOK = false
		}
		args[n], mods[n] = a, v.Args
	}
	if u, ok := s.Args.(*module.User); ok && u.AuthorizedKeys != nil {
		u.SecretKeys = secretKeys(args)
	}
	sh := s
	var tree any
	var parts []string
	if real != nil {
		tree, parts = secret.MaskValue(args[0], args[1], args[2])
	}
	var thenParts []string
	sh.Then, thenParts = secret.MaskLines(thens[0], thens[1], thens[2])
	parts = append(parts, thenParts...)
	changes := [3]string{strings.Join(s.OnChange, "\n")}
	for n := 1; n < 3; n++ {
		paths, err := st.onChangeFor(e.variant(n))
		changes[n] = strings.Join(paths, "\n")
		if err != nil {
			changes[n] = secret.Placeholder(n)
		}
	}
	_, changeParts := secret.MaskLines(changes[0], changes[1], changes[2])
	parts = append(parts, changeParts...)
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
				parts = append(parts, l.Parts()...)
			}
		}
	}
	parts = slices.DeleteFunc(parts, func(p string) bool { return p == "" })
	if contentOK && len(parts) == 0 {
		return nil, nil
	}
	var lines []string
	for _, p := range parts {
		lines = append(lines, e.filter.Lines(p)...)
	}
	sh.Parts = append(parts, lines...)
	if real != nil {
		n, err := yamlx.FromValue(tree, st.Pos)
		if err != nil {
			return nil, err
		}
		sh.Args, _ = st.newModule(st.Module)
		// A field that cannot hold secret.Mark, such as a number, stays
		// empty.
		_ = yamlx.DecodeUnchecked(n, sh.Args)
	}
	return &sh, nil
}

// MaskedContent returns what the host keeps of the content of the step in
// place of the content: nil when the content reads no secret.
func (st Step) MaskedContent() *string {
	shown := st.Shown()
	t, ok := st.Args.(module.WithText)
	if !ok || !shown.Hidden && shown.Lines == nil {
		return nil
	}
	if _, reason := t.Text(); shown.Hidden || reason != "" {
		return new(secret.Mark + "\n")
	}
	return new(secret.Record(shown.Lines))
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

// Pipelines returns the pipeline of the run and the other pipelines of the
// project. all is false when a pipeline did not decode and is missing.
func (p *Project) Pipelines() (pipelines []*Pipeline, all bool) {
	return append([]*Pipeline{p.Pipeline}, p.others...), !p.lost
}

// Writes are the paths that the steps for a host write, sorted. Trees are
// the unpack directories of download steps: a step writes everything in
// them.
type Writes struct {
	Paths, Trees []string
}

// Written returns the paths that the steps for the host h write, in every
// pipeline of the project. A stage that the selection leaves out counts. A
// step that when skips does not count, and neither does an absent one. f and
// other are the facts as for Start.
func (p *Project) Written(h Host, f facts.Facts, other map[string]HostFacts) (Writes, error) {
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
		e, err := q.Start(h, f, other)
		if err != nil {
			return Writes{}, fmt.Errorf("pipeline %s: %w", pl.Name, err)
		}
		for _, s := range all.Stages {
			if !slices.ContainsFunc(s.Targets, func(t Host) bool { return t.Name == h.Name }) {
				continue
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
				for _, rs := range st.Recipe.Steps {
					if err := add(re, rs); err != nil {
						return Writes{}, err
					}
				}
			}
		}
	}
	return Writes{slices.Sorted(maps.Keys(seen)), slices.Sorted(maps.Keys(trees))}, nil
}
