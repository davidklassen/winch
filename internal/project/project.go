// Package project loads a winch project: winch.yaml, an inventory, and
// pipelines.
package project

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/template"
	"unicode"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Project struct {
	Name      string
	Inventory *Inventory
	Pipeline  *Pipeline
}

type Config struct {
	Name         string `yaml:"name,required"`
	Inventory    string `yaml:"inventory"`
	InventoryPos yamlx.Pos
}

type Inventory struct {
	File   string
	Hosts  []Host  `yaml:"hosts"`
	Groups []Group `yaml:"groups"`
}

type Host struct {
	Name    string `yaml:",key"`
	Address string `yaml:"address"`
	User    string `yaml:"user"`
	Pos     yamlx.Pos
}

type Group struct {
	Name  string   `yaml:",key"`
	User  string   `yaml:"user"`
	Hosts []string `yaml:"hosts"`
	Pos   yamlx.Pos
}

type Pipeline struct {
	Name   string
	Stages []Stage
	// Recipes are the recipes of each host in the pipeline.
	Recipes map[string][]*Recipe
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
	Args   module.Module
	Pos    yamlx.Pos
	Recipe *Recipe
	tmpl   *template.Template
}

// Load reads the project in dir with one inventory and one pipeline. The
// inventory is the path in inventory, or the default from winch.yaml.
func Load(dir, inventory, pipeline string) (*Project, error) {
	cfg, cfgErr := loadConfig(dir)
	if cfg == nil {
		return nil, cfgErr
	}
	invs, invErr := loadInventories(dir, inventory, cfg, false)
	l := newLoader(dir)
	pl, plErr := l.loadPipeline(pipeline)
	if err := errors.Join(cfgErr, invErr, plErr); err != nil {
		return nil, err
	}
	if err := resolve(invs[0], pl); err != nil {
		return nil, err
	}
	return &Project{Name: cfg.Name, Inventory: invs[0], Pipeline: pl}, nil
}

// Validate loads every pipeline in dir against an inventory: the one in
// inventory, the default from winch.yaml, or else every file in
// inventories/.
func Validate(dir, inventory string) error {
	cfg, cfgErr := loadConfig(dir)
	if cfg == nil {
		return cfgErr
	}
	invs, invErr := loadInventories(dir, inventory, cfg, true)
	errs := []error{cfgErr, invErr}
	files, err := list(dir, "pipelines")
	if err != nil {
		return err
	}
	l := newLoader(dir)
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

// loadInventories loads the inventory in flag, or the default from
// winch.yaml. Without both, it loads every file in inventories/ when all is
// true. It returns the inventories that loaded.
func loadInventories(dir, flag string, cfg *Config, all bool) ([]*Inventory, error) {
	switch {
	case flag != "":
		inv, err := loadInventory(dir, flag)
		if err != nil {
			return nil, err
		}
		return []*Inventory{inv}, nil
	case cfg.Inventory != "":
		inv, err := loadInventory(dir, cfg.Inventory)
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
	files, err := list(dir, "inventories")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no inventory: use --inventory, set inventory in winch.yaml, or add a file to inventories/")
	}
	var invs []*Inventory
	var errs []error
	for _, file := range files {
		inv, err := loadInventory(dir, file)
		errs = append(errs, err)
		if err == nil {
			invs = append(invs, inv)
		}
	}
	return invs, errors.Join(errs...)
}

// resolve sets the targets of every stage and the recipes of every host from
// the inventory, and checks that a recipe runs at most once per host.
func resolve(inv *Inventory, pl *Pipeline) error {
	var errs []error
	first := map[[2]string]yamlx.Pos{}
	pl.Recipes = map[string][]*Recipe{}
	for i := range pl.Stages {
		s := &pl.Stages[i]
		var err error
		s.Targets, err = inv.match(s.Hosts, s.HostsPos)
		errs = append(errs, err)
		for _, st := range s.Steps {
			if st.Recipe == nil {
				continue
			}
			for _, h := range s.Targets {
				key := [2]string{h.Name, st.Recipe.Name}
				if pos, ok := first[key]; ok {
					errs = append(errs, yamlx.Errorf(st.Pos, "recipe %s runs twice on host %s; it runs first at %s", st.Recipe.Name, h.Name, pos))
					break
				}
				first[key] = st.Pos
				pl.Recipes[h.Name] = append(pl.Recipes[h.Name], st.Recipe)
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

// validAddress is the check of OpenSSH for a destination. ssh does not check
// a HostName option, and a ProxyCommand gets it through %h.
func validAddress(s string) bool {
	if strings.HasPrefix(s, "-") {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return strings.ContainsRune("'`\"$\\;&<>|(){},", r) || unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

func loadInventory(dir, file string) (*Inventory, error) {
	n, err := parse(dir, file)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{File: file}
	if err := yamlx.Decode(n, inv); err != nil {
		return nil, err
	}
	var errs []error
	var allUser string
	for _, g := range inv.Groups {
		switch {
		case g.Name != "all":
			errs = append(errs, yamlx.Errorf(g.Pos, "unknown group %q; an inventory has only the group \"all\"", g.Name))
		case g.Hosts != nil:
			errs = append(errs, yamlx.Errorf(g.Pos, "the group all contains every host; it cannot have hosts"))
		default:
			allUser = g.User
		}
	}
	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		if h.Name == "all" {
			errs = append(errs, yamlx.Errorf(h.Pos, "host %q has the name of a group", h.Name))
		}
		if h.Address == "" {
			h.Address = h.Name
		} else if !validAddress(h.Address) {
			errs = append(errs, yamlx.Errorf(h.Pos, "host %q: address %q is not a host name or IP", h.Name, h.Address))
		}
		if h.User == "" {
			h.User = allUser
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return inv, nil
}

// match returns the hosts of a pattern: "all" or one host name.
func (inv *Inventory) match(pattern string, pos yamlx.Pos) ([]Host, error) {
	if pattern == "all" {
		return inv.Hosts, nil
	}
	names := []string{"all"}
	for _, h := range inv.Hosts {
		if h.Name == pattern {
			return []Host{h}, nil
		}
		names = append(names, h.Name)
	}
	return nil, yamlx.Errorf(pos, "unknown host or group %q in %s%s", pattern, inv.File, yamlx.Suggest(pattern, names))
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

// loader loads pipelines and the recipes they use, each recipe once.
type loader struct {
	dir string
	// recipes holds nil for a recipe that failed to load.
	recipes map[string]*Recipe
}

func newLoader(dir string) *loader {
	return &loader{dir: dir, recipes: map[string]*Recipe{}}
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

// loadStep loads a step of a stage, or of the recipe r.
func (l *loader) loadStep(n *yamlx.Node, r *Recipe) (Step, error) {
	if n.Kind != yamlx.Map {
		return Step{}, yamlx.Errorf(n.Pos, "a step must be a map, got %s", yamlx.Describe(n))
	}
	st := Step{Pos: n.Pos}
	isRecipe := slices.ContainsFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "recipe" })
	var recipe string
	var recipePos yamlx.Pos
	var errs []error
	for _, p := range n.Pairs {
		switch {
		case p.Key == "name":
			errs = append(errs, yamlx.Decode(p.Value, &st.Name))
			continue
		case p.Key == "recipe" && r != nil:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a recipe cannot run another recipe; recipe steps belong in stages"))
			continue
		case p.Key == "recipe":
			errs = append(errs, yamlx.Decode(p.Value, &recipe))
			recipePos = p.Value.Pos
			continue
		case isRecipe:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a recipe step has only name and recipe, not %q", p.Key))
			continue
		}
		m, ok := module.New(p.Key)
		if !ok {
			errs = append(errs, yamlx.Errorf(p.KeyPos, "unknown module %q%s", p.Key, yamlx.Suggest(p.Key, append(module.Names(), "name", "recipe"))))
			continue
		}
		if st.Args != nil {
			errs = append(errs, yamlx.Errorf(p.KeyPos, "a step has one module; this one also has %q", st.Module))
			continue
		}
		if err := yamlx.Decode(p.Value, m); err != nil {
			errs = append(errs, err)
			continue
		}
		st.Module, st.Args = p.Key, m
	}
	if err := errors.Join(errs...); err != nil {
		return Step{}, err
	}
	if isRecipe {
		var err error
		st.Recipe, err = l.recipe(recipe, recipePos)
		return st, err
	}
	if st.Args == nil {
		return Step{}, yamlx.Errorf(n.Pos, "a step needs a module")
	}
	if f, ok := st.Args.(*module.File); ok {
		if err := l.fileContent(f, &st, r); err != nil {
			return Step{}, err
		}
	}
	return st, nil
}

// fileContent sets the data of a file step from content or source, or parses
// its template. Only a recipe step can use template and source.
func (l *loader) fileContent(f *module.File, st *Step, r *Recipe) error {
	switch {
	case f.Content != nil:
		f.Data = []byte(*f.Content)
	case r == nil && f.Template != "":
		return yamlx.Errorf(f.TemplatePos, "template: a step in a stage cannot use template; use it in a recipe")
	case r == nil && f.Source != "":
		return yamlx.Errorf(f.SourcePos, "source: a step in a stage cannot use source; use it in a recipe")
	case f.Source != "":
		data, err := l.readRecipeFile(r, "files", f.Source)
		if err != nil {
			return yamlx.Errorf(f.SourcePos, "source: %v", err)
		}
		f.Data = data
	case f.Template != "":
		text, err := l.readRecipeFile(r, "templates", f.Template)
		if err != nil {
			return yamlx.Errorf(f.TemplatePos, "template: %v", err)
		}
		st.tmpl, err = parseTemplate(r.Dir+"/templates/"+f.Template, text)
		return err
	}
	return nil
}

// readRecipeFile reads name in the directory sub of a recipe. It does not
// follow a symbolic link out of that directory.
func (l *loader) readRecipeFile(r *Recipe, sub, name string) ([]byte, error) {
	file := r.Dir + "/" + sub + "/" + name
	f, err := os.OpenInRoot(filepath.Join(l.dir, r.Dir, sub), name)
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
