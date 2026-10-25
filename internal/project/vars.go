package project

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/yamlx"
)

// Var is the declaration of a variable, in winch.yaml or in a recipe.
type Var struct {
	Name string
	Pos  yamlx.Pos
	// Recipe is empty for a variable of winch.yaml.
	Recipe string
	// node is the default, or nil for a required variable.
	node *yamlx.Node
	// computed is the default when it holds tagged values.
	computed *value
}

func (v *Var) required() bool { return v.node == nil }

var varNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// declare adds the declarations in n, a map of names to defaults. recipe is
// empty for winch.yaml.
func (l *loader) declare(n *yamlx.Node, recipe string) []error {
	if n == nil || n.Kind == yamlx.Null {
		return nil
	}
	if n.Kind != yamlx.Map {
		return []error{yamlx.Errorf(n.Pos, "vars: expected a map, got %s", yamlx.Describe(n))}
	}
	var errs []error
	for _, p := range n.Pairs {
		switch {
		case !varNameRe.MatchString(p.Key):
			errs = append(errs, yamlx.Errorf(p.KeyPos, "variable %q: a variable name has only lowercase letters, digits, and _", p.Key))
			continue
		case recipe != "" && !strings.HasPrefix(p.Key, recipe+"_"):
			errs = append(errs, yamlx.Errorf(p.KeyPos, "variable %q: a variable of recipe %s starts with %q", p.Key, recipe, recipe+"_"))
			continue
		}
		if first, ok := l.vars[p.Key]; ok {
			errs = append(errs, yamlx.Errorf(p.KeyPos, "variable %q is declared twice; it is first declared at %s", p.Key, first.Pos))
			continue
		}
		v := &Var{Name: p.Key, Pos: p.KeyPos, Recipe: recipe}
		if p.Value.Kind != yamlx.Null {
			v.node = p.Value
		}
		l.vars[p.Key] = v
		l.decls = append(l.decls, v)
	}
	return errs
}

// compileDefaults compiles the defaults and puts the declarations in the
// order in which defaults evaluate. A cycle between defaults is an error.
func (l *loader) compileDefaults() error {
	var errs []error
	sc := scope{vars: l.vars, noItem: "a default cannot use item"}
	for _, v := range l.decls {
		if v.node == nil {
			continue
		}
		c, err := compileValue(v.node, sc)
		errs = append(errs, err)
		v.computed = c
	}
	const (
		visiting = 1
		done     = 2
	)
	state := map[*Var]int{}
	var order []*Var
	var path []*Var
	var visit func(v *Var)
	visit = func(v *Var) {
		switch state[v] {
		case done:
			return
		case visiting:
			i := slices.Index(path, v)
			var cycle []string
			for _, p := range path[i:] {
				cycle = append(cycle, p.Name)
			}
			errs = append(errs, yamlx.Errorf(v.Pos, "variable %q: the defaults form a cycle: %s → %s", v.Name, strings.Join(cycle, " → "), v.Name))
			return
		}
		state[v] = visiting
		path = append(path, v)
		if v.computed != nil {
			for _, name := range v.computed.reads() {
				visit(l.vars[name])
			}
		}
		path = path[:len(path)-1]
		state[v] = done
		order = append(order, v)
	}
	for _, v := range l.decls {
		visit(v)
	}
	l.order = order
	return errors.Join(errs...)
}

// setValue is a value from --set.
type setValue struct {
	name  string
	value any
}

func (l *loader) parseSets(set []string) ([]setValue, error) {
	var out []setValue
	var errs []error
	for _, s := range set {
		key, text, ok := strings.Cut(s, "=")
		name, isVar := strings.CutPrefix(key, "vars.")
		if !ok || !isVar {
			errs = append(errs, fmt.Errorf("--set %s: use --set vars.<name>=<value>", s))
			continue
		}
		if _, ok := l.vars[name]; !ok {
			errs = append(errs, fmt.Errorf("--set %s: %s", s, unknownVariable(name, l.vars)))
			continue
		}
		n, err := yamlx.Parse("--set", []byte(text))
		if err != nil {
			msg := err.Error()
			if ye, ok := errors.AsType[*yamlx.Error](err); ok {
				msg = ye.Msg
			}
			errs = append(errs, fmt.Errorf("--set %s: %s", s, msg))
			continue
		}
		if n.Kind == yamlx.Null {
			errs = append(errs, fmt.Errorf("--set %s: null is not a value", s))
			continue
		}
		if t := findTag(n); t != nil {
			errs = append(errs, fmt.Errorf("--set %s: --set gives no %s values", s, t.Tag))
			continue
		}
		out = append(out, setValue{name: name, value: yamlx.Value(n)})
	}
	return out, errors.Join(errs...)
}

// findTag returns the first tagged scalar in n, or nil.
func findTag(n *yamlx.Node) *yamlx.Node {
	switch {
	case n.Tag != "":
		return n
	case n.Kind == yamlx.Map:
		for _, p := range n.Pairs {
			if t := findTag(p.Value); t != nil {
				return t
			}
		}
	case n.Kind == yamlx.List:
		for _, item := range n.Items {
			if t := findTag(item); t != nil {
				return t
			}
		}
	}
	return nil
}

// Env is the data of one host for expressions and templates.
type Env struct {
	host  Host
	short string
	facts facts.Facts
	vars  map[string]any
	// item is the current element of a loop when hasItem is true.
	item    any
	hasItem bool
}

func (e *Env) with(item any) *Env {
	c := *e
	c.item, c.hasItem = item, true
	return &c
}

func (e *Env) templateData() map[string]any {
	d := map[string]any{
		"vars":  e.vars,
		"facts": e.facts.Map(),
		"host": map[string]any{
			"name": e.host.Name, "short": e.short, "address": e.host.Address,
			"groups": e.host.Groups, "vars": e.vars,
		},
	}
	if e.hasItem {
		d["item"] = e.item
	}
	return d
}

func (e *Env) exprEnv() exprEnv {
	return exprEnv{
		Vars:  e.vars,
		Facts: e.facts,
		Host:  hostEnv{Name: e.host.Name, Short: e.short, Address: e.host.Address, Groups: e.host.Groups, Vars: e.vars},
		Item:  e.item,
	}
}

// Start returns the data of host h with facts f: it evaluates the defaults
// that h needs. It checks the requirements and the required variables of each
// recipe that runs on h in the pipeline, also in later stages.
func (p *Project) Start(h Host, f facts.Facts) (*Env, error) {
	short, _, _ := strings.Cut(h.Name, ".")
	e := &Env{host: h, short: short, facts: f, vars: maps.Clone(h.Vars)}
	var names []string
	for _, v := range p.vars {
		if v.Recipe == "" {
			names = append(names, v.Name)
		}
	}
	var steps []Step
	for _, s := range p.Pipeline.Stages {
		if !slices.ContainsFunc(s.Targets, func(t Host) bool { return t.Name == h.Name }) {
			continue
		}
		for _, st := range s.Steps {
			if st.when != nil {
				names = append(names, st.when.reads...)
			}
			steps = append(steps, st)
		}
	}
	if err := p.evalDefaults(e, names); err != nil {
		return nil, err
	}
	names = nil
	for _, st := range steps {
		ok, err := st.Runs(e)
		if st.Recipe == nil {
			// The step reports an error of its when when it runs.
			if ok || err != nil {
				names = append(names, st.reads()...)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if err := st.Recipe.Check(f); err != nil {
			return nil, err
		}
		if st.when != nil {
			if err := st.missing([]Host{h}); err != nil {
				return nil, err
			}
		}
		names = append(names, st.Recipe.needs...)
	}
	if err := p.evalDefaults(e, names); err != nil {
		return nil, err
	}
	return e, nil
}

// evalDefaults evaluates the defaults of names and of the variables that
// those defaults read, unless e has a value for them.
func (p *Project) evalDefaults(e *Env, names []string) error {
	need := map[string]bool{}
	for _, name := range names {
		need[name] = true
	}
	// In reverse evaluation order, a default comes before the defaults that
	// it reads.
	for _, v := range slices.Backward(p.vars) {
		if _, ok := e.vars[v.Name]; ok || !need[v.Name] || v.computed == nil {
			continue
		}
		for _, name := range v.computed.reads() {
			need[name] = true
		}
	}
	for _, v := range p.vars {
		if _, ok := e.vars[v.Name]; ok || !need[v.Name] || v.required() {
			continue
		}
		var val any
		if v.computed == nil {
			val = yamlx.Value(v.node)
		} else {
			n, err := v.computed.eval(e, "")
			if ye, ok := errors.AsType[*yamlx.Error](err); ok {
				return yamlx.Errorf(ye.Pos, "variable %q: %s", v.Name, ye.Msg)
			}
			if err != nil {
				return err
			}
			val = yamlx.Value(n)
		}
		if val != nil {
			e.vars[v.Name] = val
		}
	}
	return nil
}

// missing returns an error for each required variable of the recipe of st
// that has no value on one of hosts.
func (st Step) missing(hosts []Host) error {
	var errs []error
	for _, v := range st.Recipe.Vars {
		if !v.required() {
			continue
		}
		var without []string
		for _, h := range hosts {
			if _, ok := h.Vars[v.Name]; !ok {
				without = append(without, h.Name)
			}
		}
		if without != nil {
			errs = append(errs, yamlx.Errorf(st.Pos, "recipe %s: variable %q is required and has no value on %s", st.Recipe.Name, v.Name, strings.Join(without, ", ")))
		}
	}
	return errors.Join(errs...)
}
