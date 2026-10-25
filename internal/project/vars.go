package project

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/secret"
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
			errs = append(errs, l.seal(p.Value, "")...)
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
	sc := scope{
		vars:   l.vars,
		noItem: "a default cannot use item",
		byName: "a default reads vars only by name, such as vars.nginx_port",
		sealed: true,
	}
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
	var first *yamlx.Node
	walkTags(n, func(t *yamlx.Node) {
		if first == nil {
			first = t
		}
	})
	return first
}

// Env is the data of one host for expressions and templates, in three
// variants: 0 has the real values, 1 and 2 have the placeholders of the
// secrets. Expressions and templates read the variant n.
type Env struct {
	host  Host
	short string
	facts facts.Facts
	vars  [3]map[string]any
	// secret holds the names of the secret variables.
	secret map[string]bool
	// item is the current element of a loop when hasItem is true.
	item    [3]any
	hasItem bool
	n       int
	// failed is set in a placeholder variant for the output: a computed
	// value that fails gives the placeholder, so the other arguments still
	// show, and failed becomes true.
	failed *bool
	// secrets is true when the project has secrets. Without them, the three
	// variants are the same.
	secrets bool
	// runs are the recipes that run on the host in the pipeline.
	runs   map[string]bool
	filter *secret.Filter
}

// Runs reports whether the recipe runs on the host in the pipeline: a stage
// of the host has a step for it whose when is true.
func (e *Env) Runs(recipe string) bool { return e.runs[recipe] }

func (e *Env) with(items [3]any) *Env {
	c := *e
	c.item, c.hasItem = items, true
	return &c
}

// variant returns e for the variant n.
func (e *Env) variant(n int) *Env {
	c := *e
	c.n = n
	return &c
}

// masked returns err, an error of f for the real variant of e, with the
// parts that come from a secret masked: it runs f for the placeholder
// variants too.
func (e *Env) masked(err error, f func(*Env) error) error {
	if err == nil || e.n != 0 || !e.secrets {
		return err
	}
	var alt [2]error
	for i := range alt {
		alt[i] = f(e.variant(i + 1))
	}
	return maskError(err, alt)
}

// learn adds the secret parts of an evaluation to the filter.
func (e *Env) learn(parts []string) {
	for _, p := range parts {
		if p != "" {
			e.filter.Add(p)
		}
	}
}

func (e *Env) templateData() map[string]any {
	d := map[string]any{
		"vars":  e.vars[e.n],
		"facts": e.facts.Map(),
		"host": map[string]any{
			"name": e.host.Name, "short": e.short, "address": e.host.Address,
			"groups": e.host.Groups, "vars": e.vars[e.n],
		},
	}
	if e.hasItem {
		d["item"] = e.item[e.n]
	}
	return d
}

func (e *Env) exprEnv() exprEnv {
	return exprEnv{
		Vars:  e.vars[e.n],
		Facts: e.facts,
		Host:  hostEnv{Name: e.host.Name, Short: e.short, Address: e.host.Address, Groups: e.host.Groups, Vars: e.vars[e.n]},
		Item:  e.item[e.n],
	}
}

// Start returns the data of host h with facts f: it evaluates the defaults
// that h uses. It checks the requirements and the required variables of each
// recipe that runs on h in the pipeline, also in later stages.
func (p *Project) Start(h Host, f facts.Facts) (*Env, error) {
	short, _, _ := strings.Cut(h.Name, ".")
	e := &Env{host: h, short: short, facts: f, secret: map[string]bool{}, secrets: p.secrets, runs: map[string]bool{}, filter: p.filter}
	for n := range e.vars {
		e.vars[n] = unseal(h.Vars, n).(map[string]any)
		if !e.secrets {
			e.vars[1], e.vars[2] = e.vars[0], e.vars[0]
			break
		}
	}
	for name, v := range h.Vars {
		e.secret[name] = hasSealed(v)
	}
	for _, s := range p.Pipeline.Stages {
		if !slices.ContainsFunc(s.Targets, func(t Host) bool { return t.Name == h.Name }) {
			continue
		}
		for _, st := range s.Steps {
			if st.Recipe == nil {
				if err := p.use(e, st); err != nil {
					return nil, err
				}
				continue
			}
			if st.when != nil {
				if err := p.evalDefaults(e, st.when.reads); err != nil {
					return nil, err
				}
			}
			ok, err := st.Runs(e)
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
			e.runs[st.Recipe.Name] = true
			for _, rs := range st.Recipe.Steps {
				if err := p.use(e, rs); err != nil {
					return nil, err
				}
			}
			for _, hd := range st.Recipe.Handlers {
				for _, hs := range hd.Steps {
					if err := p.use(e, hs); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return e, nil
}

// use evaluates the defaults that the when of module step st reads, and,
// when st runs, the defaults that the rest of st reads. A step whose when
// fails reports the error when it evaluates, before it reads anything else.
func (p *Project) use(e *Env, st Step) error {
	if st.when != nil {
		if err := p.evalDefaults(e, st.when.reads); err != nil {
			return err
		}
	}
	if ok, err := st.Runs(e); !ok || err != nil {
		return nil
	}
	return p.evalDefaults(e, st.reads())
}

// evalDefaults evaluates the defaults of names and of the variables that
// those defaults read, unless e has a value for them. It evaluates each
// default in the three variants. A default that reads a secret variable is
// secret.
func (p *Project) evalDefaults(e *Env, names []string) error {
	need := map[string]bool{}
	for _, name := range names {
		need[name] = true
	}
	// In reverse evaluation order, a default comes before the defaults that
	// it reads.
	for _, v := range slices.Backward(p.vars) {
		if _, ok := e.vars[0][v.Name]; ok || !need[v.Name] || v.computed == nil {
			continue
		}
		for _, name := range v.computed.reads() {
			need[name] = true
		}
	}
	for _, v := range p.vars {
		if _, ok := e.vars[0][v.Name]; ok || !need[v.Name] || v.required() {
			continue
		}
		vals, err := p.evalDefault(e, v)
		if err != nil {
			return err
		}
		if vals[0] == nil {
			continue
		}
		for n := range vals {
			e.vars[n][v.Name] = vals[n]
		}
	}
	return nil
}

// evalDefault returns the default of v in the three variants.
func (p *Project) evalDefault(e *Env, v *Var) ([3]any, error) {
	var vals [3]any
	if v.computed == nil {
		val := yamlx.Value(v.node)
		e.secret[v.Name] = hasSealed(val)
		for n := range vals {
			vals[n] = unseal(val, n)
		}
		return vals, nil
	}
	if !e.secrets {
		node, err := v.computed.eval(e, "")
		if ye, ok := errors.AsType[*yamlx.Error](err); ok {
			return vals, yamlx.Errorf(ye.Pos, "variable %q: %s", v.Name, ye.Msg)
		}
		if err != nil {
			return vals, err
		}
		val := yamlx.Value(node)
		return [3]any{val, val, val}, nil
	}
	var errs [3]error
	for n := range vals {
		node, err := v.computed.eval(e.variant(n), "")
		if err != nil {
			errs[n] = err
			continue
		}
		val := yamlx.Value(node)
		if n == 0 {
			e.secret[v.Name] = hasSealed(val) || slices.ContainsFunc(v.computed.reads(), func(r string) bool { return e.secret[r] })
		}
		vals[n] = unseal(val, n)
	}
	if errs[0] != nil {
		err := maskError(errs[0], [2]error{errs[1], errs[2]})
		if ye, ok := errors.AsType[*yamlx.Error](err); ok {
			return vals, yamlx.Errorf(ye.Pos, "variable %q: %s", v.Name, ye.Msg)
		}
		return vals, err
	}
	for n := 1; n < 3; n++ {
		switch {
		case errs[n] != nil:
			vals[n] = secret.Placeholder(n)
		case e.secret[v.Name]:
			vals[n] = force(vals[0], vals[n], n)
		}
	}
	if e.secret[v.Name] {
		e.learn(secret.Parts(vals[0], vals[1], vals[2]))
	}
	return vals, nil
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
