package project

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

// Var is the default of a variable, in winch.yaml or in a recipe, or a value
// in the vars of a recipe step.
type Var struct {
	Name string
	Pos  yamlx.Pos
	node *yamlx.Node
	// computed is the value when it holds tagged values.
	computed *value
}

var varNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// declare adds the defaults in n, a map of names to defaults. recipe is
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
		if p.Value.Kind == yamlx.Null {
			errs = append(errs, yamlx.Errorf(p.KeyPos, "variable %q: a variable without a default has no declaration; remove it", p.Key))
			continue
		}
		errs = append(errs, l.seal(p.Value, "")...)
		v := &Var{Name: p.Key, Pos: p.KeyPos, node: p.Value}
		l.vars[p.Key] = v
		l.decls = append(l.decls, v)
	}
	return errs
}

// compileDefaults compiles the defaults and puts them in the
// order in which defaults evaluate. A cycle between defaults is an error.
func (l *loader) compileDefaults() error {
	var errs []error
	sc := scope{
		reads:   &l.reads,
		noItem:  "a default cannot use item",
		sealed:  true,
		noMatch: "a default cannot use match()",
	}
	for _, v := range l.decls {
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
				if d := l.vars[name]; d != nil {
					visit(d)
				}
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

// setValue is a value from --set. flag is the text of the flag.
type setValue struct {
	name  string
	value any
	flag  string
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
		n, err := parseValue(text, "--set")
		if err != nil {
			errs = append(errs, fmt.Errorf("--set %s: %w", s, err))
			continue
		}
		out = append(out, setValue{name: name, value: yamlx.Value(n), flag: s})
	}
	return out, errors.Join(errs...)
}

// checkNames checks that each read names a variable with a default or a
// value, in some inventory, a recipe step, or sets. It checks that each value
// of the loaded inventories, of a recipe step, and of sets is for a variable
// with a default or a read.
func (l *loader) checkNames(sets []setValue) error {
	given := l.inventoryNames()
	for name := range l.vars {
		given[name] = true
	}
	for _, v := range l.given {
		given[v.name] = true
	}
	for _, s := range sets {
		given[s.name] = true
	}
	read := l.readNames()
	var errs []error
	for _, r := range l.reads {
		if !given[r.name] {
			errs = append(errs, yamlx.Errorf(r.pos, "%s%s", unknownVariable(r.name, given), r.snippet))
		}
	}
	for _, v := range l.given {
		if msg := unreadValue(v.name, read); msg != "" {
			errs = append(errs, yamlx.Errorf(v.pos, "%s", msg))
		}
	}
	for _, s := range sets {
		if msg := unreadValue(s.name, read); msg != "" {
			errs = append(errs, fmt.Errorf("--set %s: %s", s.flag, msg))
		}
	}
	return errors.Join(errs...)
}

// unreadValue returns the error for a value of the variable name, or "".
func unreadValue(name string, read map[string]bool) string {
	switch {
	case !varNameRe.MatchString(name):
		return fmt.Sprintf("variable %q: a variable name has only lowercase letters, digits, and _", name)
	case !read[name]:
		return unknownVariable(name, read)
	}
	return ""
}

// readNames returns the names of the variables with a default or a read.
func (l *loader) readNames() map[string]bool {
	out := map[string]bool{}
	for name := range l.vars {
		out[name] = true
	}
	for _, r := range l.reads {
		out[r.name] = true
	}
	return out
}

// inventoryNames returns the names of the variables that the inventories of
// the project give a value. It skips an inventory that does not parse; a run
// with it reports the error.
func (l *loader) inventoryNames() map[string]bool {
	out := map[string]bool{}
	for _, p := range l.layout.inventories {
		n, err := p.parse(l.dir)
		if err != nil {
			continue
		}
		for _, kind := range []string{"hosts", "groups"} {
			entries := find(n, []string{kind})
			if entries == nil || entries.Value.Kind != yamlx.Map {
				continue
			}
			for _, e := range entries.Value.Pairs {
				if vars := find(e.Value, []string{"vars"}); vars != nil && vars.Value.Kind == yamlx.Map {
					for _, v := range vars.Value.Pairs {
						out[v.Key] = true
					}
				}
			}
		}
	}
	return out
}

// parseValue parses a value of the command line as YAML. what names the flag
// or the command.
func parseValue(text, what string) (*yamlx.Node, error) {
	n, err := yamlx.Parse(what, []byte(text))
	if err != nil {
		if ye, ok := errors.AsType[*yamlx.Error](err); ok {
			return nil, errors.New(ye.Msg)
		}
		return nil, err
	}
	if yamlx.HasComment([]byte(text)) {
		return nil, fmt.Errorf("YAML drops the comment; quote it: %q", text)
	}
	if n.Kind == yamlx.Null && text == "" {
		return nil, errors.New("null is not a value")
	}
	if n.Kind == yamlx.Null {
		return nil, fmt.Errorf("YAML reads null; quote it: %q", text)
	}
	if t := findTag(n); t != nil {
		return nil, fmt.Errorf("%s gives no %s values", what, t.Tag)
	}
	if n.Kind == yamlx.Map {
		return nil, fmt.Errorf("YAML reads a map; quote it: %q", text)
	}
	quoted := strings.HasPrefix(text, `"`) || strings.HasPrefix(text, "'")
	if n.Kind == yamlx.Scalar && !quoted && n.Text != text || n.Kind == yamlx.List && !strings.HasPrefix(text, "[") {
		return nil, fmt.Errorf("YAML changes the text; quote it: %q", text)
	}
	if msg := textChange(n); msg != "" {
		return nil, errors.New(msg)
	}
	return n, nil
}

// textChange tells which number in a --set value YAML reads with other text,
// and how to quote it. It is empty when all numbers keep their text.
func textChange(n *yamlx.Node) string {
	var number string
	switch v := n.Value.(type) {
	case int64:
		number = strconv.FormatInt(v, 10)
	case float64:
		number = strconv.FormatFloat(v, 'f', -1, 64)
	}
	if number != "" && number != n.Text {
		return fmt.Sprintf("YAML reads %s as %s; quote it: %q", n.Text, number, n.Text)
	}
	for _, item := range n.Items {
		if msg := textChange(item); msg != "" {
			return msg
		}
	}
	for _, p := range n.Pairs {
		if msg := textChange(p.Value); msg != "" {
			return msg
		}
	}
	return ""
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
	// parent is the data of the host in the data of a recipe step with vars,
	// else nil. host.vars reads it.
	parent *Env
	// steps holds the data of each recipe step with vars.
	steps map[*Step]*Env
	inv   *Inventory
	peers map[string]map[string]any
}

// Runs reports whether the recipe runs on the host in the pipeline: a stage
// of the host has a step for it whose when is true.
func (e *Env) Runs(recipe string) bool { return e.runs[recipe] }

// For returns the data of the recipe step st on the host of e: its own when
// the step has vars, else e.
func (e *Env) For(st *Step) *Env {
	if se := e.steps[st]; se != nil {
		return se
	}
	return e
}

// hostVars returns the variables of the host, without the vars of a recipe
// step.
func (e *Env) hostVars() map[string]any {
	if e.parent != nil {
		return e.parent.vars[e.n]
	}
	return e.vars[e.n]
}

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
		"host":  hostMap(e.host, e.hostVars()),
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
		Host:  hostEnv{Name: e.host.Name, Short: e.short, Address: e.host.Address, Groups: e.host.Groups, Vars: e.hostVars()},
		Item:  e.item[e.n],
		Match: e.match,
	}
}

// match returns the hosts of a host pattern with the fields of host.
func (e *Env) match(pattern string) ([]any, error) {
	hosts, err := e.inv.Match(pattern)
	if err != nil {
		return nil, err
	}
	out := make([]any, len(hosts))
	for i, h := range hosts {
		out[i] = hostMap(h, unseal(e.peers[h.Name], e.n))
	}
	return out, nil
}

// hostMap returns the fields of host h for templates and match(), with
// vars.
func hostMap(h Host, vars any) map[string]any {
	short, _, _ := strings.Cut(h.Name, ".")
	return map[string]any{"name": h.Name, "short": short, "address": h.Address, "groups": h.Groups, "vars": vars}
}

// peerVars returns the vars of each host for match(): the defaults that are
// plain values, the inventory values, and --set. A computed default holds a
// marker that names it and the host.
func peerVars(inv *Inventory, decls []*Var) map[string]map[string]any {
	defaults := map[string]any{}
	for _, v := range decls {
		if v.computed == nil {
			defaults[v.Name] = yamlx.Value(v.node)
		}
	}
	out := map[string]map[string]any{}
	for _, h := range inv.Hosts {
		vars := maps.Clone(defaults)
		for _, v := range decls {
			if v.computed != nil {
				vars[v.Name] = computedMark + v.Name + "\x00" + h.Name + "\x00"
			}
		}
		maps.Copy(vars, h.Vars)
		out[h.Name] = vars
	}
	return out
}

// computedMark starts the marker of a computed default of a host from match():
// the marker is the variable name and the host name, each with a NUL byte
// after it. The marker passes through variables, so the variables of a recipe
// step can hold match() hosts.
const computedMark = "\x00computed\x00"

// computedError returns the error for the first marker in v, a string, or
// nil.
func computedError(v any) error {
	s, _ := v.(string)
	_, rest, ok := strings.Cut(s, computedMark)
	if !ok {
		return nil
	}
	name, rest, _ := strings.Cut(rest, "\x00")
	host, _, _ := strings.Cut(rest, "\x00")
	return computedMessage(name, host)
}

func computedMessage(name, host string) error {
	return computedDefault{name, host}
}

// computedDefault is a read of a computed default of a host from match().
type computedDefault struct{ name, host string }

func (c computedDefault) Error() string {
	return fmt.Sprintf("vars.%s of host %s is an !expr or !tpl default; match() gives only inventory values and plain defaults", c.name, c.host)
}

// withoutComputed returns a copy of v without the map entries that hold a
// marker, so that a template that reads one fails. found is true when v holds
// a marker.
func withoutComputed(v any) (out any, found bool) {
	switch v := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(v))
		for k, x := range v {
			if s, ok := x.(string); ok && strings.HasPrefix(s, computedMark) {
				found = true
				continue
			}
			var f bool
			m[k], f = withoutComputed(x)
			found = found || f
		}
		return m, found
	case []any:
		l := make([]any, len(v))
		for i, x := range v {
			var f bool
			l[i], f = withoutComputed(x)
			found = found || f
		}
		return l, found
	}
	return v, false
}

var missingKeyRe = regexp.MustCompile(`map has no entry for key "([a-z0-9_]+)"`)

// render executes t with the data of e. A read of a computed default of a
// match() host fails as a missing key. get gives nothing for a missing key,
// so when the data holds markers, a second run with the markers fails where
// get reads one. When the second run prints the marker of a missing key, the
// error names the default and the host instead.
func (e *Env) render(t *template.Template) (string, error) {
	data := e.templateData()
	stripped, found := withoutComputed(data)
	var b strings.Builder
	err := t.Execute(&b, stripped)
	var full strings.Builder
	if found {
		var cd computedDefault
		if ferr := t.Execute(&full, data); errors.As(ferr, &cd) {
			return "", ferr
		}
	}
	if err == nil {
		return b.String(), nil
	}
	var ne nullError
	if errors.As(err, &ne) {
		// The error names the added notNull call; name the action instead.
		at, _, _ := strings.Cut(err.Error(), " at <")
		return "", errors.New(at + " at <" + ne.text + ">: " + ne.Error())
	}
	m := missingKeyRe.FindStringSubmatch(err.Error())
	if m == nil {
		return "", err
	}
	_, rest, ok := strings.Cut(full.String(), computedMark+m[1]+"\x00")
	if !ok {
		return "", err
	}
	host, _, _ := strings.Cut(rest, "\x00")
	return "", errors.New(strings.Replace(err.Error(), m[0], computedMessage(m[1], host).Error(), 1))
}

// Start returns the data of host h with facts f: it evaluates the defaults
// that h uses, and checks that h has a value for each variable without a
// default that it reads. It checks the requirements of each recipe that runs
// on h in the pipeline, also in later stages and in stages that the
// selection leaves out.
func (p *Project) Start(h Host, f facts.Facts) (*Env, error) {
	short, _, _ := strings.Cut(h.Name, ".")
	e := &Env{host: h, short: short, facts: f, secrets: p.secrets, runs: map[string]bool{}, filter: p.filter,
		steps: map[*Step]*Env{}, inv: p.Inventory, peers: p.peers}
	e.setHostValues()
	for i := range p.Pipeline.Stages {
		s := &p.Pipeline.Stages[i]
		if !slices.ContainsFunc(s.Targets, func(t Host) bool { return t.Name == h.Name }) {
			continue
		}
		if !s.Skipped {
			for _, hs := range s.handlerSteps() {
				if err := p.use(e, hs); err != nil {
					return nil, err
				}
			}
		}
		for j := range s.Steps {
			st := &s.Steps[j]
			if st.Recipe == nil && s.Skipped {
				continue
			}
			if st.Recipe == nil {
				if err := p.use(e, *st); err != nil {
					return nil, err
				}
				continue
			}
			if st.when != nil {
				if err := p.evalDefaults(e, st.when.reads, st.when.pos); err != nil {
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
			e.runs[st.Recipe.Name] = true
			// A stage that the selection leaves out counts only for the
			// requirements and the handlers of its recipes.
			if s.Skipped {
				continue
			}
			re := e
			if st.vars != nil {
				if re, err = p.stepEnv(e, st); err != nil {
					return nil, err
				}
				e.steps[st] = re
			}
			for _, rs := range st.Recipe.Steps {
				if err := p.use(re, rs); err != nil {
					return nil, err
				}
			}
			for _, hd := range st.Recipe.Handlers {
				for _, hs := range hd.Steps {
					if err := p.use(re, hs); err != nil {
						return nil, err
					}
				}
			}
			if re != e {
				if err := p.evalDefaults(e, p.unchanged(re, st), st.Pos); err != nil {
					return nil, err
				}
			}
		}
	}
	return e, nil
}

// setHostValues sets the variables of e to the values of its host: the
// inventory and --set.
func (e *Env) setHostValues() {
	e.secret = map[string]bool{}
	for n := range e.vars {
		e.vars[n] = unseal(e.host.Vars, n).(map[string]any)
		if !e.secrets {
			e.vars[1], e.vars[2] = e.vars[0], e.vars[0]
			break
		}
	}
	for name, v := range e.host.Vars {
		e.secret[name] = hasSealed(v)
	}
}

// stepEnv returns the data of the recipe step st with vars on the host of e:
// the host's values, then the step values, unless --set gives the name. The
// step values evaluate in e. Defaults evaluate again in the new data.
func (p *Project) stepEnv(e *Env, st *Step) (*Env, error) {
	var reads []string
	for _, v := range st.vars {
		if v.computed != nil {
			reads = append(reads, v.computed.reads()...)
		}
	}
	if err := p.evalDefaults(e, reads, st.Pos); err != nil {
		return nil, err
	}
	se := &Env{host: e.host, short: e.short, facts: e.facts, secrets: e.secrets, runs: e.runs, filter: e.filter,
		parent: e, inv: e.inv, peers: e.peers}
	se.setHostValues()
	for _, v := range st.vars {
		if p.set[v.Name] {
			continue
		}
		vals, isSecret, err := p.evalValue(e, v)
		if err != nil {
			return nil, err
		}
		if vals[0] == nil {
			return nil, yamlx.Errorf(v.node.Pos, "variable %q: null is not a value", v.Name)
		}
		for n := range vals {
			se.vars[n][v.Name] = vals[n]
		}
		se.secret[v.Name] = isSecret
	}
	return se, nil
}

// unchanged returns the defaults that se, the data of the recipe step st,
// evaluated and whose value reads no variable that the step sets. host.vars
// in se reads them from the host's data.
func (p *Project) unchanged(se *Env, st *Step) []string {
	dep := map[string]bool{}
	var out []string
	for _, v := range p.vars {
		if v.computed != nil && slices.ContainsFunc(v.computed.reads(), func(r string) bool { return dep[r] || st.sets(r) }) {
			dep[v.Name] = true
		}
		if _, ok := se.vars[0][v.Name]; ok && !dep[v.Name] {
			out = append(out, v.Name)
		}
	}
	return out
}

// use evaluates the defaults that the when of module step st reads, and,
// when st runs, the defaults that the rest of st reads. A step whose when
// fails reports the error when it evaluates, before it reads anything else.
func (p *Project) use(e *Env, st Step) error {
	if st.when != nil {
		if err := p.evalDefaults(e, st.when.reads, st.when.pos); err != nil {
			return err
		}
	}
	if ok, err := st.Runs(e); !ok || err != nil {
		return nil
	}
	return p.evalDefaults(e, st.reads(), st.Pos)
}

// evalDefaults evaluates the defaults of names and of the variables that
// those defaults read, unless e has a value for them. It evaluates each
// default in the three variants. A default that reads a secret variable is
// secret. A variable without a value and without a default is an error at
// pos, where something reads names.
func (p *Project) evalDefaults(e *Env, names []string, pos yamlx.Pos) error {
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
	var missing []string
	for name := range need {
		if _, ok := e.vars[0][name]; !ok && p.defaults[name] == nil {
			missing = append(missing, name)
		}
	}
	if missing != nil {
		return yamlx.Errorf(pos, "variable %q has no value on host %s", slices.Min(missing), e.host.Name)
	}
	for _, v := range p.vars {
		if _, ok := e.vars[0][v.Name]; ok || !need[v.Name] {
			continue
		}
		vals, isSecret, err := p.evalValue(e, v)
		if err != nil {
			return err
		}
		e.secret[v.Name] = isSecret
		if vals[0] == nil {
			continue
		}
		for n := range vals {
			e.vars[n][v.Name] = vals[n]
		}
	}
	return nil
}

// evalValue returns the value of v, a default or a value of a recipe step,
// in the three variants of e. It reports whether the value is secret: it
// holds a !secret, or it reads a secret variable.
func (p *Project) evalValue(e *Env, v *Var) ([3]any, bool, error) {
	var vals [3]any
	if v.computed == nil {
		val := yamlx.Value(v.node)
		for n := range vals {
			vals[n] = unseal(val, n)
		}
		return vals, hasSealed(val), nil
	}
	if !e.secrets {
		node, err := v.computed.eval(e, "")
		if ye, ok := errors.AsType[*yamlx.Error](err); ok {
			return vals, false, yamlx.Errorf(ye.Pos, "variable %q: %s", v.Name, ye.Msg)
		}
		if err != nil {
			return vals, false, err
		}
		val := yamlx.Value(node)
		return [3]any{val, val, val}, false, nil
	}
	var errs [3]error
	isSecret := false
	for n := range vals {
		node, err := v.computed.eval(e.variant(n), "")
		if err != nil {
			errs[n] = err
			continue
		}
		val := yamlx.Value(node)
		if n == 0 {
			isSecret = hasSealed(val) || slices.ContainsFunc(v.computed.reads(), func(r string) bool { return e.secret[r] })
		}
		vals[n] = unseal(val, n)
	}
	if errs[0] != nil {
		err := maskError(errs[0], [2]error{errs[1], errs[2]})
		if ye, ok := errors.AsType[*yamlx.Error](err); ok {
			return vals, false, yamlx.Errorf(ye.Pos, "variable %q: %s", v.Name, ye.Msg)
		}
		return vals, false, err
	}
	for n := 1; n < 3; n++ {
		switch {
		case errs[n] != nil:
			vals[n] = secret.Placeholder(n)
		case isSecret:
			vals[n] = force(vals[0], vals[n], n)
		}
	}
	if isSecret {
		e.learn(secret.Parts(vals[0], vals[1], vals[2]))
	}
	return vals, isSecret, nil
}
