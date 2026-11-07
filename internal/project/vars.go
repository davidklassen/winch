package project

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"unicode/utf8"

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
	// recipe is the recipe of the default, or empty for winch.yaml.
	recipe string
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
			errs = append(errs, yamlx.Errorf(p.KeyPos, "%q is not a variable name; a variable name has only lowercase letters, digits, and _", p.Key))
			continue
		case recipe != "" && !strings.HasPrefix(p.Key, recipe+"_"):
			errs = append(errs, yamlx.Errorf(p.KeyPos, "vars.%s: a variable of recipe %s starts with %s", p.Key, recipe, recipe+"_"))
			continue
		}
		if first, ok := l.vars[p.Key]; ok {
			errs = append(errs, yamlx.Errorf(p.KeyPos, "vars.%s has two defaults; the first is at %s", p.Key, first.Pos))
			continue
		}
		if p.Value.Kind == yamlx.Null {
			errs = append(errs, yamlx.Errorf(p.KeyPos, "vars.%s: null is not a value; give it a default, or remove it", p.Key))
			continue
		}
		errs = append(errs, l.seal(p.Value, "")...)
		l.warnNumbers(p.Key, p.Value)
		v := &Var{Name: p.Key, Pos: p.KeyPos, node: p.Value, recipe: recipe}
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
		reads:     &l.reads,
		reach:     &l.reach,
		noItem:    "a default cannot use item",
		inDefault: true,
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
			errs = append(errs, yamlx.Errorf(v.Pos, "vars.%s: the defaults form a cycle: %s → %s", v.Name, strings.Join(cycle, " → "), v.Name))
			return
		}
		state[v] = visiting
		path = append(path, v)
		if v.computed != nil {
			for _, name := range slices.Concat(v.computed.reads(), v.computed.peerReads()) {
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
			errs = append(errs, yamlx.Errorf(yamlx.Pos{File: "--set " + s}, "use --set vars.<name>=<value>"))
			continue
		}
		n, err := parseValue(text, "--set", "--set ", key)
		if err != nil {
			errs = append(errs, yamlx.Errorf(yamlx.Pos{File: "--set " + s}, "%s", err))
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
			errs = append(errs, yamlx.Errorf(r.pos, "vars.%s has no value: set it in the inventory, or give it a default%s%s", r.name, yamlx.Suggest(r.name, slices.Sorted(maps.Keys(given))), r.snippet))
		}
	}
	for _, v := range l.given {
		if msg := unreadValue(v.name, read); msg != "" {
			errs = append(errs, yamlx.Errorf(v.pos, "%s", msg))
		}
	}
	for _, s := range sets {
		if msg := unreadValue(s.name, read); msg != "" {
			errs = append(errs, yamlx.Errorf(yamlx.Pos{File: "--set " + s.flag}, "%s", msg))
		}
	}
	return errors.Join(errs...)
}

// unreadValue returns the error for a value of the variable name, or "".
func unreadValue(name string, read map[string]bool) string {
	switch {
	case !varNameRe.MatchString(name):
		return fmt.Sprintf("%q is not a variable name; a variable name has only lowercase letters, digits, and _", name)
	case !read[name]:
		return fmt.Sprintf("vars.%s is set but nothing reads it%s", name, yamlx.Suggest(name, slices.Sorted(maps.Keys(read))))
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

// indicators are the characters that start YAML syntax at the start of a
// value, with what YAML reads them as.
var indicators = map[byte]string{
	'[': "the start of a list",
	'{': "the start of a map",
	'*': "an alias",
	'&': "an anchor",
	'|': "a block scalar",
	'>': "a block scalar",
	'%': "a directive",
	'@': "a reserved character",
	'`': "a reserved character",
}

// parseValue parses a value of the command line as YAML. what names the flag
// or the command. An error names the fix: flag, then key=value with the value
// quoted, as one shell word.
func parseValue(text, what, flag, key string) (*yamlx.Node, error) {
	fix := func(value string) string { return flag + quote(key+"="+value) }
	whole := fix(strconv.Quote(text))
	n, err := yamlx.Parse(what, []byte(text))
	if err != nil {
		if ye, ok := errors.AsType[*yamlx.Error](err); ok {
			problem, _, _ := strings.Cut(ye.Msg, "; ")
			if what, ok := indicators[text[0]]; ok {
				problem = fmt.Sprintf("YAML reads %c at the start as %s", text[0], what)
			}
			return nil, fmt.Errorf("%s; quote it: %s", problem, whole)
		}
		return nil, err
	}
	if yamlx.HasComment([]byte(text)) {
		return nil, fmt.Errorf("YAML drops the comment; quote it: %s", whole)
	}
	if n.Kind == yamlx.Null && text == "" {
		return nil, errors.New("null is not a value")
	}
	if n.Kind == yamlx.Null {
		return nil, fmt.Errorf("YAML reads null; quote it: %s", whole)
	}
	if t := findTag(n); t != nil {
		return nil, fmt.Errorf("takes no %s values", t.Tag)
	}
	if n.Kind == yamlx.Map {
		return nil, fmt.Errorf("YAML reads a map; quote it: %s", whole)
	}
	quoted := strings.HasPrefix(text, `"`) || strings.HasPrefix(text, "'")
	if n.Kind == yamlx.Scalar && !quoted && n.Text != text || n.Kind == yamlx.List && !strings.HasPrefix(text, "[") {
		return nil, fmt.Errorf("YAML changes the text; quote it: %s", whole)
	}
	if cs := textChanges(n, nil); len(cs) > 0 {
		return nil, fmt.Errorf("YAML reads %s as %s; quote it: %s", cs[0].Text, number(cs[0]), fix(quoteNumbers(text, cs)))
	}
	return n, nil
}

// number returns the number that YAML reads in n when its text differs, else "".
func number(n *yamlx.Node) string {
	var s string
	switch v := n.Value.(type) {
	case int64:
		s = strconv.FormatInt(v, 10)
	case float64:
		// Quotes make .inf or .nan a string, not the same number.
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return ""
		}
		s = strconv.FormatFloat(v, 'f', -1, 64)
	}
	if s == n.Text {
		return ""
	}
	return s
}

// warnNumbers adds a warning for each number in n, the value of the variable
// name, that YAML reads with other text.
func (l *loader) warnNumbers(name string, n *yamlx.Node) {
	seen := map[*yamlx.Node]bool{}
	for _, c := range textChanges(n, nil) {
		// An alias gives a number twice.
		if seen[c] {
			continue
		}
		seen[c] = true
		l.warnings = append(l.warnings, yamlx.Errorf(c.Pos, "vars.%s: YAML reads %s as %s; quote it: %s", name, c.Text, number(c), strconv.Quote(c.Text)))
	}
}

// textChanges appends to out the numbers in n that YAML reads with other text.
func textChanges(n *yamlx.Node, out []*yamlx.Node) []*yamlx.Node {
	if number(n) != "" {
		out = append(out, n)
	}
	for _, item := range n.Items {
		out = textChanges(item, out)
	}
	for _, p := range n.Pairs {
		out = textChanges(p.Value, out)
	}
	return out
}

// quoteNumbers returns text with the numbers cs in double quotes. An alias
// gives a number twice.
func quoteNumbers(text string, cs []*yamlx.Node) string {
	at := map[int]string{}
	for _, c := range cs {
		i := offset(text, c.Pos)
		// The position of a number with an anchor is the anchor.
		at[i+strings.Index(text[i:], c.Text)] = c.Text
	}
	// From the end, so the offsets before stay valid.
	for _, i := range slices.Backward(slices.Sorted(maps.Keys(at))) {
		text = text[:i] + strconv.Quote(at[i]) + text[i+len(at[i]):]
	}
	return text
}

// offset returns the byte offset in text of pos, whose column counts
// characters.
func offset(text string, pos yamlx.Pos) int {
	i := 0
	for range pos.Line - 1 {
		i += strings.IndexByte(text[i:], '\n') + 1
	}
	for range pos.Col - 1 {
		_, size := utf8.DecodeRuneInString(text[i:])
		i += size
	}
	return i
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
	// runs holds the stage of each recipe that runs on the host in the
	// pipeline.
	runs   map[string]*Stage
	filter *secret.Filter
	// parent is the data of the host in the data of a recipe step with vars,
	// else nil. host.vars reads it.
	parent *Env
	// steps holds the data of each recipe step with vars.
	steps map[*Step]*Env
	// others gives the data of the hosts of hosts and match().
	others *others
}

// HostFacts are the facts of a host, or the error of their read.
type HostFacts struct {
	Facts facts.Facts
	Err   error
}

// others holds the data of the hosts of hosts and match() for the evaluation
// of one host. host is that host, with the facts f; all has the facts of the
// other hosts that the plan read. envs holds the data of each other host,
// without the vars of a recipe step, and failed the defaults that failed on
// it, by name and host.
type others struct {
	p      *Project
	host   string
	f      facts.Facts
	all    map[string]HostFacts
	envs   map[string]*Env
	failed map[string]error
}

func (o *others) facts(host string) (facts.Facts, error) {
	if host == o.host {
		return o.f, nil
	}
	hf, ok := o.all[host]
	if !ok {
		return facts.Facts{}, fmt.Errorf("read the facts of %s: the plan did not read them", host)
	}
	if hf.Err != nil {
		return facts.Facts{}, fmt.Errorf("read the facts of %s: %w", host, hf.Err)
	}
	return hf.Facts, nil
}

// env returns the data of the host h for hosts and match().
func (o *others) env(h Host) (*Env, error) {
	if e := o.envs[h.Name]; e != nil {
		return e, nil
	}
	f, err := o.facts(h.Name)
	if err != nil {
		return nil, err
	}
	e := &Env{host: h, facts: f, secrets: o.p.secrets, runs: map[string]*Stage{}, filter: o.p.filter, steps: map[*Step]*Env{}, others: o}
	e.setHostValues()
	o.envs[h.Name] = e
	return e, nil
}

// RunsIn returns the stage of the host whose step for the recipe has a true
// when, or nil when the recipe does not run on the host in the pipeline.
func (e *Env) RunsIn(recipe string) *Stage { return e.runs[recipe] }

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

// templateData returns the data of templates, with hosts when hosts is true.
func (e *Env) templateData(hosts bool) (map[string]any, error) {
	d := map[string]any{
		"vars":  e.vars[e.n],
		"facts": e.facts.Map(),
		"host":  hostMap(e.host, e.hostVars(), e.facts),
	}
	if e.hasItem {
		d["item"] = e.item[e.n]
	}
	if hosts {
		var err error
		if d["hosts"], err = e.hosts(e.others.p.Inventory.Hosts); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// exprEnv returns the data of expressions, with hosts when hosts is true.
func (e *Env) exprEnv(hosts bool) (exprEnv, error) {
	short, _, _ := strings.Cut(e.host.Name, ".")
	env := exprEnv{
		Vars:  e.vars[e.n],
		Facts: e.facts,
		Host:  hostEnv{Name: e.host.Name, Short: short, Address: e.host.Address, Groups: e.host.Groups, Vars: e.hostVars(), Facts: e.facts},
		Item:  e.item[e.n],
		Match: e.match,
		Read:  e.read,
	}
	if hosts {
		var err error
		if env.Hosts, err = e.hosts(e.others.p.Inventory.Hosts); err != nil {
			return exprEnv{}, err
		}
	}
	return env, nil
}

// match returns the hosts of a host pattern with the fields of host.
func (e *Env) match(pattern string) ([]any, error) {
	hosts, err := e.others.p.Inventory.Match(pattern)
	if err != nil {
		return nil, err
	}
	return e.hosts(hosts)
}

// hosts returns the fields of each host of hosts. A computed default of a
// host holds a marker, which a read of it by name replaces with its value.
func (e *Env) hosts(hosts []Host) ([]any, error) {
	out := make([]any, len(hosts))
	for i, h := range hosts {
		f, err := e.others.facts(h.Name)
		if err != nil {
			return nil, err
		}
		out[i] = hostMap(h, unseal(e.others.p.peers[h.Name], e.n), f)
	}
	return out, nil
}

// hostMap returns the fields of host h for templates, hosts, and match().
func hostMap(h Host, vars any, f facts.Facts) map[string]any {
	short, _, _ := strings.Cut(h.Name, ".")
	return map[string]any{"name": h.Name, "short": short, "address": h.Address, "groups": h.Groups, "vars": vars, "facts": f.Map()}
}

// read returns v, or the value of the default that v marks.
func (e *Env) read(v any) (any, error) {
	name, h, msg, ok := e.others.marker(v)
	switch {
	case !ok:
		return v, nil
	case msg != "":
		return nil, errors.New(msg)
	}
	return e.peerVar(name, h)
}

// marker reads the marker of the default name of the host h in v. It
// reports false for any other value, also for project text that looks like
// a marker.
func (o *others) marker(v any) (name string, h Host, msg string, ok bool) {
	s, _ := v.(string)
	name, host, msg, ok := parseMark(s)
	if !ok {
		return "", Host{}, "", false
	}
	i := slices.IndexFunc(o.p.Inventory.Hosts, func(h Host) bool { return h.Name == host })
	if d := o.p.defaults[name]; i < 0 || d == nil || d.computed == nil {
		return "", Host{}, "", false
	}
	return name, o.p.Inventory.Hosts[i], msg, true
}

// secret reports whether a variable of names is secret on a host of hosts
// and match(). A computed default counts on the hosts where a read evaluated
// it.
func (o *others) secret(names []string) bool {
	for _, h := range o.p.Inventory.Hosts {
		pe := o.envs[h.Name]
		for _, name := range names {
			if hasSealed(o.p.peers[h.Name][name]) || pe != nil && pe.secret[name] {
				return true
			}
		}
	}
	return false
}

// peerVar returns the value of the default name of the host h, as hosts and
// match() give it.
func (e *Env) peerVar(name string, h Host) (any, error) {
	o := e.others
	key := name + "\x00" + h.Name
	if err := o.failed[key]; err != nil {
		return nil, err
	}
	pe, err := o.env(h)
	if err == nil {
		err = o.p.evalDefaults(pe, []string{name}, o.p.defaults[name].Pos)
	}
	if err != nil {
		err = fmt.Errorf("host %s: %w", h.Name, err)
		o.failed[key] = err
		return nil, err
	}
	return pe.vars[e.n][name], nil
}

// resolve returns v with the value of each marked default that names holds.
// A default that fails gives a marker of its error. It reports whether v
// changed.
func (e *Env) resolve(v any, names []string) (any, bool) {
	switch v := v.(type) {
	case string:
		name, h, msg, ok := e.others.marker(v)
		if !ok || msg != "" || !slices.Contains(names, name) {
			return v, false
		}
		val, err := e.peerVar(name, h)
		if err != nil {
			return mark(name, h.Name, err.Error()), true
		}
		out, _ := e.resolve(val, names)
		return out, true
	case map[string]any:
		var out map[string]any
		for k, x := range v {
			r, changed := e.resolve(x, names)
			if !changed {
				continue
			}
			if out == nil {
				out = maps.Clone(v)
			}
			out[k] = r
		}
		if out == nil {
			return v, false
		}
		return out, true
	case []any:
		var out []any
		for i, x := range v {
			r, changed := e.resolve(x, names)
			if !changed {
				continue
			}
			if out == nil {
				out = slices.Clone(v)
			}
			out[i] = r
		}
		if out == nil {
			return v, false
		}
		return out, true
	}
	return v, false
}

// peerVars returns the vars of each host for hosts and match(): the defaults
// that are plain values, the inventory values, and --set. A computed default
// holds a marker that names it and the host.
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
				vars[v.Name] = mark(v.Name, h.Name, "")
			}
		}
		maps.Copy(vars, h.Vars)
		out[h.Name] = vars
	}
	return out
}

// computedMark starts the marker of a computed default of a host from hosts
// or match(): the marker is the variable name, the host name, and the quoted
// message of the error of the default or nothing, each with a NUL byte after
// it. The marker passes through variables, so the variables of a recipe step
// can hold hosts.
const computedMark = "\x00computed\x00"

func mark(name, host, msg string) string {
	if msg != "" {
		msg = strconv.Quote(msg)
	}
	return computedMark + name + "\x00" + host + "\x00" + msg + "\x00"
}

// parseMark reads the marker that s starts with.
func parseMark(s string) (name, host, msg string, ok bool) {
	rest, ok := strings.CutPrefix(s, computedMark)
	if !ok {
		return "", "", "", false
	}
	name, rest, _ = strings.Cut(rest, "\x00")
	host, rest, _ = strings.Cut(rest, "\x00")
	q, _, _ := strings.Cut(rest, "\x00")
	if q != "" {
		msg, _ = strconv.Unquote(q)
	}
	return name, host, msg, true
}

// computedError returns the error for the first marker in v, a string, or
// nil.
func computedError(v any) error {
	s, _ := v.(string)
	i := strings.Index(s, computedMark)
	if i < 0 {
		return nil
	}
	name, host, msg, _ := parseMark(s[i:])
	if msg != "" {
		return errors.New(msg)
	}
	return computedDefault{name, host}
}

// computedIn returns the error for the first marker of a computed default in
// v.
func computedIn(v any) error {
	switch v := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(v)) {
			if err := computedIn(v[k]); err != nil {
				return err
			}
		}
	case []any:
		for _, x := range v {
			if err := computedIn(x); err != nil {
				return err
			}
		}
	}
	return computedError(v)
}

// computedDefault is a read of a computed default of a host from hosts or
// match() other than by name.
type computedDefault struct{ name, host string }

func (c computedDefault) Error() string {
	return fmt.Sprintf("vars.%s of host %s is an !expr or !tpl default; read it by name", c.name, c.host)
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

// render executes t with the data of e, with hosts when hosts is true. The
// computed defaults names of the hosts of hosts and match() get their values.
// A read of another computed default fails as a missing key. get gives
// nothing for a missing key, so when the data holds markers, a second run
// with the markers fails where get reads one. A template that prints a whole
// host, in any encoding, gives other output in the second run and fails too.
// When the second run prints the marker of a missing key, the error names the
// default and the host instead.
func (e *Env) render(t *template.Template, names []string, hosts bool) (string, error) {
	d, err := e.templateData(hosts)
	if err != nil {
		return "", err
	}
	data := any(d)
	if len(names) > 0 {
		data, _ = e.resolve(data, names)
	}
	t, err = t.Clone()
	if err != nil {
		return "", err
	}
	// match strips the markers in the first run, as the data has them
	// stripped.
	strip, matched := true, false
	t.Funcs(template.FuncMap{"match": func(pattern string) ([]any, error) {
		hs, err := e.match(pattern)
		if err != nil {
			return nil, err
		}
		out, _ := e.resolve(hs, names)
		if strip {
			var found bool
			out, found = withoutComputed(out)
			matched = matched || found
		}
		return out.([]any), nil
	}})
	stripped, found := withoutComputed(data)
	var b strings.Builder
	err = t.Execute(&b, stripped)
	found = found || matched
	strip = false
	var full strings.Builder
	if found {
		var cd computedDefault
		if ferr := t.Execute(&full, data); errors.As(ferr, &cd) {
			return "", ferr
		}
	}
	if err == nil {
		if found && full.String() != b.String() {
			if err := computedError(full.String()); err != nil {
				return "", err
			}
			return "", computedIn(data)
		}
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
	i := strings.Index(full.String(), computedMark+m[1]+"\x00")
	if i < 0 {
		return "", err
	}
	return "", errors.New(strings.Replace(err.Error(), m[0], computedError(full.String()[i:]).Error(), 1))
}

// Start returns the data of host h with facts f, where all holds the facts of
// the other hosts that hosts and match() can reach: it evaluates the defaults
// that h uses, and checks that h has a value for each variable without a
// default that it reads. It checks the requirements of each recipe that runs
// on h in the pipeline, also in later stages and in stages that the
// selection leaves out.
func (p *Project) Start(h Host, f facts.Facts, all map[string]HostFacts) (*Env, error) {
	e := &Env{host: h, facts: f, secrets: p.secrets, runs: map[string]*Stage{}, filter: p.filter,
		steps: map[*Step]*Env{}, others: &others{p: p, host: h.Name, f: f, all: all, envs: map[string]*Env{}, failed: map[string]error{}}}
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
			e.runs[st.Recipe.Name] = s
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
	se := &Env{host: e.host, facts: e.facts, secrets: e.secrets, runs: e.runs, filter: e.filter,
		parent: e, others: e.others}
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
			return nil, yamlx.Errorf(v.node.Pos, "vars.%s: null is not a value", v.Name)
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
		return yamlx.Errorf(pos, "vars.%s has no value on host %s; set it in the inventory for this host, or give it a default", slices.Min(missing), e.host.Name)
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
// holds a !secret, or it reads a secret variable, also of a host from hosts or
// match().
func (p *Project) evalValue(e *Env, v *Var) ([3]any, bool, error) {
	var vals [3]any
	if v.computed == nil {
		val := yamlx.Value(v.node)
		for n := range vals {
			vals[n] = unseal(val, n)
		}
		return vals, hasSealed(val), nil
	}
	var errs [3]error
	isSecret := false
	for n := range vals {
		if n > 0 && !e.secrets {
			vals[n] = vals[0]
			continue
		}
		node, err := v.computed.eval(e.variant(n), "")
		if err != nil {
			errs[n] = err
			continue
		}
		val := yamlx.Value(node)
		if n == 0 {
			isSecret = hasSealed(val) ||
				slices.ContainsFunc(v.computed.reads(), func(r string) bool { return e.secret[r] }) ||
				e.others.secret(v.computed.peerReads())
		}
		vals[n] = unseal(val, n)
	}
	if err := errs[0]; err != nil {
		if e.secrets {
			err = maskError(err, [2]error{errs[1], errs[2]})
		}
		if ye, ok := errors.AsType[*yamlx.Error](err); ok {
			return vals, false, yamlx.Errorf(ye.Pos, "vars.%s: %s", v.Name, ye.Msg)
		}
		return vals, false, err
	}
	// A host of hosts or match() brings its secrets without a read by name.
	// A value built from them, such as a result of contains, can differ from
	// two placeholder variants that agree. Such a value is secret. A value
	// whose variants differ wherever it differs, such as a list of hosts,
	// keeps its plain parts, such as host names.
	switch {
	case errs[1] != nil || errs[2] != nil:
		vals[1], vals[2], isSecret = secret.Placeholder(1), secret.Placeholder(2), true
	case e.secrets && (isSecret || agreeOff(vals[0], vals[1], vals[2])):
		vals[1], vals[2] = force(vals[0], vals[1], vals[2])
		isSecret = true
	}
	return vals, isSecret, nil
}
