package project

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	tparse "text/template/parse"
	"unicode"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/yamlx"
)

// funcs replaces the built-in index, which gives the zero value for a missing
// map key. render replaces match with the match of the host.
var funcs = template.FuncMap{"index": index, "join": join, "has": has, "title": title, "quote": quote, "sqlquote": sqlquote, "json": toJSON, "get": get,
	"match": func(string) ([]any, error) { return nil, errors.New("match has no host") }}

// tmplFile is a parsed template file of a recipe.
type tmplFile struct {
	t *template.Template
	// item is true when the template reads .item.
	item bool
	// data is true when it reads a name other than item, and hosts when it
	// reads hosts.
	data, hosts bool
	reads       []string
	// values are the variables whose values it reads.
	values []string
	// peerReads are the variables that it reads of a host from hosts or
	// match().
	peerReads []string
	matches   []matchCall
}

// parseTemplate parses the template text of file and checks the names it
// reads. item is allowed: the step that uses the file decides.
func parseTemplate(file string, text []byte, sc scope) (*tmplFile, error) {
	t, err := template.New(file).Option("missingkey=error").Funcs(funcs).Parse(string(text))
	if err != nil {
		hint := exprFuncHint(err, "compute it in a variable with !expr, and read that variable in the template")
		err = templateError(file, err)
		if ye, ok := err.(*yamlx.Error); ok {
			ye.Msg += hint
		}
		return nil, err
	}
	c := nameCheck{sc: sc, at: func(off int) yamlx.Pos {
		before := string(text[:off])
		return yamlx.Pos{File: file, Line: strings.Count(before, "\n") + 1, Col: off - strings.LastIndexByte(before, '\n')}
	}}
	c.check(t, file)
	if err := errors.Join(c.errs...); err != nil {
		return nil, err
	}
	failNull(t)
	return c.file(t), nil
}

// parseInline parses the text of a !tpl value at pos.
func parseInline(pos yamlx.Pos, text string, sc scope) (*tmplFile, error) {
	t, err := template.New(pos.String()).Option("missingkey=error").Funcs(funcs).Parse(text)
	if err != nil {
		// A parse error names the template, which is the position here.
		msg := strings.ReplaceAll(templateMessage(pos.String(), err), pos.String()+":", "line ")
		return nil, yamlx.Errorf(pos, "%s%s", msg, exprFuncHint(err, "use !expr"))
	}
	c := nameCheck{sc: sc, at: func(int) yamlx.Pos { return pos }}
	c.check(t, pos.String())
	if c.item && sc.noItem != "" {
		c.errs = append(c.errs, yamlx.Errorf(pos, "%s", sc.noItem))
	}
	if err := errors.Join(c.errs...); err != nil {
		return nil, err
	}
	failNull(t)
	return c.file(t), nil
}

func (c *nameCheck) file(t *template.Template) *tmplFile {
	return &tmplFile{t: t, item: c.item, data: c.data, hosts: c.hosts, reads: c.reads, values: c.values, peerReads: c.peerReads, matches: c.matches}
}

// names is a level of the names that a template can read. A nil *names allows
// any name.
type names struct {
	noun string
	sub  map[string]*names
}

// templateNames are the names that a template can read. The level of vars
// takes any name.
var templateNames = func() *names {
	vars := &names{noun: "variable"}
	fact := factNames(reflect.TypeFor[facts.Facts]())
	host := map[string]*names{"vars": vars, "facts": fact}
	for _, n := range hostFields {
		if _, ok := host[n]; !ok {
			host[n] = nil
		}
	}
	return &names{noun: "name", sub: map[string]*names{
		"vars":  vars,
		"facts": fact,
		"host":  {noun: "host field", sub: host},
		"hosts": nil,
		"item":  nil,
	}}
}()

// factNames returns the names of the facts in the struct t.
func factNames(t reflect.Type) *names {
	n := &names{noun: "fact", sub: map[string]*names{}}
	for i := range t.NumField() {
		f := t.Field(i)
		var sub *names
		if f.Type.Kind() == reflect.Struct {
			sub = factNames(f.Type)
		}
		n.sub[f.Tag.Get("expr")] = sub
	}
	return n
}

// nameCheck checks the names of each field that reads the data. at gives the
// position of an offset in the text.
type nameCheck struct {
	sc    scope
	at    func(off int) yamlx.Pos
	t     *template.Template
	top   *names
	main  bool
	item  bool
	data  bool
	hosts bool
	reads []string
	// peerReads are the variables that it reads of other hosts.
	peerReads []string
	matches   []matchCall
	// values are the variables whose values it reads. A field of the
	// elements of a variable x is the value "x.field". A range over only
	// the keys of a map does not read its values.
	values []string
	errs   []error
	// elem is true for the value of a range whose body reads only fields
	// of the element, and fields are those fields.
	elem   bool
	fields []string
	// byKey is the key while the check walks the map of a get or index with
	// a constant key: a read of a host's vars by name.
	byKey *tparse.StringNode
}

// check checks every template of t. main names the template of the text,
// where $ is the data.
func (c *nameCheck) check(t *template.Template, main string) {
	c.t = t
	c.top = templateNames
	for _, d := range t.Templates() {
		c.main = d.Name() == main
		c.walk(d.Root, c.main)
		(&tmplHosts{c: c, top: c.main, scopes: []map[string]hostKind{{}}}).walk(d.Root)
	}
}

// tmplHosts reports each host of .hosts or match, or list of them, that a
// template reads whole, as hostCheck does for expressions. top is true where
// dot is the data, dot is the kind of dot elsewhere, and scopes are the kinds
// of the variables, one map for each block.
type tmplHosts struct {
	c      *nameCheck
	top    bool
	dot    hostKind
	scopes []map[string]hostKind
}

func (h *tmplHosts) fail(n tparse.Node) {
	h.c.notByName(int(n.Position()))
}

// set declares the variable of d with the kind k. An = keeps the kind of the
// variable: it may run in a block that runs once, many times, or never, so
// an = of a host is a whole read.
func (h *tmplHosts) set(p *tparse.PipeNode, d *tparse.VariableNode, k hostKind) {
	switch {
	case !p.IsAssign:
		h.scopes[len(h.scopes)-1][d.Ident[0]] = k
	case k != noHost:
		h.fail(p.Cmds[len(p.Cmds)-1])
	}
}

func (h *tmplHosts) get(name string) hostKind {
	for i := len(h.scopes) - 1; i >= 0; i-- {
		if k, ok := h.scopes[i][name]; ok {
			return k
		}
	}
	return noHost
}

func (h *tmplHosts) walk(n tparse.Node) {
	switch n := n.(type) {
	case *tparse.ListNode:
		if n != nil {
			for _, x := range n.Nodes {
				h.walk(x)
			}
		}
	case *tparse.ActionNode:
		k := h.pipe(n.Pipe)
		switch {
		case len(n.Pipe.Decl) > 0:
			h.set(n.Pipe, n.Pipe.Decl[0], k)
		case k != noHost:
			h.fail(n.Pipe.Cmds[len(n.Pipe.Cmds)-1])
		}
	case *tparse.TemplateNode:
		if n.Pipe != nil && h.pipe(n.Pipe) != noHost {
			h.fail(n.Pipe)
		}
	case *tparse.IfNode:
		h.block(n.Pipe, n.List, n.ElseList, func(k hostKind) (bool, hostKind, []hostKind) {
			return h.top, h.dot, []hostKind{k}
		})
	case *tparse.RangeNode:
		h.block(n.Pipe, n.List, n.ElseList, func(k hostKind) (bool, hostKind, []hostKind) {
			if k == oneHost {
				h.fail(n.Pipe.Cmds[len(n.Pipe.Cmds)-1])
			}
			return false, k.elem(), []hostKind{noHost, k.elem()}
		})
	case *tparse.WithNode:
		h.block(n.Pipe, n.List, n.ElseList, func(k hostKind) (bool, hostKind, []hostKind) {
			return false, k, []hostKind{k}
		})
	}
}

// block walks an if, range, or with in a scope that holds the variables of
// its pipe p. kinds gives, for the kind of p, the top and dot of list and
// the kinds of the variables: the last variable takes the last kind, the
// one before it the kind before.
func (h *tmplHosts) block(p *tparse.PipeNode, list, elseList *tparse.ListNode, kinds func(hostKind) (bool, hostKind, []hostKind)) {
	h.scopes = append(h.scopes, map[string]hostKind{})
	top, dot, vars := kinds(h.pipe(p))
	for i, d := range p.Decl {
		k := noHost
		if j := len(vars) - len(p.Decl) + i; j >= 0 {
			k = vars[j]
		}
		h.set(p, d, k)
	}
	outerTop, outerDot := h.top, h.dot
	h.top, h.dot = top, dot
	h.scopes = append(h.scopes, map[string]hostKind{})
	h.walk(list)
	h.scopes = h.scopes[:len(h.scopes)-1]
	h.top, h.dot = outerTop, outerDot
	h.walk(elseList)
	h.scopes = h.scopes[:len(h.scopes)-1]
}

// tmplArg is an argument of a command: a node, or the value of the command
// before it in the pipeline.
type tmplArg struct {
	node tparse.Node
	kind hostKind
}

// pipe returns the kind of the value of p and reports the whole reads in it.
func (h *tmplHosts) pipe(p *tparse.PipeNode) hostKind {
	var prev tmplArg
	for i, cmd := range p.Cmds {
		var args []tmplArg
		for _, x := range cmd.Args {
			if _, ok := x.(*tparse.IdentifierNode); !ok {
				args = append(args, tmplArg{x, h.value(x)})
			}
		}
		if i > 0 {
			args = append(args, prev)
		}
		prev = tmplArg{cmd, h.command(cmd, args)}
	}
	return prev.kind
}

func (h *tmplHosts) use(args []tmplArg) {
	for _, a := range args {
		if a.kind != noHost {
			h.fail(a.node)
		}
	}
}

func (h *tmplHosts) command(cmd *tparse.CommandNode, args []tmplArg) hostKind {
	fn, ok := cmd.Args[0].(*tparse.IdentifierNode)
	switch {
	case !ok && len(args) == 1:
		return args[0].kind
	case !ok:
		h.use(args)
		return noHost
	}
	switch fn.Ident {
	case "match":
		h.use(args)
		return hostList
	case "len", "not":
		return noHost
	case "slice":
		if len(args) == 0 {
			return noHost
		}
		h.use(args[1:])
		return args[0].kind
	case "index", "get":
		if len(args) == 0 {
			return noHost
		}
		k := args[0].kind
		keys := args[1:]
		h.use(keys)
		for _, key := range keys {
			if _, ok := key.node.(*tparse.StringNode); ok {
				k = noHost
				continue
			}
			if k == oneHost {
				h.fail(key.node)
			}
			k = k.elem()
		}
		return k
	}
	h.use(args)
	return noHost
}

func (h *tmplHosts) value(n tparse.Node) hostKind {
	switch n := n.(type) {
	case *tparse.FieldNode:
		if h.top && len(n.Ident) == 1 && n.Ident[0] == "hosts" {
			return hostList
		}
	case *tparse.VariableNode:
		switch {
		case n.Ident[0] == "$" && h.c.main && len(n.Ident) == 2 && n.Ident[1] == "hosts":
			return hostList
		case len(n.Ident) == 1:
			return h.get(n.Ident[0])
		}
	case *tparse.DotNode:
		if !h.top {
			return h.dot
		}
	case *tparse.ChainNode:
		h.value(n.Node)
	case *tparse.PipeNode:
		return h.pipe(n)
	}
	return noHost
}

// walk checks n. top is false where "." is another value: inside range and
// with, and in a defined template.
func (c *nameCheck) walk(n tparse.Node, top bool) {
	switch n := n.(type) {
	case *tparse.ListNode:
		if n != nil {
			for _, x := range n.Nodes {
				c.walk(x, top)
			}
		}
	case *tparse.ActionNode:
		c.walk(n.Pipe, top)
	case *tparse.TemplateNode:
		if c.t.Lookup(n.Name) == nil {
			var defined []string
			for _, d := range c.t.Templates() {
				defined = append(defined, d.Name())
			}
			c.errs = append(c.errs, yamlx.Errorf(c.at(int(n.Pos)), "template %q is not defined in this template%s", n.Name, yamlx.Suggest(n.Name, defined)))
		}
		if n.Pipe != nil {
			c.walk(n.Pipe, top)
		}
	case *tparse.PipeNode:
		if n != nil {
			for _, x := range n.Cmds {
				c.walk(x, top)
			}
		}
	case *tparse.CommandNode:
		id, _ := n.Args[0].(*tparse.IdentifierNode)
		lookup := id != nil && (id.Ident == "get" || id.Ident == "index")
		var byKey *tparse.StringNode
		if lookup && len(n.Args) > 2 {
			byKey, _ = n.Args[2].(*tparse.StringNode)
		}
		if id != nil && id.Ident == "match" {
			c.match(n)
		}
		outer := c.byKey
		for i, x := range n.Args {
			c.byKey = nil
			if i == 1 {
				c.byKey = byKey
			}
			c.walk(x, top)
		}
		c.byKey = outer
		if key, ok := n.Args[len(n.Args)-1].(*tparse.StringNode); lookup && ok && key.Text == "vars" {
			c.notByName(int(key.Pos))
		}
	case *tparse.ChainNode:
		c.walk(n.Node, top)
		c.peers(n.Field, int(n.Pos))
	case *tparse.IfNode:
		c.walk(n.Pipe, top)
		c.walk(n.List, top)
		c.walk(n.ElseList, top)
	case *tparse.RangeNode:
		c.fields, c.elem = elemFields(n)
		c.walk(n.Pipe, top)
		c.fields, c.elem = nil, false
		c.walk(n.List, false)
		c.walk(n.ElseList, top)
	case *tparse.WithNode:
		c.walk(n.Pipe, top)
		c.walk(n.List, false)
		c.walk(n.ElseList, top)
	case *tparse.FieldNode:
		// The position of .a.b is the position of .b.
		dot := int(n.Pos)
		if len(n.Ident) > 1 {
			dot -= len(n.Ident[0]) + 1
		}
		if top {
			c.field(n.Ident, dot, dot)
		} else {
			c.peers(n.Ident, dot)
		}
	case *tparse.VariableNode:
		// The position of $.a is the position of .a.
		switch {
		case c.main && n.Ident[0] == "$" && len(n.Ident) > 1:
			c.field(n.Ident[1:], int(n.Pos), int(n.Pos)-1)
		case c.main && n.Ident[0] == "$":
			c.notByName(int(n.Pos))
		default:
			c.peers(n.Ident[1:], int(n.Pos))
		}
	case *tparse.DotNode:
		if top {
			c.notByName(int(n.Pos))
		}
	}
}

// match logs the call of match n: the hosts that it can reach, and a
// constant pattern for the check against the inventory.
func (c *nameCheck) match(n *tparse.CommandNode) {
	c.data = true
	if len(n.Args) != 2 {
		c.sc.reach.all = true
		return
	}
	pattern, ok := n.Args[1].(*tparse.StringNode)
	if !ok {
		c.sc.reach.all = true
		return
	}
	c.matches = append(c.matches, matchCall{pos: c.at(int(n.Pos)), pattern: pattern.Text})
	c.sc.reach.patterns = append(c.sc.reach.patterns, pattern.Text)
}

func (c *nameCheck) notByName(off int) {
	c.errs = append(c.errs, yamlx.Errorf(c.at(off), "%s", notByName))
}

// log adds a read of the variable name at the offset off.
func (c *nameCheck) log(name string, off int) {
	*c.sc.reads = append(*c.sc.reads, varRead{name: name, pos: c.at(off)})
}

// peers logs the variable after each vars in ident, a field of a value
// other than the data, such as a host from match(). A read of the whole vars
// map would lose the computed defaults of such a host.
func (c *nameCheck) peers(ident []string, off int) {
	for i := 1; i < len(ident); i++ {
		if ident[i-1] == "vars" {
			c.peerReads = append(c.peerReads, ident[i])
			c.log(ident[i], off)
		}
	}
	if len(ident) > 0 && ident[len(ident)-1] == "vars" {
		if c.byKey == nil {
			c.notByName(off)
			return
		}
		c.peerReads = append(c.peerReads, c.byKey.Text)
		c.log(c.byKey.Text, int(c.byKey.Pos))
	}
}

// field checks the names of a field such as .host.vars.domain. dot is the
// offset of its first dot, first the offset for an error in the first name.
func (c *nameCheck) field(ident []string, dot, first int) {
	switch ident[0] {
	case "item":
		c.item = true
	case "hosts":
		c.data, c.hosts = true, true
		c.sc.reach.all = true
	default:
		c.data = true
	}
	level := c.top
	vars := c.top.sub["vars"]
	off := first
	for i, id := range ident {
		if level == nil {
			c.peers(ident[i-1:], dot)
			return
		}
		if i > 0 {
			off = dot
		}
		if level == vars {
			c.reads = append(c.reads, id)
			switch {
			case !c.elem || len(c.fields) > 0 && i < len(ident)-1:
				c.values = append(c.values, id)
			default:
				for _, f := range c.fields {
					c.values = append(c.values, id+"."+f)
				}
			}
			c.log(id, off)
			c.peers(ident[i+1:], dot)
			return
		}
		next, ok := level.sub[id]
		if !ok {
			var opts []string
			for n := range level.sub {
				opts = append(opts, n)
			}
			slices.Sort(opts)
			c.errs = append(c.errs, yamlx.Errorf(c.at(off), "unknown %s %q%s", level.noun, id, yamlx.Suggest(id, opts)))
			return
		}
		level = next
		dot += len(id) + 1
	}
	if level == vars || level == c.top.sub["host"] {
		c.notByName(first)
	}
}

// elemFields returns the fields of the element that the body of the range n
// reads, as .name in range .vars.m or $v.name in range $k, $v := .vars.m. It
// returns false when the body reads the element whole. With =, the variables
// keep the last element after the range.
func elemFields(n *tparse.RangeNode) ([]string, bool) {
	if n.Pipe.IsAssign || len(n.Pipe.Cmds) != 1 || len(n.Pipe.Cmds[0].Args) != 1 {
		return nil, false
	}
	switch n.Pipe.Cmds[0].Args[0].(type) {
	case *tparse.FieldNode, *tparse.VariableNode:
	default:
		return nil, false
	}
	v := ""
	if d := n.Pipe.Decl; len(d) > 0 {
		v = d[len(d)-1].Ident[0]
	}
	var fields []string
	if !readsElem(n.List, v, true, &fields) {
		return nil, false
	}
	return fields, true
}

// readsElem adds to fields the first name of each field that n reads of the
// variable v, or of dot where dot is true. It returns false when n reads v or
// dot whole.
func readsElem(n tparse.Node, v string, dot bool, fields *[]string) bool {
	all := func(dot bool, ns ...tparse.Node) bool {
		for _, x := range ns {
			if !readsElem(x, v, dot, fields) {
				return false
			}
		}
		return true
	}
	switch n := n.(type) {
	case *tparse.ListNode:
		return n == nil || all(dot, n.Nodes...)
	case *tparse.ActionNode:
		return all(dot, n.Pipe)
	case *tparse.TemplateNode:
		return n.Pipe == nil || all(dot, n.Pipe)
	case *tparse.PipeNode:
		for _, x := range n.Cmds {
			if !all(dot, x) {
				return false
			}
		}
		return true
	case *tparse.CommandNode:
		return all(dot, n.Args...)
	case *tparse.ChainNode:
		return all(dot, n.Node)
	case *tparse.IfNode:
		return all(dot, n.Pipe, n.List, n.ElseList)
	case *tparse.RangeNode:
		return all(dot, n.Pipe, n.ElseList) && all(false, n.List)
	case *tparse.WithNode:
		return all(dot, n.Pipe, n.ElseList) && all(false, n.List)
	case *tparse.DotNode:
		return !dot
	case *tparse.FieldNode:
		if dot {
			*fields = append(*fields, n.Ident[0])
		}
	case *tparse.VariableNode:
		if n.Ident[0] != v {
			return true
		}
		if len(n.Ident) == 1 {
			return false
		}
		*fields = append(*fields, n.Ident[1])
	}
	return true
}

// nullError is the error of an action that prints a null value. text is the
// pipeline of the action.
type nullError struct{ text string }

func (nullError) Error() string { return "null is not a value" }

// failNull makes each action of t that prints fail on a null value: the
// template package prints null as "<no value>". It adds the notNull function
// at the end of the pipeline, after the parse, so that a template cannot call
// it.
func failNull(t *template.Template) {
	t.Funcs(template.FuncMap{"notNull": notNull})
	var walk func(n tparse.Node)
	walk = func(n tparse.Node) {
		switch n := n.(type) {
		case *tparse.ListNode:
			if n != nil {
				for _, x := range n.Nodes {
					walk(x)
				}
			}
		case *tparse.ActionNode:
			if len(n.Pipe.Decl) > 0 {
				return
			}
			text := n.Pipe.String()
			n.Pipe.Cmds = append(n.Pipe.Cmds, &tparse.CommandNode{NodeType: tparse.NodeCommand, Pos: n.Pipe.Pos, Args: []tparse.Node{
				tparse.NewIdentifier("notNull").SetPos(n.Pipe.Pos),
				&tparse.StringNode{NodeType: tparse.NodeString, Pos: n.Pipe.Pos, Quoted: strconv.Quote(text), Text: text},
			}})
		case *tparse.IfNode:
			walk(n.List)
			walk(n.ElseList)
		case *tparse.RangeNode:
			walk(n.List)
			walk(n.ElseList)
		case *tparse.WithNode:
			walk(n.List)
			walk(n.ElseList)
		}
	}
	for _, d := range t.Templates() {
		walk(d.Root)
	}
}

func notNull(text string, v any) (any, error) {
	if v == nil {
		return nil, nullError{text}
	}
	return v, nil
}

// index is the built-in index, except that a missing map key is an error.
func index(item any, keys ...any) (any, error) {
	v := reflect.ValueOf(item)
	for _, k := range keys {
		kv := reflect.ValueOf(k)
		switch v.Kind() {
		case reflect.Map:
			if !kv.IsValid() || !kv.Type().AssignableTo(v.Type().Key()) {
				return nil, fmt.Errorf("index: key %v is not a %s", k, v.Type().Key())
			}
			e := v.MapIndex(kv)
			if !e.IsValid() {
				return nil, fmt.Errorf("map has no entry for key %q", fmt.Sprint(k))
			}
			v = e
		case reflect.Slice, reflect.Array, reflect.String:
			i, ok := k.(int)
			if !ok {
				return nil, fmt.Errorf("index: %v is not an integer", k)
			}
			if i < 0 || i >= v.Len() {
				return nil, fmt.Errorf("index %d out of range for length %d", i, v.Len())
			}
			v = v.Index(i)
		default:
			return nil, fmt.Errorf("index: cannot index %s", v.Kind())
		}
		for v.Kind() == reflect.Interface {
			v = v.Elem()
		}
	}
	if !v.IsValid() {
		return nil, nil
	}
	return v.Interface(), nil
}

// get reads a key that a map may leave out. A missing key gives nil.
func get(m any, key string) (any, error) {
	mm, ok := m.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("get: %s is not a map", describeValue(m))
	}
	if err := computedError(mm[key]); err != nil {
		return nil, err
	}
	return mm[key], nil
}

func listArg(name string, l any) (reflect.Value, error) {
	v := reflect.ValueOf(l)
	if v.Kind() != reflect.Slice && v.Kind() != reflect.Array {
		return v, fmt.Errorf("%s: %s is not a list", name, describeValue(l))
	}
	return v, nil
}

func join(l any, sep string) (string, error) {
	v, err := listArg("join", l)
	if err != nil {
		return "", err
	}
	parts := make([]string, v.Len())
	for i := range v.Len() {
		e := v.Index(i).Interface()
		if e == nil {
			return "", fmt.Errorf("join: element %d is null", i+1)
		}
		parts[i] = fmt.Sprint(e)
	}
	return strings.Join(parts, sep), nil
}

func has(l any, x any) (bool, error) {
	v, err := listArg("has", l)
	if err != nil {
		return false, err
	}
	for i := range v.Len() {
		if reflect.DeepEqual(v.Index(i).Interface(), x) {
			return true, nil
		}
	}
	return false, nil
}

func title(s string) string {
	var b strings.Builder
	start := true
	for _, r := range s {
		if start {
			r = unicode.ToUpper(r)
		}
		start = unicode.IsSpace(r)
		b.WriteRune(r)
	}
	return b.String()
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var sqlEscapes = strings.NewReplacer(`\`, `\\`, "'", "''")

func sqlquote(s string) string {
	return "'" + sqlEscapes.Replace(s) + "'"
}

// jsonEscapes escapes the characters that encoding/json keeps and YAML does
// not allow unescaped: control characters and U+FFFE and U+FFFF.
var jsonEscapes = func() *strings.Replacer {
	pairs := []string{"\ufffe", `\ufffe`, "\uffff", `\uffff`}
	for r := rune(0x7f); r <= 0x9f; r++ {
		pairs = append(pairs, string(r), fmt.Sprintf(`\u%04x`, r))
	}
	return strings.NewReplacer(pairs...)
}()

func toJSON(v any) (string, error) {
	if err := computedIn(v); err != nil {
		return "", err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return jsonEscapes.Replace(strings.TrimSuffix(b.String(), "\n")), nil
}

var undefinedFuncRe = regexp.MustCompile(`: function "(\w+)" not defined$`)

// exprFuncHint is the hint for a parse error of a template that calls an
// expression function, with fix as the way to use it, or "".
func exprFuncHint(err error, fix string) string {
	if f := undefinedFuncRe.FindStringSubmatch(err.Error()); f != nil && isExprFunc(f[1]) {
		return fmt.Sprintf("; %s is an expression function: %s", f[1], fix)
	}
	return ""
}

var templateErrRe = regexp.MustCompile(`(?s)^(\d+)(?::(\d+))?: (?:executing "(?:[^"\\]|\\.)*" at <(.*?)>: )?(.*)$`)

// parseTemplateError splits an error of the template package for the template
// name into the line, the column, and the message. A parse error has no
// column, so it gets column 1.
func parseTemplateError(name string, err error) (line, col int, msg string, ok bool) {
	m := templateErrRe.FindStringSubmatch(strings.TrimPrefix(err.Error(), "template: "+name+":"))
	if m == nil {
		return 0, 0, "", false
	}
	line, _ = strconv.Atoi(m[1])
	col = 1
	if m[2] != "" {
		col, _ = strconv.Atoi(m[2])
		col++
	}
	msg = m[4]
	if m[3] != "" {
		msg = m[3] + ": " + msg
	}
	return line, col, msg, true
}

// templateError turns an error of the template package into an error with
// the position in file.
func templateError(file string, err error) error {
	line, col, msg, ok := parseTemplateError(file, err)
	if !ok {
		return fmt.Errorf("%s: %w", file, err)
	}
	return yamlx.Errorf(yamlx.Pos{File: file, Line: line, Col: col}, "%s", msg)
}

// templateMessage is the message of an error of the template package, without
// the position.
func templateMessage(name string, err error) string {
	if _, _, msg, ok := parseTemplateError(name, err); ok {
		return msg
	}
	return err.Error()
}
