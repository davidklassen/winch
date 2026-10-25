package project

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Inventory struct {
	File   string
	Hosts  []Host  `yaml:"hosts"`
	Groups []Group `yaml:"groups"`
}

type Host struct {
	Name     string      `yaml:",key"`
	Address  string      `yaml:"address"`
	User     string      `yaml:"user"`
	VarsNode *yamlx.Node `yaml:"vars"`
	Pos      yamlx.Pos
	// Groups are the groups of the host: all, then the others in file order.
	Groups []string
	// Vars are the values from the inventory and from --set.
	Vars map[string]any
}

type Group struct {
	Name      string `yaml:",key"`
	User      string `yaml:"user"`
	UserPos   yamlx.Pos
	HostsNode *yamlx.Node `yaml:"hosts"`
	VarsNode  *yamlx.Node `yaml:"vars"`
	Pos       yamlx.Pos
	members   []string
	vars      []source
}

// source is one value of a variable in the inventory.
type source struct {
	name  string
	value any
	pos   yamlx.Pos
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

// loadInventory loads an inventory file. Its variables must be declared; the
// values of set come last.
func (l *loader) loadInventory(file string, set []setValue) (*Inventory, error) {
	n, err := parse(l.dir, file)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{File: file}
	if err := yamlx.Decode(n, inv); err != nil {
		return nil, err
	}
	var errs []error
	hostNames := map[string]bool{}
	var names []string
	for _, h := range inv.Hosts {
		hostNames[h.Name] = true
		names = append(names, h.Name)
	}
	for i := range inv.Groups {
		g := &inv.Groups[i]
		var verrs []error
		g.vars, verrs = l.values(g.VarsNode)
		errs = append(errs, verrs...)
		switch {
		case g.Name == "all" && g.HostsNode != nil:
			errs = append(errs, yamlx.Errorf(g.Pos, "the group all contains every host; it cannot have hosts"))
		case g.Name == "all":
			g.members = names
		case hostNames[g.Name]:
			errs = append(errs, yamlx.Errorf(g.Pos, "group %q has the name of a host", g.Name))
		default:
			var merr error
			g.members, merr = members(g, hostNames, names)
			errs = append(errs, merr)
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
		own, verrs := l.values(h.VarsNode)
		errs = append(errs, verrs...)
		errs = append(errs, inv.resolve(h, own, set))
	}
	errs = append(errs, inv.required(l.decls))
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return inv, nil
}

// values returns the variable values in n, a map of names to values.
func (l *loader) values(n *yamlx.Node) ([]source, []error) {
	if n == nil || n.Kind == yamlx.Null {
		return nil, nil
	}
	if n.Kind != yamlx.Map {
		return nil, []error{yamlx.Errorf(n.Pos, "vars: expected a map, got %s", yamlx.Describe(n))}
	}
	var out []source
	var errs []error
	for _, p := range n.Pairs {
		switch {
		case l.vars[p.Key] == nil:
			errs = append(errs, yamlx.Errorf(p.KeyPos, "%s", unknownVariable(p.Key, l.vars)))
		case p.Value.Kind == yamlx.Null:
			errs = append(errs, yamlx.Errorf(p.Value.Pos, "variable %q: null is not a value", p.Key))
		default:
			errs = append(errs, l.seal(p.Value, fmt.Sprintf("variable %q: an inventory holds no expressions or templates", p.Key))...)
			out = append(out, source{name: p.Key, value: yamlx.Value(p.Value), pos: p.Value.Pos})
		}
	}
	return out, errs
}

func members(g *Group, hostNames map[string]bool, names []string) ([]string, error) {
	if g.HostsNode == nil || g.HostsNode.Kind == yamlx.Null {
		return nil, nil
	}
	if g.HostsNode.Kind != yamlx.List {
		return nil, yamlx.Errorf(g.HostsNode.Pos, "hosts: expected a list, got %s", yamlx.Describe(g.HostsNode))
	}
	var out []string
	var errs []error
	for _, item := range g.HostsNode.Items {
		name, ok := item.Value.(string)
		switch {
		case !ok || item.Tag != "":
			errs = append(errs, yamlx.Errorf(item.Pos, "hosts: expected a host name, got %s", yamlx.Describe(item)))
		case !hostNames[name]:
			errs = append(errs, yamlx.Errorf(item.Pos, "unknown host %q%s", name, yamlx.Suggest(name, names)))
		case slices.Contains(out, name):
			errs = append(errs, yamlx.Errorf(item.Pos, "host %q is in the group twice", name))
		default:
			out = append(out, name)
		}
	}
	return out, errors.Join(errs...)
}

// resolve sets the groups, the user, and the variables of h. A host value
// beats a group value, a group value beats all, and --set beats them all.
func (inv *Inventory) resolve(h *Host, own []source, set []setValue) error {
	h.Vars = map[string]any{}
	h.Groups = []string{"all"}
	user := h.User
	var errs []error
	var all *Group
	from := map[string]*Group{}
	var userFrom *Group
	for i := range inv.Groups {
		g := &inv.Groups[i]
		if g.Name == "all" {
			all = g
			continue
		}
		if !slices.Contains(g.members, h.Name) {
			continue
		}
		h.Groups = append(h.Groups, g.Name)
		for _, s := range g.vars {
			if first := from[s.name]; first != nil && !reflect.DeepEqual(h.Vars[s.name], s.value) && !slices.ContainsFunc(own, func(o source) bool { return o.name == s.name }) &&
				!slices.ContainsFunc(set, func(v setValue) bool { return v.name == s.name }) {
				errs = append(errs, yamlx.Errorf(s.pos, "variable %q: groups %s and %s of host %s set different values", s.name, first.Name, g.Name, h.Name))
				continue
			}
			from[s.name] = g
			h.Vars[s.name] = s.value
		}
		if g.User == "" {
			continue
		}
		if userFrom != nil && userFrom.User != g.User && h.User == "" {
			errs = append(errs, yamlx.Errorf(g.UserPos, "user: groups %s and %s of host %s set different users", userFrom.Name, g.Name, h.Name))
			continue
		}
		userFrom = g
		if user == "" {
			user = g.User
		}
	}
	if all != nil {
		for _, s := range all.vars {
			if _, ok := h.Vars[s.name]; !ok {
				h.Vars[s.name] = s.value
			}
		}
		if user == "" {
			user = all.User
		}
	}
	for _, s := range own {
		h.Vars[s.name] = s.value
	}
	for _, s := range set {
		h.Vars[s.name] = s.value
	}
	h.User = user
	return errors.Join(errs...)
}

// required checks that every host has a value for each required variable of
// winch.yaml.
func (inv *Inventory) required(vars []*Var) error {
	var errs []error
	for _, v := range vars {
		if v.Recipe != "" || !v.required() {
			continue
		}
		var without []string
		for _, h := range inv.Hosts {
			if _, ok := h.Vars[v.Name]; !ok {
				without = append(without, h.Name)
			}
		}
		if without != nil {
			errs = append(errs, yamlx.Errorf(v.Pos, "variable %q is required and has no value on %s", v.Name, strings.Join(without, ", ")))
		}
	}
	return errors.Join(errs...)
}

// match returns the hosts of a pattern: a group or a host, in inventory order.
func (inv *Inventory) match(pattern string, pos yamlx.Pos) ([]Host, error) {
	var out []Host
	for _, h := range inv.Hosts {
		if h.Name == pattern || slices.Contains(h.Groups, pattern) {
			out = append(out, h)
		}
	}
	names := []string{"all"}
	for _, g := range inv.Groups {
		names = append(names, g.Name)
	}
	if out != nil || slices.Contains(names, pattern) {
		return out, nil
	}
	for _, h := range inv.Hosts {
		names = append(names, h.Name)
	}
	return nil, yamlx.Errorf(pos, "unknown host or group %q in %s%s", pattern, inv.File, yamlx.Suggest(pattern, names))
}
