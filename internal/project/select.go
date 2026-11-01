package project

import (
	"fmt"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

// Selection holds the flags that pick what a run does: --hosts, --stages, and
// --user.
type Selection struct {
	Hosts  string
	Stages string
	Users  []string
}

// Select sets the users of the hosts, marks the stages that the selection
// leaves out as skipped, and keeps in each stage only the hosts of the host
// pattern. A skipped stage keeps its hosts: the requirements and the
// handlers of its recipes still count. A run in which no stage has a host is
// an error.
func (p *Project) Select(sel Selection) error {
	if err := p.setUsers(sel.Users); err != nil {
		return err
	}
	var flags []string
	if sel.Hosts != "" {
		flags = append(flags, "--hosts "+sel.Hosts)
		hosts, err := p.Inventory.Match(sel.Hosts)
		if err != nil {
			return fmt.Errorf("--hosts %s: %s", sel.Hosts, problem(err))
		}
		for i := range p.Pipeline.Stages {
			s := &p.Pipeline.Stages[i]
			s.Targets = slices.DeleteFunc(s.Targets, func(t Host) bool {
				return !slices.ContainsFunc(hosts, func(h Host) bool { return h.Name == t.Name })
			})
		}
	}
	if sel.Stages != "" {
		flags = append(flags, "--stages "+sel.Stages)
		var names []string
		for _, s := range p.Pipeline.Stages {
			names = append(names, s.Name)
		}
		want := map[string]bool{}
		for name := range strings.SplitSeq(sel.Stages, ",") {
			name = strings.TrimSpace(name)
			switch {
			case name == "":
				return fmt.Errorf("--stages %s: an empty stage name", sel.Stages)
			case !slices.Contains(names, name):
				return fmt.Errorf("--stages %s: unknown stage %q%s", sel.Stages, name, yamlx.Suggest(name, names))
			}
			want[name] = true
		}
		for i := range p.Pipeline.Stages {
			p.Pipeline.Stages[i].Skipped = !want[p.Pipeline.Stages[i].Name]
		}
	}
	runs := slices.ContainsFunc(p.Pipeline.Stages, func(s Stage) bool { return !s.Skipped && len(s.Targets) > 0 })
	switch {
	case runs:
		return nil
	case flags != nil:
		return fmt.Errorf("%s: no selected stage runs on these hosts", strings.Join(flags, " "))
	case len(p.Pipeline.Stages) == 1:
		return fmt.Errorf("the host pattern %q matches no host in %s", p.Pipeline.Stages[0].Hosts, p.Inventory.File)
	default:
		return fmt.Errorf("no stage of pipeline %s matches a host in %s", p.Pipeline.Name, p.Inventory.File)
	}
}

// setUsers sets the login user of the hosts from --user values: name for all
// hosts, or host=name for one host. A host value beats the value for all.
func (p *Project) setUsers(users []string) error {
	if len(users) == 0 {
		return nil
	}
	all := ""
	byHost := map[string]string{}
	var names []string
	for _, h := range p.Inventory.Hosts {
		names = append(names, h.Name)
	}
	for _, u := range users {
		host, name, one := strings.Cut(u, "=")
		if !one {
			host, name = "", u
		}
		switch {
		case name == "":
			return fmt.Errorf("--user %s: the user name is empty", u)
		case one && host == "":
			return fmt.Errorf("--user %s: the host before = is empty", u)
		case !one && all != "":
			return fmt.Errorf("--user %s: the user for all hosts is %s already", u, all)
		case !one:
			all = name
		case !slices.Contains(names, host):
			return fmt.Errorf("--user %s: unknown host %q%s", u, host, yamlx.Suggest(host, names))
		case byHost[host] != "":
			return fmt.Errorf("--user %s: host %s has the user %s already", u, host, byHost[host])
		default:
			byHost[host] = name
		}
	}
	user := map[string]string{}
	for i := range p.Inventory.Hosts {
		h := &p.Inventory.Hosts[i]
		if u := byHost[h.Name]; u != "" {
			h.User = u
		} else if all != "" {
			h.User = all
		}
		user[h.Name] = h.User
	}
	for i := range p.Pipeline.Stages {
		for j := range p.Pipeline.Stages[i].Targets {
			t := &p.Pipeline.Stages[i].Targets[j]
			t.User = user[t.Name]
		}
	}
	return nil
}
