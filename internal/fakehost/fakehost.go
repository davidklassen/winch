// Package fakehost is a test double for hosts: it keeps files, packages,
// answers, and facts in memory and checks and applies file, dir, pkg,
// service, user, group, and debconf steps against them. It keeps pending
// handlers, then records, health gates, and asserts. It runs commands, cmd
// steps, and asserts as records.
package fakehost

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
)

type Hosts struct {
	mu         sync.Mutex
	files      map[string]map[string]string
	noDirs     map[string]map[string]bool
	pkgs       map[string]map[string]bool
	pkgFiles   map[string]map[string]string
	pkgDeps    map[string][]string
	failCheck  map[string]bool
	failApply  map[string]bool
	Applies    int
	Refreshes  map[string]int
	FactsReads map[string]int
	facts      map[string]facts.Facts
	pending    map[string][]string
	thens      map[string][]protocol.Then
	checks     map[string][]protocol.Check
	failCmd    map[string]bool
	// Log lists the service actions and the commands per host, in order.
	Log map[string][]string
	// Open is the number of open connections.
	Open int
	// Connects counts the connects per host.
	Connects map[string]int
	down     map[string]bool
	users    map[string]bool
	groups   map[string]bool
	answers  map[string]string
	results  map[string]module.Result
	execs    map[string]module.ExecResult
	// failExec and failClose hold the hosts whose exec or close fails.
	failExec, failClose map[string]bool
	// OnCheck and OnApply run before each check and each apply of a step,
	// with the host and the main argument of the step.
	OnCheck, OnApply func(host, main string)
	// OnConnect runs before each connect, and OnExec in each exec.
	OnConnect, OnExec func(host string)
	// Batch lists the batch mode of each ConnectorFor call.
	Batch []bool
	// Users holds the login user of the last connect of each host.
	Users map[string]string
	// MaxOpen is the highest number of open connections.
	MaxOpen int
	// Trace lists the connects, applies, health gates, and closes of all
	// hosts, in order.
	Trace []string
	// RepoRemoved lists the Removed paths of each checked repo step.
	RepoRemoved [][]string
	// ServiceNewFile lists the name and the NewFile of each checked service
	// step, as "name: content".
	ServiceNewFile []string
	// DirKeep holds the Keep paths of the last checked dir step with purge,
	// by "host path".
	DirKeep map[string][]string
	// Guards holds the guard of each apply, by "host main".
	Guards map[string]protocol.Guard
	// noAccess holds the hosts whose access check fails, and noAccessOnce
	// those whose next one fails.
	noAccess, noAccessOnce map[string]bool
	// timer is the time that a started rollback timer has left.
	timer time.Duration
	// rollbackErr is the error of every rollback.
	rollbackErr error
	boots       map[string]protocol.Boot
	// dests holds the destinations that SetDestination set.
	dests map[string]protocol.Destination
}

func New() *Hosts {
	return &Hosts{
		files:        map[string]map[string]string{},
		noDirs:       map[string]map[string]bool{},
		pkgs:         map[string]map[string]bool{},
		pkgFiles:     map[string]map[string]string{},
		pkgDeps:      map[string][]string{},
		failCheck:    map[string]bool{},
		failApply:    map[string]bool{},
		Refreshes:    map[string]int{},
		FactsReads:   map[string]int{},
		facts:        map[string]facts.Facts{},
		pending:      map[string][]string{},
		thens:        map[string][]protocol.Then{},
		checks:       map[string][]protocol.Check{},
		failCmd:      map[string]bool{},
		Log:          map[string][]string{},
		results:      map[string]module.Result{},
		execs:        map[string]module.ExecResult{},
		failExec:     map[string]bool{},
		failClose:    map[string]bool{},
		Connects:     map[string]int{},
		Users:        map[string]string{},
		down:         map[string]bool{},
		users:        map[string]bool{},
		groups:       map[string]bool{},
		answers:      map[string]string{},
		DirKeep:      map[string][]string{},
		Guards:       map[string]protocol.Guard{},
		noAccess:     map[string]bool{},
		noAccessOnce: map[string]bool{},
		timer:        time.Nanosecond,
		boots:        map[string]protocol.Boot{},
		dests:        map[string]protocol.Destination{},
	}
}

// FailAccess makes the access check of host fail.
func (h *Hosts) FailAccess(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.noAccess[host] = true
}

// FailAccessOnce makes the next access check of host fail.
func (h *Hosts) FailAccessOnce(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.noAccessOnce[host] = true
}

// SetTimer sets the time that a started rollback timer has left.
func (h *Hosts) SetTimer(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.timer = d
}

// FailRollback makes every rollback fail with err.
func (h *Hosts) FailRollback(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rollbackErr = err
}

// SetBoot sets what a reboot of host reports.
func (h *Hosts) SetBoot(host string, b protocol.Boot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.boots[host] = b
}

// SetAnswer sets the debconf answer of a question on a host.
func (h *Hosts) SetAnswer(host, question, value string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answers[host+" "+question] = value
}

// SetResult makes the check of the dir or link step for path, of the line step
// for its match, or of the service step
// for the unit name, on a host return res.
func (h *Hosts) SetResult(host, name string, res module.Result) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.results[host+" "+name] = res
}

// result returns a copy of the result that SetResult stored for key. The run
// masks changes in place, which must not change the stored result. The caller
// holds mu.
func (h *Hosts) result(key string) (module.Result, bool) {
	res, ok := h.results[key]
	res.Changes = slices.Clone(res.Changes)
	return res, ok
}

// SetUser makes the user name exist on a host.
func (h *Hosts) SetUser(host, name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users[host+" "+name] = true
}

// SetGroup makes the group name exist on a host.
func (h *Hosts) SetGroup(host, name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.groups[host+" "+name] = true
}

func (h *Hosts) SetPending(host string, names ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pending[host] = names
}

func (h *Hosts) PendingOf(host string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.pending[host])
}

func (h *Hosts) SetThen(host string, thens ...protocol.Then) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.thens[host] = thens
}

// ThenOf returns the pending then records of a host.
func (h *Hosts) ThenOf(host string) []protocol.Then {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.thens[host])
}

// Pend records a pending health gate or assert on a host.
func (h *Hosts) Pend(host string, c protocol.Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[host] = append(h.checks[host], c)
}

// ChecksOf returns the pending health gates and asserts of a host.
func (h *Hosts) ChecksOf(host string) []protocol.Check {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.checks[host])
}

func (h *Hosts) FailCommand(host, command string) { h.failCmd[host+" "+command] = true }

func (h *Hosts) SetFile(host, path, content string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.files[host] == nil {
		h.files[host] = map[string]string{}
	}
	h.files[host][path] = content
}

// RemoveDir makes the directory dir missing on a host. Every other directory
// exists.
func (h *Hosts) RemoveDir(host, dir string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.noDirs[host] == nil {
		h.noDirs[host] = map[string]bool{}
	}
	h.noDirs[host][dir] = true
}

// missingParents returns the parent lines of the missing parents of p, from
// the top.
func (c *Conn) missingParents(p string) []string {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	var changes []string
	for d := path.Dir(p); d != "/"; d = path.Dir(d) {
		if c.hosts.noDirs[c.host][d] {
			changes = append(changes, module.ParentChange(d))
		}
	}
	slices.Reverse(changes)
	return changes
}

// makeDirs creates p and its parents. The caller holds the lock.
func (c *Conn) makeDirs(p string) {
	for d := p; d != "/"; d = path.Dir(d) {
		delete(c.hosts.noDirs[c.host], d)
	}
}

// SetPkgFile makes an install of the package pkg write a file.
func (h *Hosts) SetPkgFile(pkg, path, content string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pkgFiles[pkg] == nil {
		h.pkgFiles[pkg] = map[string]string{}
	}
	h.pkgFiles[pkg][path] = content
}

// SetPkg installs packages on a host.
func (h *Hosts) SetPkg(host string, names ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pkgs[host] == nil {
		h.pkgs[host] = map[string]bool{}
	}
	for _, n := range names {
		h.pkgs[host][n] = true
	}
}

// SetPkgDeps makes the package pkg depend on deps.
func (h *Hosts) SetPkgDeps(pkg string, deps ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pkgDeps[pkg] = deps
}

// SetFacts sets the facts of a host. A host without them is Debian 13 on amd64.
func (h *Hosts) SetFacts(host string, f facts.Facts) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.facts[host] = f
}

func (h *Hosts) File(host, path string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.files[host][path]
	return c, ok
}

// FailCheck makes checks fail on a host, or only for one path with
// "host path".
func (h *Hosts) FailCheck(key string) { h.failCheck[key] = true }
func (h *Hosts) FailApply(key string) { h.failApply[key] = true }

// Fix ends the failures that FailCheck, FailApply, and FailCommand set for
// key.
func (h *Hosts) Fix(key string) {
	delete(h.failCheck, key)
	delete(h.failApply, key)
	delete(h.failCmd, key)
}

// SetUnreachable makes each later connect to host fail as unreachable.
func (h *Hosts) SetUnreachable(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.down[host] = true
}

func (h *Hosts) Connect(ctx context.Context, host project.Host) (*Conn, error) {
	if h.OnConnect != nil {
		h.OnConnect(host.Name)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if host.Address == "unreachable" || h.down[host.Name] {
		return nil, run.MarkUnreachable(errors.New("ssh: connect to host " + host.Address + ": Connection refused"))
	}
	h.Open++
	h.MaxOpen = max(h.MaxOpen, h.Open)
	h.Connects[host.Name]++
	h.Users[host.Name] = host.User
	h.Trace = append(h.Trace, "connect "+host.Name)
	dest, ok := h.dests[host.Name]
	if !ok {
		dest = protocol.Destination{User: host.User, HostName: host.Address, Port: "22"}
	}
	return &Conn{hosts: h, host: host.Name, dest: dest}, nil
}

// SetDestination sets the destination that each later session with host
// reports, as an SSH config would. Without it, a session reports the user
// and address of the inventory, and port 22.
func (h *Hosts) SetDestination(host string, d protocol.Destination) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dests[host] = d
}

func (h *Hosts) fails(m map[string]bool, host, path string) bool {
	return m[host] || m[host+" "+path]
}

// ConnectorFor returns Connect as a run.Connect, and records batch.
func (h *Hosts) ConnectorFor(batch bool) run.Connect {
	h.mu.Lock()
	h.Batch = append(h.Batch, batch)
	h.mu.Unlock()
	return h.Connector()
}

// Connector returns Connect as a run.Connect.
func (h *Hosts) Connector() run.Connect {
	return func(ctx context.Context, proj string, host project.Host) (run.Conn, error) {
		c, err := h.Connect(ctx, host)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}

type Conn struct {
	hosts *Hosts
	host  string
	dest  protocol.Destination
}

func (c *Conn) Destination() protocol.Destination { return c.dest }

func (c *Conn) Check(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error) {
	if c.hosts.OnCheck != nil {
		c.hosts.OnCheck(c.host, m.Main())
	}
	// A real session finishes a call that has started.
	if ctx.Err() != nil {
		return module.Result{}, fmt.Errorf("fakehost: the call got an ended context: %w", ctx.Err())
	}
	if u, ok := m.(*module.Unit); ok {
		res, err := c.Check(ctx, name, u.File(), st)
		if res.Status == module.Change {
			res.Changes = append(res.Changes, "daemon-reload")
		}
		return res, err
	}
	if p, ok := m.(*module.Pkg); ok {
		return c.checkPkg(p, st), nil
	}
	switch m := m.(type) {
	case *module.Cmd:
		res := module.Result{Status: module.Unknown}
		if m.Unless != nil {
			if !c.hosts.failCmd[c.host+" "+*m.Unless] {
				return module.Result{Status: module.OK}, nil
			}
			res = module.Result{Status: module.Change, Action: module.Modify}
		} else if m.Creates != "" {
			if _, ok := c.hosts.File(c.host, m.Creates); ok {
				return module.Result{Status: module.OK}, nil
			}
			res = module.Result{Status: module.Change, Action: module.Create}
		}
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		if m.User != "" && !c.hosts.users[c.host+" "+m.User] {
			res.Missing = append(res.Missing, "user "+m.User)
		}
		if c.hosts.noDirs[c.host][m.Dir] {
			res.Missing = append(res.Missing, "dir "+m.Dir)
		}
		return res, nil
	case *module.Assert:
		return module.Result{Status: module.OK, Deferred: true}, nil
	case *module.Reboot:
		c.hosts.mu.Lock()
		required := c.hosts.facts[c.host].RebootRequired
		c.hosts.mu.Unlock()
		if !*m.IfRequired || required {
			return module.Result{Status: module.Change, Action: module.Modify}, nil
		}
		return module.Result{Status: module.OK, Deferred: true}, nil
	case *module.Hostname, *module.Timezone, *module.Certbot, *module.Firewall:
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		if res, ok := c.hosts.result(c.host + " " + m.Main()); ok {
			return res, nil
		}
		return module.Result{Status: module.OK}, nil
	}
	if d, ok := m.(*module.Dir); ok {
		return c.checkDir(d), nil
	}
	if u, ok := m.(*module.User); ok {
		res := c.checkAccount(c.hosts.users, u.Name)
		if g := c.checkAccount(c.hosts.groups, u.Name); res.Action == module.Create && u.Group == "" && g.Action == module.Create {
			res.Changes = []string{"group " + u.Name + " (new)"}
		}
		return res, nil
	}
	if g, ok := m.(*module.Group); ok {
		return c.checkAccount(c.hosts.groups, g.Name), nil
	}
	if d, ok := m.(*module.Debconf); ok {
		return c.checkAnswer(d), nil
	}
	if d, ok := m.(*module.Download); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		if res, ok := c.hosts.result(c.host + " " + d.Main()); ok {
			return res, nil
		}
		return module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + d.URL}}, nil
	}
	if l, ok := m.(*module.Link); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		if res, ok := c.hosts.result(c.host + " " + l.Path); ok {
			return res, nil
		}
		return module.Result{Status: module.OK}, nil
	}
	if l, ok := m.(*module.Line); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		if res, ok := c.hosts.result(c.host + " " + l.Match); ok {
			return res, nil
		}
		return module.Result{Status: module.OK}, nil
	}
	if r, ok := m.(*module.Repo); ok {
		c.hosts.mu.Lock()
		c.hosts.RepoRemoved = append(c.hosts.RepoRemoved, r.Removed)
		c.hosts.mu.Unlock()
		return module.Result{Status: module.OK}, nil
	}
	if sv, ok := m.(*module.Service); ok {
		c.hosts.mu.Lock()
		c.hosts.ServiceNewFile = append(c.hosts.ServiceNewFile, sv.Name+": "+string(sv.NewFile))
		res, ok := c.hosts.result(c.host + " " + sv.Name)
		c.hosts.mu.Unlock()
		if ok {
			return res, nil
		}
		if !sv.Reloaded && !sv.Restarted {
			return module.Result{}, errors.New("fakehost: a service step needs reloaded or restarted")
		}
		if c.hosts.fails(c.hosts.failCheck, c.host, sv.Name) {
			return module.Result{}, errors.New("permission denied")
		}
		return module.Result{Status: module.Change, Action: module.Modify, Changes: []string{serviceAction(sv)}}, nil
	}
	f := m.(*module.File)
	if c.hosts.fails(c.hosts.failCheck, c.host, f.Path) {
		return module.Result{}, errors.New("permission denied")
	}
	c.hosts.mu.Lock()
	res, ok := c.hosts.results[c.host+" "+f.Path]
	c.hosts.mu.Unlock()
	if ok {
		return res, nil
	}
	cur, ok := c.hosts.File(c.host, f.Path)
	switch {
	case f.Absent && !ok:
		return module.Result{Status: module.OK}, nil
	case f.Absent:
		return module.Result{Status: module.Change, Action: module.Remove}, nil
	case !ok:
		return module.Result{Status: module.Change, Action: module.Create, Old: new(""), Validates: f.Validation != nil,
			Changes: append(c.missingParents(f.Path), "owner root, group root, mode 0644")}, nil
	case cur != string(f.Data):
		return module.Result{Status: module.Change, Action: module.Modify, Old: &cur, Validates: f.Validation != nil}, nil
	}
	return module.Result{Status: module.OK}, nil
}

func (c *Conn) checkAnswer(d *module.Debconf) module.Result {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	cur, ok := c.hosts.answers[c.host+" "+d.Question]
	switch {
	case !ok:
		return module.Result{Status: module.Change, Action: module.Create, Changes: []string{fmt.Sprintf("answer (none) → %q", d.Value)}}
	case cur != d.Value:
		return module.Result{Status: module.Change, Action: module.Modify, Changes: []string{fmt.Sprintf("answer %q → %q", cur, d.Value)}}
	}
	return module.Result{Status: module.OK}
}

// checkAccount creates only.
func (c *Conn) checkAccount(m map[string]bool, name string) module.Result {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	if m[c.host+" "+name] {
		return module.Result{Status: module.OK}
	}
	return module.Result{Status: module.Change, Action: module.Create}
}

// checkDir creates only.
func (c *Conn) checkDir(d *module.Dir) module.Result {
	c.hosts.mu.Lock()
	if d.Purge {
		c.hosts.DirKeep[c.host+" "+d.Path] = d.Keep
	}
	if res, ok := c.hosts.result(c.host + " " + d.Path); ok {
		c.hosts.mu.Unlock()
		return res
	}
	missing := c.hosts.noDirs[c.host][d.Path]
	c.hosts.mu.Unlock()
	if !missing {
		return module.Result{Status: module.OK}
	}
	group, mode := cmp.Or(string(d.Group), "root"), cmp.Or(d.Mode, "0755")
	return module.Result{Status: module.Change, Action: module.Create,
		Changes: append(c.missingParents(d.Path), "owner root, group "+group+", mode "+mode)}
}

// checkPkg plans the packages that SetPkgDeps makes the step's packages
// depend on, or depend on them. A removal also takes the packages that
// depend on them in turn, and counts the packages that earlier steps install.
// The first install with a state that is not fresh refreshes the index.
func (c *Conn) checkPkg(p *module.Pkg, st *module.State) module.Result {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	installed := c.hosts.pkgs[c.host]
	if p.Absent {
		var todo, others []string
		for _, n := range p.Name {
			if installed[n] {
				todo = append(todo, n)
			}
		}
		if len(todo) == 0 {
			return module.Result{Status: module.OK}
		}
		gone := func(d string) bool { return slices.Contains(todo, d) || slices.Contains(others, d) }
		for more := true; more; {
			more = false
			for n, deps := range c.hosts.pkgDeps {
				if (installed[n] || slices.Contains(p.Installed, n)) && !gone(n) && slices.ContainsFunc(deps, gone) {
					others = append(others, n)
					more = true
				}
			}
		}
		changes := []string{"remove " + strings.Join(todo, ", ")}
		if len(others) > 0 {
			slices.Sort(others)
			changes = append(changes, "also remove "+strings.Join(others, ", "))
		}
		return module.Result{Status: module.Change, Action: module.Remove, Changes: changes}
	}
	var missing, others []string
	for _, n := range p.Name {
		if !installed[n] {
			missing = append(missing, n)
			for _, d := range c.hosts.pkgDeps[n] {
				if !installed[d] && !slices.Contains(p.Name, d) && !slices.Contains(others, d) {
					others = append(others, d)
				}
			}
		}
	}
	if len(missing) == 0 {
		return module.Result{Status: module.OK}
	}
	var changes []string
	if !st.IndexFresh {
		changes = append(changes, "refresh the package index")
		st.IndexFresh = true
	}
	changes = append(changes, "install "+strings.Join(missing, ", "))
	if len(others) > 0 {
		changes = append(changes, "also install "+strings.Join(others, ", "))
	}
	return module.Result{Status: module.Change, Action: module.Create, Changes: changes}
}

// serviceAction is the action of a service step: only reloaded and
// restarted.
func serviceAction(s *module.Service) string {
	if s.Reloaded {
		return "reload"
	}
	return "restart"
}

// Apply starts a rollback timer that ends at once for a changed step with
// confirm_access, or a result with Guard.
func (c *Conn) Apply(ctx context.Context, name string, m module.Module, st *module.State, notify []string, then *protocol.Then, check *protocol.Check, guard protocol.Guard) (module.Result, error) {
	res, err := c.apply(ctx, name, m, st, notify, then, check)
	c.hosts.mu.Lock()
	c.hosts.Guards[c.host+" "+m.Main()] = guard
	c.hosts.mu.Unlock()
	if err == nil && res.Status == module.Change && (guard.Confirm || res.Guard) {
		c.hosts.mu.Lock()
		res.Timer = c.hosts.timer
		c.hosts.mu.Unlock()
	}
	return res, err
}

func (c *Conn) apply(ctx context.Context, name string, m module.Module, st *module.State, notify []string, then *protocol.Then, check *protocol.Check) (module.Result, error) {
	if c.hosts.OnApply != nil {
		c.hosts.OnApply(c.host, m.Main())
	}
	c.hosts.mu.Lock()
	c.hosts.Trace = append(c.hosts.Trace, "apply "+c.host+" "+m.Main())
	c.hosts.mu.Unlock()
	if ctx.Err() != nil {
		return module.Result{}, fmt.Errorf("fakehost: the call got an ended context: %w", ctx.Err())
	}
	fresh := st.IndexFresh
	res, err := c.Check(ctx, name, m, st)
	if a, ok := m.(*module.Assert); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		c.hosts.Log[c.host] = append(c.hosts.Log[c.host], "assert "+a.Command)
		failed := c.hosts.failCmd[c.host+" "+a.Command]
		if check != nil {
			c.hosts.checks[c.host] = slices.DeleteFunc(c.hosts.checks[c.host], func(k protocol.Check) bool { return k == *check })
			if failed {
				c.hosts.checks[c.host] = append(c.hosts.checks[c.host], *check)
			}
		}
		if failed {
			return module.Result{}, errors.New(a.Message)
		}
		return res, nil
	}
	if err != nil || res.Status == module.OK {
		return res, err
	}
	if u, ok := m.(*module.Unit); ok {
		m = u.File()
	}
	// A failed apply keeps no record of this call.
	if sv, ok := m.(*module.Service); ok && c.hosts.fails(c.hosts.failApply, c.host, sv.Name) {
		return module.Result{}, fmt.Errorf("systemctl: %s failed", sv.Name)
	}
	if f, ok := m.(*module.File); ok && c.hosts.fails(c.hosts.failApply, c.host, f.Path) {
		return module.Result{}, fmt.Errorf("write %s: read-only file system", f.Path)
	}
	c.hosts.mu.Lock()
	for _, n := range notify {
		if !slices.Contains(c.hosts.pending[c.host], n) {
			c.hosts.pending[c.host] = append(c.hosts.pending[c.host], n)
		}
	}
	if then != nil && !slices.ContainsFunc(c.hosts.thens[c.host], func(t protocol.Then) bool { return reflect.DeepEqual(t, *then) }) {
		c.hosts.thens[c.host] = append(c.hosts.thens[c.host], *then)
	}
	c.hosts.mu.Unlock()
	if cm, ok := m.(*module.Cmd); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		c.hosts.Log[c.host] = append(c.hosts.Log[c.host], "cmd "+cm.Command)
		if c.hosts.failCmd[c.host+" "+cm.Command] {
			return module.Result{}, fmt.Errorf("%s: exit status 1", cm.Command)
		}
		return res, nil
	}
	if sv, ok := m.(*module.Service); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		key := sv.Name + " " + serviceAction(sv)
		c.hosts.Log[c.host] = append(c.hosts.Log[c.host], key)
		return res, nil
	}
	if p, ok := m.(*module.Pkg); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		if !fresh {
			c.hosts.Refreshes[c.host]++
		}
		if c.hosts.pkgs[c.host] == nil {
			c.hosts.pkgs[c.host] = map[string]bool{}
		}
		if c.hosts.files[c.host] == nil {
			c.hosts.files[c.host] = map[string]string{}
		}
		for _, n := range p.Name {
			if p.Absent {
				delete(c.hosts.pkgs[c.host], n)
				continue
			}
			c.hosts.pkgs[c.host][n] = true
			for path, content := range c.hosts.pkgFiles[n] {
				c.hosts.files[c.host][path] = content
			}
		}
		return res, nil
	}
	if d, ok := m.(*module.Dir); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		c.makeDirs(d.Path)
		return res, nil
	}
	switch m := m.(type) {
	case *module.Reboot, *module.Hostname, *module.Timezone, *module.Certbot, *module.Firewall, *module.Download:
		return res, nil
	case *module.User:
		c.hosts.SetUser(c.host, m.Name)
		return res, nil
	case *module.Group:
		c.hosts.SetGroup(c.host, m.Name)
		return res, nil
	case *module.Debconf:
		c.hosts.SetAnswer(c.host, m.Question, m.Value)
		return res, nil
	}
	f := m.(*module.File)
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Applies++
	if f.Absent {
		delete(c.hosts.files[c.host], f.Path)
		return res, nil
	}
	if c.hosts.files[c.host] == nil {
		c.hosts.files[c.host] = map[string]string{}
	}
	c.hosts.files[c.host][f.Path] = string(f.Data)
	c.makeDirs(path.Dir(f.Path))
	return res, nil
}

func (c *Conn) log(entry string) {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Log[c.host] = append(c.hosts.Log[c.host], entry)
}

func (c *Conn) Access(ctx context.Context) error {
	c.log("access")
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	if c.hosts.noAccess[c.host] || c.hosts.noAccessOnce[c.host] {
		delete(c.hosts.noAccessOnce, c.host)
		return errors.New("ssh: connect to host " + c.host + " port 22: Connection timed out")
	}
	return nil
}

func (c *Conn) Confirm(ctx context.Context) error {
	c.log("confirm")
	return nil
}

func (c *Conn) Rollback(ctx context.Context) error {
	c.log("rollback")
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	return c.hosts.rollbackErr
}

// Reboot boots the kernel of SetBoot. The host still needs a reboot when that
// is not the newest one, or when packages ask for one.
func (c *Conn) Reboot(ctx context.Context, wait time.Duration) (protocol.Boot, error) {
	c.log("reboot " + wait.String())
	c.hosts.mu.Lock()
	b, ok := c.hosts.boots[c.host]
	if !ok {
		b = protocol.Boot{State: "running"}
	}
	if f, ok := c.hosts.facts[c.host]; ok {
		f.RebootRequired = b.Kernel != b.Newest || len(b.Packages) > 0
		c.hosts.facts[c.host] = f
	}
	c.hosts.mu.Unlock()
	return b, nil
}

func (c *Conn) Facts(ctx context.Context) (facts.Facts, error) {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.FactsReads[c.host]++
	if f, ok := c.hosts.facts[c.host]; ok {
		return f, nil
	}
	return facts.Facts{OS: facts.OS{ID: "debian", Version: "13", Codename: "trixie", Arch: "amd64"}}, nil
}

func (c *Conn) Pending(ctx context.Context) (protocol.Pending, error) {
	return protocol.Pending{Handlers: c.hosts.PendingOf(c.host), Then: c.hosts.ThenOf(c.host), Checks: c.hosts.ChecksOf(c.host)}, nil
}

func (c *Conn) Pend(ctx context.Context, check protocol.Check) error {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	if !slices.Contains(c.hosts.checks[c.host], check) {
		c.hosts.checks[c.host] = append(c.hosts.checks[c.host], check)
	}
	return nil
}

func (c *Conn) Passed(ctx context.Context, check protocol.Check) error {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.checks[c.host] = slices.DeleteFunc(c.hosts.checks[c.host], func(k protocol.Check) bool { return k == check })
	return nil
}

func (c *Conn) Handled(ctx context.Context, handler string) error {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.pending[c.host] = slices.DeleteFunc(c.hosts.pending[c.host], func(n string) bool { return n == handler })
	return nil
}

func (c *Conn) Command(ctx context.Context, command string, then protocol.Then) error {
	if ctx.Err() != nil {
		return fmt.Errorf("fakehost: the call got an ended context: %w", ctx.Err())
	}
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Log[c.host] = append(c.hosts.Log[c.host], "command "+command)
	if c.hosts.failCmd[c.host+" "+command] {
		return fmt.Errorf("%s: exit status 1", command)
	}
	c.hosts.thens[c.host] = slices.DeleteFunc(c.hosts.thens[c.host], then.Matches)
	return nil
}

func (c *Conn) DropThen(ctx context.Context, then protocol.Then) error {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.thens[c.host] = slices.DeleteFunc(c.hosts.thens[c.host], func(t protocol.Then) bool { return reflect.DeepEqual(t, then) })
	return nil
}

// Health records the gate in Trace. A command that FailCommand names fails;
// a gate that passes removes its record.
func (c *Conn) Health(ctx context.Context, h protocol.Health) error {
	if ctx.Err() != nil {
		return fmt.Errorf("fakehost: the call got an ended context: %w", ctx.Err())
	}
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Trace = append(c.hosts.Trace, fmt.Sprintf("health %s %s %s %s", c.host, h.Command, h.Stable, h.Timeout))
	if c.hosts.failCmd[c.host+" "+h.Command] {
		return fmt.Errorf("did not pass within %s: exit status 1", h.Timeout)
	}
	c.hosts.checks[c.host] = slices.DeleteFunc(c.hosts.checks[c.host], func(k protocol.Check) bool { return k == h.Check })
	return nil
}

// FailExec makes winch exec fail on a host; FailClose makes its sessions
// fail to close.
func (h *Hosts) FailExec(host string)  { h.failExec[host] = true }
func (h *Hosts) FailClose(host string) { h.failClose[host] = true }

func (c *Conn) Close() error {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Open--
	c.hosts.Trace = append(c.hosts.Trace, "close "+c.host)
	if c.hosts.failClose[c.host] {
		return errors.New("session: exit status 255")
	}
	return nil
}

func (h *Hosts) SetExec(host string, res module.ExecResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.execs[host] = res
}

// Exec records the command in Log and returns the result that SetExec set.
func (c *Conn) Exec(ctx context.Context, command string) (module.ExecResult, error) {
	if ctx.Err() != nil {
		return module.ExecResult{}, fmt.Errorf("fakehost: the call got an ended context: %w", ctx.Err())
	}
	if c.hosts.OnExec != nil {
		c.hosts.OnExec(c.host)
	}
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Log[c.host] = append(c.hosts.Log[c.host], "exec "+command)
	if c.hosts.failExec[c.host] {
		return module.ExecResult{}, errors.New("session: the helper ended")
	}
	return c.hosts.execs[c.host], nil
}
