// Package fakehost is a test double for hosts: it keeps files, packages,
// answers, and facts in memory and checks and applies file, dir, pkg,
// service, user, group, and debconf steps against them. It keeps pending
// handlers and then records, and runs commands, cmd steps, and asserts as
// records.
package fakehost

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"

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
	failCheck  map[string]bool
	failApply  map[string]bool
	Applies    int
	Refreshes  map[string]int
	FactsReads map[string]int
	facts      map[string]facts.Facts
	pending    map[string][]string
	thens      map[string][]protocol.Then
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
}

func New() *Hosts {
	return &Hosts{
		files:      map[string]map[string]string{},
		noDirs:     map[string]map[string]bool{},
		pkgs:       map[string]map[string]bool{},
		pkgFiles:   map[string]map[string]string{},
		failCheck:  map[string]bool{},
		failApply:  map[string]bool{},
		Refreshes:  map[string]int{},
		FactsReads: map[string]int{},
		facts:      map[string]facts.Facts{},
		pending:    map[string][]string{},
		thens:      map[string][]protocol.Then{},
		failCmd:    map[string]bool{},
		Log:        map[string][]string{},
		results:    map[string]module.Result{},
		execs:      map[string]module.ExecResult{},
		failExec:   map[string]bool{},
		failClose:  map[string]bool{},
		Connects:   map[string]int{},
		Users:      map[string]string{},
		down:       map[string]bool{},
		users:      map[string]bool{},
		groups:     map[string]bool{},
		answers:    map[string]string{},
		DirKeep:    map[string][]string{},
	}
}

// SetAnswer sets the debconf answer of a question on a host.
func (h *Hosts) SetAnswer(host, question, value string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answers[host+" "+question] = value
}

// SetResult makes the check of the dir step for path, of the line step for its
// match, or of the service step
// for the unit name, on a host return res.
func (h *Hosts) SetResult(host, name string, res module.Result) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.results[host+" "+name] = res
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
	return &Conn{hosts: h, host: host.Name}, nil
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
}

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
		if m.Creates == "" {
			return module.Result{Status: module.Unknown}, nil
		}
		if _, ok := c.hosts.File(c.host, m.Creates); ok {
			return module.Result{Status: module.OK}, nil
		}
		return module.Result{Status: module.Change, Action: module.Create}, nil
	case *module.Assert:
		return module.Result{Status: module.OK, Deferred: true}, nil
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
		return module.Result{Status: module.Change, Action: module.Create, Changes: []string{"download " + d.URL}}, nil
	}
	if _, ok := m.(*module.Link); ok {
		return module.Result{Status: module.OK}, nil
	}
	if l, ok := m.(*module.Line); ok {
		c.hosts.mu.Lock()
		defer c.hosts.mu.Unlock()
		if res, ok := c.hosts.results[c.host+" "+l.Match]; ok {
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
		res, ok := c.hosts.results[c.host+" "+sv.Name]
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
	cur, ok := c.hosts.File(c.host, f.Path)
	switch {
	case f.Absent && !ok:
		return module.Result{Status: module.OK}, nil
	case f.Absent:
		return module.Result{Status: module.Change, Action: module.Remove}, nil
	case !ok:
		return module.Result{Status: module.Change, Action: module.Create, Old: new(""),
			Changes: append(c.missingParents(f.Path), "owner root, group root, mode 0644")}, nil
	case cur != string(f.Data):
		return module.Result{Status: module.Change, Action: module.Modify, Old: &cur}, nil
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
	if res, ok := c.hosts.results[c.host+" "+d.Path]; ok {
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

// checkPkg installs only. The first install with a state that is not fresh
// refreshes the index.
func (c *Conn) checkPkg(p *module.Pkg, st *module.State) module.Result {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	var missing []string
	for _, n := range p.Name {
		if !c.hosts.pkgs[c.host][n] {
			missing = append(missing, n)
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

func (c *Conn) Apply(ctx context.Context, name string, m module.Module, st *module.State, notify []string, then *protocol.Then) (module.Result, error) {
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
		if c.hosts.failCmd[c.host+" "+a.Command] {
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
	if then != nil && !slices.Contains(c.hosts.thens[c.host], *then) {
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
	return protocol.Pending{Handlers: c.hosts.PendingOf(c.host), Then: c.hosts.ThenOf(c.host)}, nil
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
	c.hosts.thens[c.host] = slices.DeleteFunc(c.hosts.thens[c.host], func(t protocol.Then) bool { return t == then })
	return nil
}

// Health records the gate in Trace. A command that FailCommand names fails.
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
