// Package fakehost is a test double for hosts: it keeps files, packages, and
// facts in memory and checks and applies file, dir, pkg, and service steps
// against them. It keeps pending handlers and then records, and runs
// commands as records.
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
	}
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

// SetFacts sets the facts of a host. A host without them is Debian 13.
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

func (h *Hosts) Connect(ctx context.Context, host project.Host) (*Conn, error) {
	if host.Address == "unreachable" {
		return nil, errors.New("ssh: connect to host unreachable: Connection refused")
	}
	h.mu.Lock()
	h.Open++
	h.mu.Unlock()
	return &Conn{hosts: h, host: host.Name}, nil
}

func (h *Hosts) fails(m map[string]bool, host, path string) bool {
	return m[host] || m[host+" "+path]
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
	if p, ok := m.(*module.Pkg); ok {
		return c.checkPkg(p, st), nil
	}
	if d, ok := m.(*module.Dir); ok {
		return c.checkDir(d), nil
	}
	if sv, ok := m.(*module.Service); ok {
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

// checkDir creates only.
func (c *Conn) checkDir(d *module.Dir) module.Result {
	c.hosts.mu.Lock()
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
	fresh := st.IndexFresh
	res, err := c.Check(ctx, name, m, st)
	if err != nil || res.Status == module.OK {
		return res, err
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
	if sv, ok := m.(*module.Service); ok {
		if c.hosts.fails(c.hosts.failApply, c.host, sv.Name) {
			return module.Result{}, fmt.Errorf("systemctl: %s failed", sv.Name)
		}
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
	f := m.(*module.File)
	if c.hosts.fails(c.hosts.failApply, c.host, f.Path) {
		return module.Result{}, fmt.Errorf("write %s: read-only file system", f.Path)
	}
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
	return facts.Facts{OS: facts.OS{ID: "debian", Version: "13", Codename: "trixie"}}, nil
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
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Log[c.host] = append(c.hosts.Log[c.host], "command "+command)
	if c.hosts.failCmd[c.host+" "+command] {
		return fmt.Errorf("%s: exit status 1", command)
	}
	c.hosts.thens[c.host] = slices.DeleteFunc(c.hosts.thens[c.host], func(t protocol.Then) bool { return t == then })
	return nil
}

func (c *Conn) Close() error {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Open--
	return nil
}
