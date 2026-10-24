// Package fakehost is a test double for hosts: it keeps files and packages in
// memory and checks and applies file and pkg steps against them.
package fakehost

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
)

type Hosts struct {
	mu        sync.Mutex
	files     map[string]map[string]string
	pkgs      map[string]map[string]bool
	failCheck map[string]bool
	failApply map[string]bool
	Applies   int
	Refreshes map[string]int
	// Open is the number of open connections.
	Open int
}

func New() *Hosts {
	return &Hosts{
		files:     map[string]map[string]string{},
		pkgs:      map[string]map[string]bool{},
		failCheck: map[string]bool{},
		failApply: map[string]bool{},
		Refreshes: map[string]int{},
	}
}

func (h *Hosts) SetFile(host, path, content string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.files[host] == nil {
		h.files[host] = map[string]string{}
	}
	h.files[host][path] = content
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
	return func(ctx context.Context, host project.Host) (run.Conn, error) {
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
			Changes: []string{"owner root, group root, mode 0644"}}, nil
	case cur != *f.Content:
		return module.Result{Status: module.Change, Action: module.Modify, Old: &cur}, nil
	}
	return module.Result{Status: module.OK}, nil
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

func (c *Conn) Apply(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error) {
	fresh := st.IndexFresh
	res, err := c.Check(ctx, name, m, st)
	if err != nil || res.Status == module.OK {
		return res, err
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
		for _, n := range p.Name {
			c.hosts.pkgs[c.host][n] = true
		}
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
	c.hosts.files[c.host][f.Path] = *f.Content
	return res, nil
}

func (c *Conn) Close() error {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	c.hosts.Open--
	return nil
}
