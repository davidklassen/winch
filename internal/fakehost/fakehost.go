// Package fakehost is a test double for hosts: it keeps files in memory and
// checks and applies file steps against them.
package fakehost

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
)

type Hosts struct {
	mu        sync.Mutex
	files     map[string]map[string]string
	failCheck map[string]bool
	failApply map[string]bool
	Applies   int
	// Open is the number of open connections.
	Open int
}

func New() *Hosts {
	return &Hosts{files: map[string]map[string]string{}, failCheck: map[string]bool{}, failApply: map[string]bool{}}
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

func (c *Conn) Check(ctx context.Context, name string, m module.Module) (module.Result, error) {
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

func (c *Conn) Apply(ctx context.Context, name string, m module.Module) (module.Result, error) {
	res, err := c.Check(ctx, name, m)
	if err != nil || res.Status == module.OK {
		return res, err
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
