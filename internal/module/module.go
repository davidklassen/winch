// Package module holds the modules. The controller decodes and validates
// their arguments; the helper checks and applies them on the host.
package module

import (
	"context"
	"errors"
	"maps"
	"slices"
)

// ErrNeedContent is the error of an apply that must write content it did not
// get. The controller sends the step again with the content.
var ErrNeedContent = errors.New("apply needs the content")

type Status string

const (
	OK     Status = "ok"
	Change Status = "change"
)

type Action string

const (
	Create Action = "create"
	Modify Action = "change"
	Remove Action = "remove"
)

// Result is the outcome of a check. Changes are lines for the plan. Old is
// the current text content when the content changes, for the diff.
type Result struct {
	Status  Status   `json:"status"`
	Action  Action   `json:"action,omitempty"`
	Changes []string `json:"changes,omitempty"`
	Old     *string  `json:"old,omitempty"`
}

// State is what earlier steps of the run did on the host. The controller
// keeps it per host and sends it with each step.
type State struct {
	// IndexFresh is true after an install of the run refreshed the package
	// index.
	IndexFresh bool `json:"index_fresh,omitempty"`
}

// Module is the decoded arguments of one step. Main returns the main
// argument for the plan. Check updates the state. Apply runs on the value
// that Check returned a change for, and does what Check decided.
type Module interface {
	Main() string
	Check(ctx context.Context, st *State) (Result, error)
	Apply(ctx context.Context) error
}

// WithContent is a module that writes content. A check sends only the hash
// of the content, and the plan shows a diff to Text.
type WithContent interface {
	Module
	WithoutContent() Module
	Text() *string
}

var modules = map[string]func() Module{
	"dir":     func() Module { return new(Dir) },
	"file":    func() Module { return new(File) },
	"link":    func() Module { return new(Link) },
	"pkg":     func() Module { return new(Pkg) },
	"service": func() Module { return new(Service) },
}

// New returns empty arguments for the module name.
func New(name string) (Module, bool) {
	f, ok := modules[name]
	if !ok {
		return nil, false
	}
	return f(), true
}

func Names() []string {
	return slices.Sorted(maps.Keys(modules))
}
