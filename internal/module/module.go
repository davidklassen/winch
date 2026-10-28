// Package module holds the modules. The controller decodes and validates
// their arguments; the helper checks and applies them on the host.
package module

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"
)

// ErrNeedContent is the error of an apply that must write content it did not
// get. The controller sends the step again with the content.
var ErrNeedContent = errors.New("apply needs the content")

type Status string

const (
	OK     Status = "ok"
	Change Status = "change"
	// Unknown is the status of a step that cannot know whether it changes
	// something: a cmd without creates.
	Unknown Status = "unknown"
)

type Action string

const (
	Create Action = "create"
	Modify Action = "change"
	Remove Action = "remove"
)

// Result is the outcome of a check. Changes are lines for the plan. Old is
// the current text content when the content changes, for the diff. OldReason
// says why Old is nil when the content changes: the current content is not
// text, or is larger than 1 MiB. Link is
// the target of the symbolic link at the path that the step follows.
// StartedBy are the active or enabled units that start the unit that a
// service step stops or disables; the plan needs a step for each. Deferred
// marks a step that runs during apply without a change, such as an assert.
type Result struct {
	Status    Status   `json:"status"`
	Action    Action   `json:"action,omitempty"`
	Changes   []string `json:"changes,omitempty"`
	Old       *string  `json:"old,omitempty"`
	OldReason string   `json:"old_reason,omitempty"`
	Link      string   `json:"link,omitempty"`
	StartedBy []string `json:"started_by,omitempty"`
	// MissingUnitFiles are the paths of a missing service unit file. A
	// selected removal of any of these paths suppresses the plan's note.
	MissingUnitFiles []string `json:"missing_unit_files,omitempty"`
	Deferred         bool     `json:"deferred,omitempty"`
	// Quiet marks a change that only writes a record of the helper, such as
	// the record of a download: it notifies no handler and runs no then.
	Quiet bool `json:"quiet,omitempty"`
	// Guard is set on a change that can lock out the login user: apply
	// checks the access after it, as for confirm_access.
	Guard bool `json:"guard,omitempty"`
	// Timer is set by an apply that started the rollback timer: the time
	// that the timer has left.
	Timer time.Duration `json:"timer,omitempty"`
	// SourceSHA256 is the hash of the content that copy_from or stock
	// reads on the host, so the plan hash covers it.
	SourceSHA256 string `json:"source_sha256,omitempty"`
}

// State is what earlier steps of the run did on the host. The controller
// keeps it per host and sends it with each step.
type State struct {
	// IndexFresh is true after an install of the run refreshed the package
	// index.
	IndexFresh bool `json:"index_fresh,omitempty"`
	// LoginUID is the UID of the session's login user. The helper sets it.
	LoginUID uint32 `json:"-"`
	// SSHConnection is the SSH_CONNECTION of the session's login. The helper
	// sets it.
	SSHConnection string `json:"-"`
}

// Module is the decoded arguments of one step. Main returns the main
// argument for the plan. Check updates the state. Apply runs on the value
// that Check returned a change for, and does what Check decided. Both call
// note with a line for the person while they wait for the host.
type Module interface {
	Main() string
	Check(ctx context.Context, st *State, note func(string)) (Result, error)
	Apply(ctx context.Context, note func(string)) error
}

// WithText is a module whose plan shows a diff from the old text of a check
// result. Text returns the new text and the reason the plan shows no diff to
// it, or "" when the plan shows one.
type WithText interface {
	Module
	Text() ([]byte, string)
}

// WithContent is a module that writes content. A check sends only the hash
// of the content.
type WithContent interface {
	WithText
	WithoutContent() Module
}

var modules = map[string]func() Module{
	"assert":   func() Module { return new(Assert) },
	"certbot":  func() Module { return new(Certbot) },
	"cmd":      func() Module { return new(Cmd) },
	"debconf":  func() Module { return new(Debconf) },
	"dir":      func() Module { return new(Dir) },
	"download": func() Module { return new(Download) },
	"file":     func() Module { return new(File) },
	"group":    func() Module { return new(Group) },
	"hostname": func() Module { return new(Hostname) },
	"line":     func() Module { return new(Line) },
	"link":     func() Module { return new(Link) },
	"pkg":      func() Module { return new(Pkg) },
	"reboot":   func() Module { return new(Reboot) },
	"repo":     func() Module { return new(Repo) },
	"service":  func() Module { return new(Service) },
	"timezone": func() Module { return new(Timezone) },
	"unit":     func() Module { return new(Unit) },
	"upgrade":  func() Module { return new(Upgrade) },
	"user":     func() Module { return new(User) },
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
