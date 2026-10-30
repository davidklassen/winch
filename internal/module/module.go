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
	// Missing are the user and the dir of a cmd that runs, as "user <name>"
	// or "dir <path>", that do not exist on the host.
	Missing  []string `json:"missing,omitempty"`
	Deferred bool     `json:"deferred,omitempty"`
	// Validates is set on a change for which apply runs the validate command
	// of the step.
	Validates bool `json:"validates,omitempty"`
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
	// RemovedUsers are the users that earlier steps of the host remove.
	RemovedUsers []string `json:"removed_users,omitempty"`
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

// WithValidate is a module with a validate command: "" when it has none.
type WithValidate interface {
	Module
	ValidateCommand() string
}

// WithContent is a module that writes content. A check sends only the hash
// of the content.
type WithContent interface {
	WithText
	WithoutContent() Module
}

var modules = map[string]struct {
	new  func() Module
	text string
}{
	"assert":   {func() Module { return new(Assert) }, "Fail the host during apply when a command fails."},
	"certbot":  {func() Module { return new(Certbot) }, "Get a Let's Encrypt certificate with certbot."},
	"cmd":      {func() Module { return new(Cmd) }, "Run a command."},
	"debconf":  {func() Module { return new(Debconf) }, "Set an answer in the debconf database."},
	"dir":      {func() Module { return new(Dir) }, "Manage a directory."},
	"download": {func() Module { return new(Download) }, "Download a file or an archive and check its SHA-256."},
	"file":     {func() Module { return new(File) }, "Write a file, or set the owner, group, and mode of a file."},
	"firewall": {func() Module { return new(Firewall) }, "Filter the traffic that reaches the host."},
	"group":    {func() Module { return new(Group) }, "Manage a group."},
	"hostname": {func() Module { return new(Hostname) }, "Set the static host name."},
	"line":     {func() Module { return new(Line) }, "Keep one line in a file that another program owns."},
	"link":     {func() Module { return new(Link) }, "Manage a symbolic link."},
	"pkg":      {func() Module { return new(Pkg) }, "Install or remove packages with apt."},
	"reboot":   {func() Module { return new(Reboot) }, "Reboot the host and wait until it answers again."},
	"repo":     {func() Module { return new(Repo) }, "Add an apt source and its key."},
	"service":  {func() Module { return new(Service) }, "Start, stop, enable, or disable a systemd unit."},
	"timezone": {func() Module { return new(Timezone) }, "Set the time zone."},
	"unit":     {func() Module { return new(Unit) }, "Write a systemd unit file."},
	"upgrade":  {func() Module { return new(Upgrade) }, "Install the pending package upgrades."},
	"user":     {func() Module { return new(User) }, "Manage a user account."},
}

// New returns empty arguments for the module name.
func New(name string) (Module, bool) {
	m, ok := modules[name]
	if !ok {
		return nil, false
	}
	return m.new(), true
}

func Names() []string {
	return slices.Sorted(maps.Keys(modules))
}
