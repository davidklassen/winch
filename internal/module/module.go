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

// Tool is a program or a file of a package, such as nft of nftables.
type Tool struct {
	Name    string `json:"name"`
	Package string `json:"package"`
}

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
	// Starts is set on a service step that starts its unit.
	Starts bool `json:"starts,omitempty"`
	// MissingUnitFiles are the paths of a missing service unit file. A
	// selected removal of any of these paths suppresses the plan's note.
	MissingUnitFiles []string `json:"missing_unit_files,omitempty"`
	// Missing are the user and the dir of a cmd that runs, as "user <name>"
	// or "dir <path>", that do not exist on the host.
	Missing []string `json:"missing,omitempty"`
	// MissingTools are the programs and files that the step needs and the
	// host lacks.
	MissingTools []Tool `json:"missing_tools,omitempty"`
	Deferred     bool   `json:"deferred,omitempty"`
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
	// Refreshed is true after an upgrade step of the run, also in the plan,
	// refreshed the package index, and no later step changed a source.
	Refreshed bool `json:"refreshed,omitempty"`
	// RemovedUsers are the users that earlier steps of the host remove.
	RemovedUsers []string `json:"removed_users,omitempty"`
	// MovedUsers are the users that earlier steps of the host move to
	// another primary group.
	MovedUsers []string `json:"moved_users,omitempty"`
	// LoginUID is the UID of the session's login user. The helper sets it.
	LoginUID uint32 `json:"-"`
	// SSHConnection is the SSH_CONNECTION of the session's login. The helper
	// sets it.
	SSHConnection string `json:"-"`
}

// Module is the decoded arguments of one step. Main returns the main
// argument for the plan. Check updates the state. Apply runs on the value
// that Check returned a change for, and does what Check decided. Both tell
// say the lines for the person while they wait for the host.
type Module interface {
	Main() string
	Check(ctx context.Context, st *State, say Say) (Result, error)
	Apply(ctx context.Context, say Say) error
}

// Say takes the lines for the person while a step works on the host.
type Say interface {
	// Note tells a fact about the host that needs no fix.
	Note(text string)
	// Warn tells a problem on the host to fix.
	Warn(text string)
	// Progress tells what the host does now.
	Progress(text string)
}

// Silent is a Say that drops the lines.
type Silent struct{}

func (Silent) Note(string) {}

func (Silent) Warn(string) {}

func (Silent) Progress(string) {}

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
	new        func() Module
	text, body string
}{
	"assert":   {func() Module { return new(Assert) }, "stop a host when a check command fails", "The plan marks the step with * and runs nothing. Apply runs the command. A failed assert stays pending on the host, and the next apply runs it again, also when nothing else changes."},
	"certbot":  {func() Module { return new(Certbot) }, "get a Let's Encrypt certificate", "The step runs certbot certonly. Renewal stays with certbot's own timer. Install the package certbot in an earlier pkg step. The nginx and apache authenticators also need python3-certbot-nginx or python3-certbot-apache."},
	"cmd":      {func() Module { return new(Cmd) }, "run a command", "Without creates or unless, the check result is unknown, and apply runs the command each time. A secret in the command does not show in the process list of the host. A program that the command starts with the secret as an argument, such as psql -c, does show it."},
	"debconf":  {func() Module { return new(Debconf) }, "set a debconf answer", "Only the scripts of a package read its answers. Put the step before the pkg step that installs the package, also when the package comes in as a dependency."},
	"dir":      {func() Module { return new(Dir) }, "manage a directory", "The step creates missing parent directories, owned by root with mode 0755. winch checks owner, group, and mode on every run."},
	"download": {func() Module { return new(Download) }, "download a file or an archive", "The host fetches the file and checks its sha256. A download with another checksum fails and keeps the old file. A step has path or unpack."},
	"file":     {func() Module { return new(File) }, "manage a file", "At most one of content, template, source, copy_from, and stock sets the content. A step without any of them manages only the owner, group, and mode that it gives, of a file that exists. The step creates missing parent directories, owned by root with mode 0755."},
	"firewall": {func() Module { return new(Firewall) }, "filter incoming traffic", "The step owns the nftables table inet winch and changes no other table. The rules of Docker, fail2ban, or /etc/nftables.conf stay. Its input chain filters traffic to the host. A host has at most one firewall step in a run.\n\nThe step needs nft: install the package nftables in an earlier pkg step.\n\nEvery change gets the access check and the rollback of confirm_access. When the access check fails after the new rules load, the old rules come back."},
	"group":    {func() Module { return new(Group) }, "manage a group", ""},
	"hostname": {func() Module { return new(Hostname) }, "set the host name", ""},
	"line":     {func() Module { return new(Line) }, "manage one line in a file", ""},
	"link":     {func() Module { return new(Link) }, "manage a symbolic link", "The step creates missing parent directories, owned by root with mode 0755."},
	"pkg":      {func() Module { return new(Pkg) }, "install or remove packages", "Before the first install of a run on a host, apply refreshes the package index. After a repo step changed something, the next pkg step refreshes it again."},
	"reboot":   {func() Module { return new(Reboot) }, "reboot the host", ""},
	"repo":     {func() Module { return new(Repo) }, "manage an apt source", ""},
	"service":  {func() Module { return new(Service) }, "control a systemd unit", "With running: false, a missing unit file is ok, with the note <unit> does not exist. A service step with confirm_access: true runs the access check after the step, and rolls back when it fails. Run winch doc step.confirm_access. In a handler, restarted and reloaded check as ok when a service step of the run started the unit after the handler's last notify, no earlier step of the handler changed anything, and the step has no confirm_access."},
	"timezone": {func() Module { return new(Timezone) }, "set the time zone", ""},
	"unit":     {func() Module { return new(Unit) }, "manage a systemd unit file", "A change of the file, also of its owner or mode, runs systemctl daemon-reload. daemon-reload does not restart a running unit. A handler with restarted: true does."},
	"upgrade":  {func() Module { return new(Upgrade) }, "upgrade the installed packages", "The step refreshes the package index, also during the plan, and checks for pending upgrades."},
	"user":     {func() Module { return new(User) }, "manage a user account", "A step that creates a user also creates its home directory. Without group, it also creates a group with the name of the user. The defaults and system count only when the step creates the user."},
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
