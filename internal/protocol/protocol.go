// Package protocol defines the messages between winch and the helper: one
// JSON object per line, each response with the ID of its request.
package protocol

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/davidklassen/winch/internal/module"
)

type Request struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	// NeedContent marks an apply that must write content it did not get.
	NeedContent bool `json:"need_content,omitempty"`
	// Note is a fact about the host that needs no fix, Warning a problem on
	// the host to fix, and Progress tells what the host does now. A response
	// with one of them is not the answer: more responses follow.
	Note     string `json:"note,omitempty"`
	Warning  string `json:"warning,omitempty"`
	Progress string `json:"progress,omitempty"`
}

// Hello is the first request of a session. The helper writes it into the
// lock file, so a second session can name the run that holds the lock.
type Hello struct {
	// Project names the file of the pending handlers.
	Project string    `json:"project"`
	Run     string    `json:"run"`
	User    string    `json:"user"`
	Machine string    `json:"machine"`
	Started time.Time `json:"started"`
	// Resume is set on the connect after a reboot: the same run goes on.
	Resume bool `json:"resume,omitempty"`
}

// Welcome is the answer to hello.
type Welcome struct {
	// Login is the name of the session's login user. It is empty when the
	// helper cannot read the name, as for an LDAP account.
	Login    string `json:"login"`
	LoginUID uint32 `json:"login_uid"`
}

// Destination is where a session logs in: the login user that the host
// reports, and the host name and port that ssh resolves for the host.
type Destination struct {
	User     string `json:"user"`
	UID      uint32 `json:"uid"`
	HostName string `json:"hostname"`
	Port     string `json:"port"`
	// Jump is the ProxyJump or ProxyCommand that ssh resolves, or empty.
	Jump string `json:"jump,omitempty"`
}

// Step is the params of check and apply.
type Step struct {
	Module string          `json:"module"`
	Args   json.RawMessage `json:"args"`
	State  module.State    `json:"state"`
	// Notify are the handlers, as <recipe>.<handler>, that the helper records
	// before an apply changes something.
	Notify []string `json:"notify,omitempty"`
	// Then is the then of the step, which the helper records before an
	// apply changes something.
	Then *Then `json:"then,omitempty"`
	// Check is the record of an assert step. The helper adds it when the
	// command fails, and removes it when the command exits 0.
	Check *Check `json:"check,omitempty"`
	Guard Guard  `json:"guard,omitzero"`
}

// Guard tells the helper how to guard an apply against a lockout. The helper
// keeps the old state of what a step changes in the rollback store of its
// recipe, or of its stage for a module step of a stage, and in the stores of
// Handlers.
type Guard struct {
	Recipe   string `json:"recipe,omitempty"`
	Pipeline string `json:"pipeline,omitempty"`
	Stage    string `json:"stage,omitempty"`
	// Save keeps the old state in the store: the recipe or the stage has a
	// step with confirm_access.
	Save bool `json:"save,omitempty"`
	// Handlers are the records of the handlers with confirm_access that the
	// step notifies. The step keeps the old state in the store of each, which
	// the timer of that handler puts back. When the session ends while one is
	// pending, the helper puts back its store and drops its record.
	Handlers []string `json:"handlers,omitempty"`
	// Confirm is the confirm_access of the step: a change starts the
	// rollback timer, which puts back the whole store.
	Confirm bool `json:"confirm,omitempty"`
}

// Booted is the params of booted: the boot ID before the reboot, and the
// time to wait for the system to start.
type Booted struct {
	Old  string        `json:"old"`
	Wait time.Duration `json:"wait"`
}

// Boot is the result of booted. Same is set when the host has not rebooted
// yet. RebootError is set instead when the reboot command failed, so the host
// does not reboot. State is that of
// systemctl is-system-running; Failed are the failed units of a degraded
// system. Kernel is the running kernel, and Newest the
// newest kernel in /boot of its flavor. Packages are those that
// /run/reboot-required.pkgs lists.
type Boot struct {
	Same        bool     `json:"same,omitempty"`
	RebootError string   `json:"reboot_error,omitempty"`
	State       string   `json:"state,omitempty"`
	Failed      []string `json:"failed,omitempty"`
	Kernel      string   `json:"kernel,omitempty"`
	Newest      string   `json:"newest,omitempty"`
	Packages    []string `json:"packages,omitempty"`
}

// Then is a record of a then: the scope of its step, and its module and main
// arguments, one for each element of a loop.
type Then struct {
	Recipe   string   `json:"recipe,omitempty"`
	Pipeline string   `json:"pipeline,omitempty"`
	Stage    string   `json:"stage,omitempty"`
	Handler  string   `json:"handler,omitempty"`
	Module   string   `json:"module,omitempty"`
	Mains    []string `json:"mains,omitempty"`
	// Legacy are the main arguments that winch 0.1.0 recorded for a step
	// whose main argument reads a secret: the plain argument, or the SHA-256
	// of the plain command. They match a record of that version, and a host
	// never gets them in a new record.
	Legacy []string `json:"legacy,omitempty"`
}

// Matches reports whether o is a record of the same step as t: the same scope
// and module, and a main argument in common.
func (t Then) Matches(o Then) bool {
	in := func(m string) bool { return slices.Contains(o.Mains, m) }
	return t.Recipe == o.Recipe && t.Pipeline == o.Pipeline && t.Stage == o.Stage && t.Handler == o.Handler && t.Module == o.Module &&
		(slices.ContainsFunc(t.Mains, in) || slices.ContainsFunc(t.Legacy, in))
}

// Command is the params of command, which runs the command and then removes
// the records that match its then.
type Command struct {
	Command string `json:"command"`
	Then    Then   `json:"then"`
}

// Exec is the params of exec, which runs a command of winch exec. Its result
// is a module.ExecResult.
type Exec struct {
	Command string `json:"command"`
}

// Check is a record of a pending health gate or assert: the place of its
// stage or step. Step counts from 1 in the steps of the recipe, of its
// handler, or of the stage of the pipeline for a step of a stage. It is 0 for
// the gate of a stage.
type Check struct {
	Recipe   string `json:"recipe,omitempty"`
	Pipeline string `json:"pipeline,omitempty"`
	Stage    string `json:"stage,omitempty"`
	Handler  string `json:"handler,omitempty"`
	Step     int    `json:"step,omitempty"`
}

// Pending is the result of pending: the records of the project.
type Pending struct {
	Handlers []string `json:"handlers"`
	Then     []Then   `json:"then"`
	Checks   []Check  `json:"checks,omitempty"`
}

// Handled is the params of handled: the handler whose record the helper
// removes.
type Handled struct {
	Name string `json:"name"`
}

// StepResult is the result of check and apply, with the new state.
type StepResult struct {
	module.Result
	State module.State `json:"state"`
}

// Health is the params of health: run Command until it exits 0, then keep
// running it for Stable. The gate fails when it does not pass within Timeout.
// The helper removes the record Check when the gate passes.
type Health struct {
	Command string        `json:"command"`
	Stable  time.Duration `json:"stable"`
	Timeout time.Duration `json:"timeout"`
	Check   Check         `json:"check"`
}
