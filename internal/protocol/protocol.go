// Package protocol defines the messages between winch and the helper: one
// JSON object per line, each response with the ID of its request.
package protocol

import (
	"crypto/sha256"
	"encoding/hex"
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
	// Project names the files of the pending records.
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
	// React are the records of the later steps that react to a path of the
	// step, which the helper adds before an apply changes something.
	React []React `json:"react,omitempty"`
	Guard Guard   `json:"guard,omitzero"`
	// Masked is the masked new content of a step whose content reads a
	// secret. A step that writes content without it drops the record.
	Masked *string `json:"masked,omitempty"`
}

// Guard tells the helper how to guard an apply against a lockout. The helper
// keeps the old state of what a step changes in the stores of Guarded and
// SSHD, and in Store when the step is guarded itself.
type Guard struct {
	// Store is the store of the step, as React.Store names it.
	Store string `json:"store,omitempty"`
	// Guarded are the records of the later steps with confirm_access that
	// react to a path of the step. The step keeps the old state in the store
	// of each, which the timer of that step puts back. When the session ends
	// while one is pending, the helper puts back its store and drops its
	// record.
	Guarded []React `json:"guarded,omitempty"`
	// SSHD are the stores of the later steps of the host with
	// confirm_access that restart or reload sshd. A step that changes sshd's
	// config keeps its old state in each, so the rollback of such a step puts
	// it back. When the session ends before such a step ran, the helper puts
	// back the paths of the step.
	SSHD []string `json:"sshd,omitempty"`
	// LoadsSSHD is set on a step with confirm_access that loads sshd. Its
	// rollback timer tests the sshd files of its store.
	LoadsSSHD bool `json:"loads_sshd,omitempty"`
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

// React is a record of a pending step with on_change: the scope of the step,
// its module, and the SHA-256 of its main arguments, one for each element of
// a loop. The record of a then has Then, and the module and the main
// arguments of its step.
type React struct {
	Recipe   string   `json:"recipe,omitempty"`
	Pipeline string   `json:"pipeline,omitempty"`
	Stage    string   `json:"stage,omitempty"`
	Module   string   `json:"module,omitempty"`
	Mains    []string `json:"mains,omitempty"`
	Then     bool     `json:"then,omitempty"`
}

// Matches reports whether o is a record of the same step as r: the same scope,
// module, and kind, and a main argument in common.
func (r React) Matches(o React) bool {
	in := func(m string) bool { return slices.Contains(o.Mains, m) }
	return r.Recipe == o.Recipe && r.Pipeline == o.Pipeline && r.Stage == o.Stage && r.Module == o.Module && r.Then == o.Then &&
		slices.ContainsFunc(r.Mains, in)
}

// Line is the record as a line of the record file.
func (r React) Line() string {
	// The record is plain data; it always encodes.
	b, _ := json.Marshal(r)
	return string(b)
}

// Store names the rollback store of the step of the record.
func (r React) Store() string {
	sum := sha256.Sum256([]byte(r.Line()))
	return "step-" + hex.EncodeToString(sum[:8])
}

// Command is the params of command, which runs the command of a then and
// then removes the records that match React.
type Command struct {
	Command string `json:"command"`
	React   React  `json:"react"`
}

// Exec is the params of exec, which runs a command of winch exec. Its result
// is a module.ExecResult. A zero Timeout is the limit of every host command.
type Exec struct {
	Command string        `json:"command"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// Check is a record of a pending health gate: its pipeline and stage. A record
// with a recipe, a handler, or a step is of an assert, a module that winch no
// longer has.
type Check struct {
	Recipe   string `json:"recipe,omitempty"`
	Pipeline string `json:"pipeline,omitempty"`
	Stage    string `json:"stage,omitempty"`
	Handler  string `json:"handler,omitempty"`
	Step     int    `json:"step,omitempty"`
}

// Pending is the result of pending: the records of the project.
type Pending struct {
	React  []React `json:"react"`
	Checks []Check `json:"checks,omitempty"`
	// Old are the record files of the project that an older winch wrote and
	// that winch no longer reads.
	Old []string `json:"old,omitempty"`
	// Rollback is the plan of the rollback of an earlier run whose timer
	// process is gone: the files that it puts back and what it runs.
	Rollback []string `json:"rollback,omitempty"`
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
