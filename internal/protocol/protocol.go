// Package protocol defines the messages between winch and the helper: one
// JSON object per line, each response with the ID of its request.
package protocol

import (
	"encoding/json"
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
	// Note is a line for the person while the request waits on the host. A
	// response with a note is not the answer: more responses follow.
	Note string `json:"note,omitempty"`
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
}

// Then is a record of a then: the place of its step, and its module and main
// argument. Step counts from 1 in the steps of the recipe, of its handler, or
// of the stage of the pipeline for a step of a stage. Main is that of the last
// element of a loop.
type Then struct {
	Recipe   string `json:"recipe,omitempty"`
	Pipeline string `json:"pipeline,omitempty"`
	Stage    string `json:"stage,omitempty"`
	Handler  string `json:"handler,omitempty"`
	Step     int    `json:"step"`
	Module   string `json:"module,omitempty"`
	Main     string `json:"main,omitempty"`
}

// Command is the params of command, which runs the command and then removes
// the record of its then.
type Command struct {
	Command string `json:"command"`
	Then    Then   `json:"then"`
}

// Exec is the params of exec, which runs a command of winch exec. Its result
// is a module.ExecResult.
type Exec struct {
	Command string `json:"command"`
}

// Pending is the result of pending: the records of the project.
type Pending struct {
	Handlers []string `json:"handlers"`
	Then     []Then   `json:"then"`
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
type Health struct {
	Command string        `json:"command"`
	Stable  time.Duration `json:"stable"`
	Timeout time.Duration `json:"timeout"`
}
