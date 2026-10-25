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
}

// Handled is the params of handled: the handler whose record the helper
// removes.
type Handled struct {
	Name string `json:"name"`
}

// Command is the params of command.
type Command struct {
	Command string `json:"command"`
}

// StepResult is the result of check and apply, with the new state.
type StepResult struct {
	module.Result
	State module.State `json:"state"`
}
