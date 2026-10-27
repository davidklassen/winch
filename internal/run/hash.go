package run

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

type hashRun struct {
	Project string   `json:"project"`
	Stages  []string `json:"stages"`
}

type hashHost struct {
	Host    string            `json:"host"`
	Address string            `json:"address"`
	User    string            `json:"user,omitempty"`
	Failed  bool              `json:"failed,omitempty"`
	Pending *protocol.Pending `json:"pending,omitempty"`
}

type hashStage struct {
	Stage       string      `json:"stage"`
	Parallelism int         `json:"parallelism,omitempty"`
	Health      *hashHealth `json:"health,omitempty"`
}

type hashHealth struct {
	Command string `json:"command"`
	Stable  int    `json:"stable"`
	Timeout int    `json:"timeout"`
}

type hashStep struct {
	Address string `json:"address"`
	Module  string `json:"module,omitempty"`
	// Args, Then, and Result are JSON, or the SHA-256 of their JSON for a
	// step that reads a secret.
	Args        any      `json:"args,omitempty"`
	Then        any      `json:"then,omitempty"`
	Notify      []string `json:"notify,omitempty"`
	Result      any      `json:"result,omitempty"`
	PendingThen bool     `json:"pending_then,omitempty"`
	// Runs and Steps are set on a handler slot.
	Runs  bool       `json:"runs,omitempty"`
	Steps []hashStep `json:"steps,omitempty"`
}

// hashResult is a check result with the old content as its SHA-256.
type hashResult struct {
	module.Result
	Old string `json:"old,omitempty"`
}

// HashInput returns the text that the plan hash covers: a JSON line with the
// project and the stage order, then JSON lines per host, in inventory order.
func (p *Plan) HashInput() []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	write := func(v any) {
		// The values are plain data; they always encode.
		_ = enc.Encode(v)
	}
	hr := hashRun{Project: p.Project}
	for _, sp := range p.Stages {
		hr.Stages = append(hr.Stages, sp.Stage.Name)
	}
	write(hr)
	for _, h := range p.Hosts {
		hh := hashHost{Host: h.Name, Address: h.Address, User: h.User, Failed: p.Failed[h.Name] != nil}
		if pending, ok := p.Pending[h.Name]; ok {
			hh.Pending = &pending
		}
		write(hh)
		for _, sp := range p.Stages {
			for _, hp := range sp.Hosts {
				if hp.Host.Name != h.Name {
					continue
				}
				hs := hashStage{Stage: sp.Stage.Name, Parallelism: sp.Stage.Parallelism}
				if h := sp.Stage.Health; h != nil {
					hs.Health = &hashHealth{Command: h.Command, Stable: h.Stable, Timeout: h.Timeout}
				}
				write(hs)
				for _, pl := range hp.Steps {
					write(stepHash(pl))
				}
			}
		}
	}
	return b.Bytes()
}

// stepHash is the hash input of a planned step or a handler slot.
func stepHash(p Planned) hashStep {
	if s := p.Handler; s != nil {
		h := hashStep{Address: p.Address, Runs: s.Runs}
		for _, st := range s.Steps {
			h.Steps = append(h.Steps, stepHash(st))
		}
		return h
	}
	h := hashStep{Address: p.Address, Module: p.Step.Module, Notify: p.Notify, PendingThen: p.PendingThen}
	args := p.Step.Args
	if c, ok := args.(module.WithContent); ok {
		args = c.WithoutContent()
	}
	var then any
	if p.Step.Then != "" {
		then = p.Step.Then
	}
	var result any
	if p.Step.Args != nil && p.Result.Status != "" {
		r := hashResult{Result: p.Result}
		r.Result.Old = nil
		if p.Result.Old != nil {
			r.Old = sum(*p.Result.Old)
		}
		result = r
	}
	h.Args, h.Then, h.Result = args, then, result
	if p.Step.Secret {
		h.Args, h.Then, h.Result = sumJSON(args), sumJSON(then), sumJSON(result)
	}
	return h
}

func sum(s string) string { return sumBytes([]byte(s)) }

func sumBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// sumJSON returns the SHA-256 of the JSON of v.
func sumJSON(v any) string {
	b, _ := json.Marshal(v)
	return sumBytes(b)
}

// Hash returns the plan hash: the first 16 hex characters of the SHA-256 of
// the hash input. MakePlan computes it once.
func (p *Plan) Hash() string { return p.hash }
