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
	Project string            `json:"project"`
	Stages  []string          `json:"stages"`
	Files   map[string]string `json:"files,omitempty"`
	Set     []string          `json:"set,omitempty"`
}

type hashHost struct {
	Host        string               `json:"host"`
	Destination protocol.Destination `json:"destination"`
	Failed      bool                 `json:"failed,omitempty"`
	Pending     *protocol.Pending    `json:"pending,omitempty"`
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
	Address  string   `json:"address"`
	Module   string   `json:"module,omitempty"`
	Args     any      `json:"args,omitempty"`
	Then     string   `json:"then,omitempty"`
	OnChange []string `json:"on_change,omitempty"`
	// ConfirmAccess changes what apply does, so the hash covers it.
	ConfirmAccess bool   `json:"confirm_access,omitempty"`
	Result        any    `json:"result,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Pending       bool   `json:"pending,omitempty"`
	PendingThen   bool   `json:"pending_then,omitempty"`
	ThenRuns      bool   `json:"then_runs,omitempty"`
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
	hr := hashRun{Project: p.Project, Files: p.sums, Set: p.set}
	for _, sp := range p.Stages {
		hr.Stages = append(hr.Stages, sp.Stage.Name)
	}
	write(hr)
	for _, h := range p.Hosts {
		hh := hashHost{Host: h.Name, Destination: p.Destinations[h.Name], Failed: p.Failed[h.Name] != nil}
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
					write(p.stepHash(pl))
				}
			}
		}
	}
	return b.Bytes()
}

// stepHash is the hash input of a planned step.
func (plan *Plan) stepHash(p Planned) hashStep {
	h := hashStep{Address: p.Address, Module: p.Step.Module, Args: p.Step.Args, Then: p.Step.Then, OnChange: p.Step.OnChange, ConfirmAccess: p.Step.ConfirmAccess,
		Reason: p.Reason, Pending: p.Pending, PendingThen: p.PendingThen, ThenRuns: p.ThenRuns}
	if c, ok := p.Step.Args.(module.WithContent); ok {
		h.Args = c.WithoutContent()
	}
	if p.Step.Args != nil && p.Result.Status != "" {
		r := hashResult{Result: p.Result}
		// SourceSHA256 covers the new text. The stderr of a check can change
		// from run to run, such as a time in it, while apply does the same.
		r.Result.Old, r.New, r.Masked, r.Stderr = nil, nil, nil, ""
		if p.Result.Old != nil {
			r.Old = sum(*p.Result.Old)
		}
		h.Result = r
	}
	return h
}

func sum(s string) string { return sumBytes([]byte(s)) }

func sumBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Hash returns the plan hash: the first 16 hex characters of the SHA-256 of
// the hash input. MakePlan computes it once.
func (p *Plan) Hash() string { return p.hash }
