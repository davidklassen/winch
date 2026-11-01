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
	Address string `json:"address"`
	Module  string `json:"module,omitempty"`
	// A step that reads a secret has the Args and Then of the first
	// placeholder variant, and its Result as filtered JSON text.
	Args   any      `json:"args,omitempty"`
	Then   string   `json:"then,omitempty"`
	Notify []string `json:"notify,omitempty"`
	// ConfirmAccess changes what apply does, so the hash covers it.
	ConfirmAccess bool `json:"confirm_access,omitempty"`
	Result        any  `json:"result,omitempty"`
	PendingThen   bool `json:"pending_then,omitempty"`
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
	hr := hashRun{Project: p.Project, Files: p.sums}
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

// stepHash is the hash input of a planned step or a handler slot.
func (plan *Plan) stepHash(p Planned) hashStep {
	if s := p.Handler; s != nil {
		h := hashStep{Address: p.Address, Runs: s.Runs}
		for _, st := range s.Steps {
			h.Steps = append(h.Steps, plan.stepHash(st))
		}
		return h
	}
	h := hashStep{Address: p.Address, Module: p.Step.Module, Notify: p.Notify, ConfirmAccess: p.Step.ConfirmAccess, PendingThen: p.PendingThen}
	var args any = p.Step.Args
	then := p.Step.Then
	if p.Step.Secret {
		args, then = p.Step.HashArgs, p.Step.HashThen
	}
	if c, ok := args.(module.WithContent); ok {
		args = c.WithoutContent()
	}
	h.Args, h.Then = args, then
	if p.Step.Args != nil && p.Result.Status != "" {
		r := hashResult{Result: p.Result}
		r.Result.Old = nil
		if p.Result.Old != nil {
			old := *p.Result.Old
			if p.Step.Secret {
				old = plan.filter.Text(old)
			}
			r.Old = sum(old)
		}
		h.Result = r
		if p.Step.Secret {
			b, _ := json.Marshal(r)
			h.Result = plan.filter.Text(string(b))
		}
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
