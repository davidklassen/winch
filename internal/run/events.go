package run

import (
	"encoding/json"
	"io"
	"time"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

// Events writes JSON events, one object per line. Each event is one write,
// so the secret filter of the writer sees the whole line.
type Events struct {
	w   io.Writer
	now func() time.Time
}

func NewEvents(w io.Writer, now func() time.Time) *Events {
	return &Events{w: w, now: now}
}

// Write writes the event v, a struct, with its type and the time first. The
// JSON escapes <, >, and & as json.Marshal does, as the JSON form of a secret
// in the filter does.
func (e *Events) Write(typ string, v any) {
	head, _ := json.Marshal(struct {
		Type string `json:"type"`
		Time string `json:"time"`
	}{typ, e.now().UTC().Format(time.RFC3339Nano)})
	line := head[:len(head)-1]
	// The events are plain data; they always encode.
	if b, _ := json.Marshal(v); len(b) > 2 {
		line = append(append(line, ','), b[1:]...)
	} else {
		line = append(line, '}')
	}
	// A failed write of stdout has no one to tell.
	_, _ = e.w.Write(append(line, '\n'))
}

// Events is the Reporter of apply that writes applied and host events.
func (e *Events) Step(ev StepEvent) { e.Write("applied", ev) }
func (e *Events) Host(ev HostEvent) { e.Write("host", ev) }
func (e *Events) Done(*Outcome)     {}

// WriteJSON writes a planned event for each checked step and each handler
// that will run, of the hosts that did not fail, then a host event per host.
func (p *Plan) WriteJSON(e *Events) {
	for _, h := range p.Hosts {
		if p.Failed[h.Name] != nil {
			continue
		}
		for _, sp := range p.Stages {
			for _, hp := range sp.Hosts {
				if hp.Host.Name != h.Name {
					continue
				}
				writePlanned(e, h.Name, sp.Stage, hp.Steps)
				if sp.Stage.Health != nil && hp.changes() {
					e.Write("planned", healthEvent(h.Name, sp.Stage))
				}
			}
		}
	}
	for _, h := range p.Hosts {
		ev := HostEvent{Phase: "plan", Host: h.Name, Status: "ok"}
		switch err := p.Failed[h.Name]; {
		case err != nil:
			ev.Status, ev.Error = hostStatus(err), err.Error()
		case p.changes(h.Name):
			ev.Status = "change"
		}
		e.Write("host", ev)
	}
}

func writePlanned(e *Events, host string, stage *project.Stage, steps []Planned) {
	for _, p := range steps {
		ev := stepEvent(host, stage, p)
		if s := p.Handler; s != nil {
			if s.Runs {
				ev.Handler, ev.Status = s.Handler.FullName(), "change"
				e.Write("planned", ev)
			}
			continue
		}
		ev.Step, ev.Module, ev.Status, ev.Action = label(p.Step), p.Step.Module, string(p.Result.Status), string(p.Result.Action)
		if p.Result.Status == module.Change {
			ev.Link = secret.Printable(p.Result.Link)
			for _, c := range p.Result.Changes {
				ev.Changes = append(ev.Changes, secret.Printable(c))
			}
			ev.Diff = diffLines(p.Step, p.Result)
		}
		if p.ThenRuns {
			ev.Then, ev.ThenPending = secret.PrintableLines(p.Step.ShownThen()), p.PendingThen
		}
		e.Write("planned", ev)
	}
}
