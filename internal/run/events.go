package run

import (
	"cmp"
	"encoding/json"
	"time"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

// Events writes JSON events, one object per line and one write per line.
type Events struct {
	w   *color.Writer
	now func() time.Time
}

func NewEvents(w *color.Writer, now func() time.Time) *Events {
	return &Events{w: w, now: now}
}

// Write writes the event v, a struct, with its type and the time first.
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
	_ = e.w.WriteJSON(append(line, '\n'))
}

// Events is the Reporter of apply that writes applied and host events.
func (e *Events) Step(ev StepEvent) {
	ev.Error = secret.PrintableLines(ev.Error)
	e.Write("applied", ev)
}

func (e *Events) Host(ev HostEvent) {
	ev.Error = secret.PrintableLines(ev.Error)
	e.Write("host", ev)
}

func (e *Events) Done(*Outcome) {}

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
	kinds := p.hostKinds()
	for _, h := range p.Hosts {
		ev := HostEvent{Phase: "plan", Host: h.Name, Status: cmp.Or(kinds[h.Name], "ok")}
		if err := p.Failed[h.Name]; err != nil {
			ev.Status, ev.Error = hostStatus(err), err.Error()
		}
		e.Host(ev)
	}
}

func writePlanned(e *Events, host string, stage *project.Stage, steps []Planned) {
	for _, p := range steps {
		ev := stepEvent(host, stage, p)
		if s := p.Handler; s != nil {
			if s.Runs {
				ev.Handler, ev.Status = s.Handler.FullName(), "change"
				e.Write("planned", ev)
				for _, hs := range s.Steps {
					if hs.PendingThen {
						tev := stepEvent(host, stage, hs)
						tev.Handler, tev.Status = ev.Handler, "change"
						tev.Then, tev.ThenPending = secret.PrintableLines(hs.Step.ShownThen()), true
						e.Write("planned", tev)
					}
				}
			}
			continue
		}
		ev.Step, ev.Module, ev.Status, ev.Action = label(p.Step), p.Step.Module, string(p.Result.Status), string(p.Result.Action)
		if p.Result.Status == module.Change {
			ev.Link = secret.Printable(p.Result.Link)
			for _, c := range p.Result.Changes {
				ev.Changes = append(ev.Changes, secret.PrintableLines(c))
			}
			ev.Diff = diffLines(p.Step, p.Result)
			if p.Result.Validates {
				ev.Validate = secret.PrintableLines(p.Step.ShownValidate())
			}
		}
		if p.ThenRuns {
			ev.Then, ev.ThenPending = secret.PrintableLines(p.Step.ShownThen()), p.PendingThen
		}
		e.Write("planned", ev)
	}
}
