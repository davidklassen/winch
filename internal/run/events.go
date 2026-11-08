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

func (e *Events) Access(string, string) {}

// PutBack writes a note on the files that the session end puts back.
func (e *Events) PutBack(host, line string) {
	e.Write("diagnostic", struct {
		Severity string `json:"severity"`
		Host     string `json:"host"`
		Message  string `json:"message"`
	}{"note", host, secret.Printable(line)})
}

func (e *Events) Host(ev HostEvent) {
	ev.Error = secret.PrintableLines(ev.Error)
	e.Write("host", ev)
}

func (e *Events) Done(*Outcome) {}

// WriteJSON writes a planned event for each checked step and each then that
// will run, of the hosts that did not fail, then a host event per host.
func (p *Plan) WriteJSON(e *Events) {
	for _, h := range p.Hosts {
		if p.Failed[h.Name] != nil {
			continue
		}
		if p.rollsBack(h.Name) {
			e.Write("planned", rollbackEvent(h.Name, p.Pending[h.Name].Rollback))
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
		ev := HostEvent{Phase: "plan", Host: h.Name, Status: cmp.Or(kinds[h.Name], "unchanged")}
		if err := p.Failed[h.Name]; err != nil {
			ev.Status, ev.Error = hostStatus(err), err.Error()
		}
		e.Host(ev)
	}
}

func writePlanned(e *Events, host string, stage *project.Stage, steps []Planned) {
	for _, p := range steps {
		ev := stepEvent(host, stage, p)
		ev.Step, ev.Module = label(p.Step), p.Step.Module
		ev.result(p.Step, p.Result)
		if p.Result.Status == module.Change {
			ev.Diff = diffLines(p)
		}
		ev.Pending = p.Pending
		if p.ThenRuns {
			ev.Then = secret.PrintableLines(p.Step.Shown().Then)
			ev.Pending = ev.Pending || p.PendingThen
		}
		e.Write("planned", ev)
	}
}
