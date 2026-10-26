package run

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
)

// ErrInterrupted is the error of a host that an interrupt stopped before its
// next step.
var ErrInterrupted = errors.New("interrupted")

// StepEvent is a step that the plan or apply checked, a handler that will
// run, or a then that ran.
type StepEvent struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	Stage   string `json:"stage"`
	Recipe  string `json:"recipe,omitempty"`
	Handler string `json:"handler,omitempty"`
	// Step is the label of the step in the plan.
	Step    string   `json:"step,omitempty"`
	Module  string   `json:"module,omitempty"`
	Status  string   `json:"status"`
	Action  string   `json:"action,omitempty"`
	Link    string   `json:"link,omitempty"`
	Changes []string `json:"changes,omitempty"`
	Diff    []string `json:"diff,omitempty"`
	Then    string   `json:"then,omitempty"`
	// ThenPending is true for a then that a run before left pending.
	ThenPending bool   `json:"then_pending,omitempty"`
	Error       string `json:"error,omitempty"`
}

// HostEvent is a host that finished or failed.
type HostEvent struct {
	Phase  string `json:"phase"`
	Host   string `json:"host"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Reporter receives the results of apply as they happen.
type Reporter interface {
	Step(StepEvent)
	Host(HostEvent)
	Done(*Outcome)
}

// Outcome is the result of apply.
type Outcome struct {
	Hosts   int
	Changed map[string]bool
	// Failed holds the hosts that failed in the plan or in apply.
	Failed map[string]error
}

func (o *Outcome) OK() bool { return len(o.Failed) == 0 }

func (o *Outcome) Unchanged() int { return o.Hosts - len(o.Changed) - len(o.Failed) }

// ErrUnreachable is the cause of a connect error when winch could not reach
// the host.
var ErrUnreachable = errors.New("unreachable")

// MarkUnreachable returns err, marked so that errors.Is finds ErrUnreachable.
// Its text stays the same.
func MarkUnreachable(err error) error { return unreachable{err} }

type unreachable struct{ error }

func (unreachable) Is(target error) bool { return target == ErrUnreachable }

func (u unreachable) Unwrap() error { return u.error }

// Text returns a reporter that prints one line per step that changes, and
// the errors to errOut.
func Text(out, errOut io.Writer) Reporter { return text{out, errOut} }

type text struct{ out, errOut io.Writer }

func (t text) Step(ev StepEvent) {
	switch {
	case ev.Status != "change":
	case ev.Then != "" && ev.ThenPending:
		fmt.Fprintf(t.out, "%s: %s: ! then: %s\n", ev.Host, ev.scope(), ev.Then)
	case ev.Then == "":
		fmt.Fprintf(t.out, "%s: %s: %s %s%s\n", ev.Host, ev.scope(), marks[module.Action(ev.Action)], ev.label(), linkNote(ev.Link))
	}
}

func (t text) Host(ev HostEvent) {
	if ev.Error != "" {
		fmt.Fprintf(t.errOut, "%s: %s\n", ev.Host, ev.Error)
	}
}

func (t text) Done(o *Outcome) {
	fmt.Fprintf(t.out, "\n%s: %d changed, %d unchanged%s\n", hosts(o.Hosts),
		len(o.Changed), o.Unchanged(), failures(len(o.Failed)))
}

// Apply applies every stage of a plan on the hosts with a change in the plan.
// A stage can undo what an earlier stage does, so a stage without a change
// runs too. Each step is checked again right before it is applied, and the
// handlers follow what apply changes.
func Apply(ctx context.Context, plan *Plan, connect Connect, rep Reporter) *Outcome {
	o := &Outcome{Hosts: len(plan.Hosts), Changed: map[string]bool{}, Failed: map[string]error{}}
	for name, err := range plan.Failed {
		o.Failed[name] = err
	}
	toApply := map[string]bool{}
	for _, sp := range plan.Stages {
		for _, hp := range sp.Hosts {
			if hp.changes() {
				toApply[hp.Host.Name] = true
			}
		}
	}
	runs := map[string]*hostApply{}
	for _, sp := range plan.Stages {
		for _, hp := range sp.Hosts {
			name := hp.Host.Name
			if !toApply[name] || o.Failed[name] != nil {
				continue
			}
			if runs[name] == nil {
				runs[name] = &hostApply{host: name, rep: rep, notified: map[string]bool{}, thens: map[protocol.Then]bool{}}
				for _, n := range plan.Pending[name].Handlers {
					runs[name].notified[n] = true
				}
				for _, t := range plan.Pending[name].Then {
					runs[name].thens[t] = true
				}
			}
			ok, err := runs[name].apply(ctx, connect, plan.Project, sp.Stage, hp)
			if err != nil {
				o.Failed[name] = err
				delete(o.Changed, name)
				rep.Host(HostEvent{Phase: "apply", Host: name, Status: hostStatus(err), Error: err.Error()})
				continue
			}
			if ok {
				o.Changed[name] = true
			}
		}
	}
	for _, h := range plan.Hosts {
		if o.Failed[h.Name] != nil {
			continue
		}
		status := "unchanged"
		if o.Changed[h.Name] {
			status = "changed"
		}
		rep.Host(HostEvent{Phase: "apply", Host: h.Name, Status: status})
	}
	rep.Done(o)
	return o
}

// hostStatus is the status of a host that failed with err.
func hostStatus(err error) string {
	if errors.Is(err, ErrUnreachable) {
		return "unreachable"
	}
	return "failed"
}

// hostApply is what apply keeps about a host between its stages.
type hostApply struct {
	host  string
	rep   Reporter
	state module.State
	// notified are the handlers that wait for their slot: notified in this
	// run, or pending on the host.
	notified map[string]bool
	// thens are the pending then records that no step ran yet.
	thens map[protocol.Then]bool
	conn  Conn
}

// apply runs the steps and the handlers of a stage on one host. It reports
// whether a step changed something.
func (a *hostApply) apply(ctx context.Context, connect Connect, proj string, stage *project.Stage, hp HostPlan) (changed bool, err error) {
	if ctx.Err() != nil {
		return false, ErrInterrupted
	}
	a.conn, err = connect(context.WithoutCancel(ctx), proj, hp.Host)
	if err != nil {
		return false, fmt.Errorf("failed: %w", err)
	}
	defer func() {
		if cerr := a.conn.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("failed: %w", cerr)
		}
	}()
	return a.steps(ctx, stage, "", hp.Steps)
}

// stepEvent returns the event of p on host in stage, without its result.
func stepEvent(host string, stage *project.Stage, p Planned) StepEvent {
	ev := StepEvent{Host: host, Address: host + ":" + secret.Printable(p.Address), Stage: secret.Printable(stage.Name)}
	if p.In != nil {
		ev.Recipe = secret.Printable(p.In.Recipe.Name)
	}
	return ev
}

// scope is the recipe of an event, or its stage.
func (ev StepEvent) scope() string { return cmp.Or(ev.Recipe, ev.Stage) }

// label is the label of the step of an event, with its handler.
func (ev StepEvent) label() string {
	if ev.Handler != "" {
		return "handler " + ev.Handler + ": " + ev.Step
	}
	return ev.Step
}

// steps applies steps and runs the handlers of their slots. A step runs its
// then after its last element when an element changed something, or when its
// then is pending on the host.
func (a *hostApply) steps(ctx context.Context, stage *project.Stage, handler string, steps []Planned) (changed bool, err error) {
	// changedLabel is the label of the last element of the current step that
	// changed something, or "".
	changedLabel := ""
	for _, p := range steps {
		if ctx.Err() != nil {
			return changed, ErrInterrupted
		}
		if p.Handler != nil {
			c, err := a.handler(ctx, stage, p.Handler)
			changed = changed || c
			if err != nil {
				return changed, err
			}
			continue
		}
		ev := stepEvent(a.host, stage, p)
		ev.Handler, ev.Step, ev.Module = secret.Printable(handler), label(p.Step), p.Step.Module
		l := ev.label()
		c, err := a.step(ctx, ev, l, p)
		changed = changed || c
		if err != nil {
			return changed, err
		}
		if c {
			changedLabel = l
		}
		if !p.Last {
			continue
		}
		t := p.Then
		failLabel := cmp.Or(changedLabel, l)
		run := t != nil && (changedLabel != "" || a.thens[*t])
		changedLabel = ""
		if !run {
			continue
		}
		tev := ev
		tev.Step, tev.Module, tev.Then, tev.ThenPending = "", "", secret.Printable(p.Step.ShownThen()), a.thens[*t]
		if err := a.conn.Command(context.WithoutCancel(ctx), p.Step.Then, *t); err != nil {
			tev.Status, tev.Error = "failed", err.Error()
			a.rep.Step(tev)
			return changed, fmt.Errorf("%s: failed: %s: then: %w", ev.scope(), failLabel, err)
		}
		tev.Status = "change"
		a.rep.Step(tev)
		if a.thens[*t] {
			delete(a.thens, *t)
			changed = true
		}
	}
	return changed, nil
}

// handler runs the steps of a slot's handler when it was notified, and then
// removes its record on the host.
func (a *hostApply) handler(ctx context.Context, stage *project.Stage, s *Slot) (bool, error) {
	name := s.Handler.FullName()
	if !a.notified[name] {
		return false, nil
	}
	changed, err := a.steps(ctx, stage, name, s.Steps)
	if err != nil {
		return changed, err
	}
	if err := a.conn.Handled(context.WithoutCancel(ctx), name); err != nil {
		return changed, fmt.Errorf("%s: failed: handler %s: %w", secret.Printable(s.Handler.Recipe.Name), secret.Printable(name), err)
	}
	delete(a.notified, name)
	return changed, nil
}

// step applies one element of a step with the label l. It reports a change.
func (a *hostApply) step(ctx context.Context, ev StepEvent, l string, p Planned) (bool, error) {
	res, err := a.conn.Apply(context.WithoutCancel(ctx), p.Step.Module, p.Step.Args, &a.state, p.Notify, p.Then)
	if err != nil {
		ev.Status, ev.Error = "failed", err.Error()
		a.rep.Step(ev)
		return false, fmt.Errorf("%s: failed: %s: %w", ev.scope(), l, err)
	}
	ev.Status, ev.Action = string(res.Status), string(res.Action)
	ev.Link = secret.Printable(res.Link)
	a.rep.Step(ev)
	if res.Status != module.Change {
		return false, nil
	}
	for _, n := range p.Notify {
		a.notified[n] = true
	}
	return true, nil
}
