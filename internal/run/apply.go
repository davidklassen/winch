package run

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/davidklassen/winch/internal/color"
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
	// Health is the command of a health gate.
	Health string `json:"health,omitempty"`
	// Step is the label of the step in the plan.
	Step   string `json:"step,omitempty"`
	Module string `json:"module,omitempty"`
	Status string `json:"status"`
	Action string `json:"action,omitempty"`
	Link   string `json:"link,omitempty"`
	// Note says what apply saw: that the host rebooted.
	Note    string   `json:"note,omitempty"`
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
func Text(out, errOut *color.Writer) Reporter { return text{out, errOut} }

type text struct{ out, errOut *color.Writer }

func (t text) Step(ev StepEvent) {
	var line color.Text
	switch {
	case ev.Health != "" && ev.Status == "ok":
		markLine(&line, ev.Host+": "+ev.Stage+": ", "*", " health:"+command(ev.Health, "    ")+"\n")
	case ev.Status != "change":
	case ev.Then != "" && ev.ThenPending:
		markLine(&line, ev.Host+": "+ev.scope()+": ", "!", " then:"+command(ev.Then, "    ")+"\n")
	case ev.Then == "":
		note := ""
		if ev.Note != "" {
			note = " (" + ev.Note + ")"
		}
		markLine(&line, ev.Host+": "+ev.scope()+": ", marks[module.Action(ev.Action)], " "+ev.label()+linkNote(ev.Link)+note+"\n")
	}
	if line != nil {
		color.Fprint(t.out, line)
	}
}

func (t text) Host(ev HostEvent) {
	if ev.Error != "" {
		hostError(t.errOut, ev.Host, ev.Error)
	}
}

func (t text) Done(o *Outcome) {
	fmt.Fprintf(t.out, "\n%s: %d changed, %d unchanged%s\n", hosts(o.Hosts),
		len(o.Changed), o.Unchanged(), failures(len(o.Failed)))
}

// Apply applies every stage of a plan on the hosts with a change in the plan.
// A stage can undo what an earlier stage does, so a stage without a change
// runs too. Each step is checked again right before it is applied, and the
// handlers follow what apply changes. The hosts of a stage run at the same
// time, at most the stage's parallelism.
func Apply(ctx context.Context, plan *Plan, connect Connect, rep Reporter) *Outcome {
	rep = &lockedReporter{rep: rep}
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
	open := func(h project.Host) (Conn, error) {
		a := runs[h.Name]
		if a.conn == nil {
			c, err := connect(context.WithoutCancel(ctx), plan.Project, h)
			if err != nil {
				return nil, fmt.Errorf("failed: %w", err)
			}
			a.conn = c
		}
		return a.conn, nil
	}
	last := map[string]int{}
	for i, sp := range plan.Stages {
		for _, hp := range sp.Hosts {
			last[hp.Host.Name] = i
		}
	}
	for si, sp := range plan.Stages {
		var hps []HostPlan
		var hosts []project.Host
		for _, hp := range sp.Hosts {
			name := hp.Host.Name
			if !toApply[name] || o.Failed[name] != nil {
				continue
			}
			hps, hosts = append(hps, hp), append(hosts, hp.Host)
			if runs[name] == nil {
				runs[name] = &hostApply{host: name, rep: rep, notified: map[string]bool{}, thens: map[protocol.Then]bool{}}
				for _, n := range plan.Pending[name].Handlers {
					runs[name].notified[n] = true
				}
				for _, t := range plan.Pending[name].Then {
					runs[name].thens[t] = true
				}
			}
		}
		changed := make([]bool, len(hps))
		stage := sp.Stage
		errs := rollout(ctx, stage.Name, hosts, stage.Parallelism, plan.opts.Serial, open, func(i int, _ Conn) error {
			a := runs[hosts[i].Name]
			var err error
			changed[i], err = a.apply(ctx, stage, hps[i])
			if err != nil || last[hosts[i].Name] == si {
				if cerr := a.close(); err == nil && cerr != nil {
					err = fmt.Errorf("failed: %w", cerr)
				}
			}
			return err
		})
		for i, h := range hosts {
			if err := errs[i]; err != nil {
				runs[h.Name].close() //nolint:errcheck // the host failed already
				o.Failed[h.Name] = err
				delete(o.Changed, h.Name)
				rep.Host(HostEvent{Phase: "apply", Host: h.Name, Status: hostStatus(err), Error: err.Error()})
				continue
			}
			if changed[i] {
				o.Changed[h.Name] = true
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

// lockedReporter lets the hosts of a stage report at the same time.
type lockedReporter struct {
	mu  sync.Mutex
	rep Reporter
}

func (r *lockedReporter) Step(ev StepEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.Step(ev)
}

func (r *lockedReporter) Host(ev HostEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.Host(ev)
}

func (r *lockedReporter) Done(o *Outcome) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.Done(o)
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
	// conn is the session with the host, open across its stages.
	conn Conn
}

// close closes the session with the host, if one is open.
func (a *hostApply) close() error {
	if a.conn == nil {
		return nil
	}
	err := a.conn.Close()
	a.conn = nil
	return err
}

// apply runs the steps and the handlers of a stage on one host, then its
// health gate when the plan or apply has a change in the stage. It reports
// whether a step changed something.
func (a *hostApply) apply(ctx context.Context, stage *project.Stage, hp HostPlan) (bool, error) {
	changed, err := a.steps(ctx, stage, "", hp.Steps)
	if err != nil {
		return changed, err
	}
	if stage.Health != nil && (changed || hp.changes()) {
		if ctx.Err() != nil {
			return changed, ErrInterrupted
		}
		return changed, a.health(ctx, stage)
	}
	return changed, nil
}

// health runs the health gate of a stage.
func (a *hostApply) health(ctx context.Context, stage *project.Stage) error {
	h := stage.Health
	ev := healthEvent(a.host, stage)
	err := a.conn.Health(context.WithoutCancel(ctx), protocol.Health{Command: h.Command,
		Stable: time.Duration(h.Stable) * time.Second, Timeout: time.Duration(h.Timeout) * time.Second})
	if err != nil {
		ev.Status, ev.Error = "failed", err.Error()
	}
	a.rep.Step(ev)
	if err != nil {
		shown, sep := command(ev.Health, "    "), ": "
		if strings.HasPrefix(shown, "\n") {
			sep = "\n"
		}
		return fmt.Errorf("%s: failed: health:%s%s%w", ev.Stage, shown, sep, err)
	}
	return nil
}

// healthEvent returns the event of the health gate of stage on host, as it
// passes.
func healthEvent(host string, stage *project.Stage) StepEvent {
	return StepEvent{Host: host, Address: host + ":" + stage.Name + "#health", Stage: stage.Name, Health: secret.PrintableLines(stage.Health.Command), Status: "ok"}
}

// stepEvent returns the event of p on host in stage, without its result.
func stepEvent(host string, stage *project.Stage, p Planned) StepEvent {
	ev := StepEvent{Host: host, Address: host + ":" + p.Address, Stage: stage.Name}
	if p.In != nil {
		ev.Recipe = p.In.Recipe.Name
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
		ev.Handler, ev.Step, ev.Module = handler, label(p.Step), p.Step.Module
		l := ev.label()
		res, err := a.step(ctx, ev, l, p, guard(stage, p))
		changed = changed || res.Status == module.Change
		if err != nil {
			return changed, err
		}
		if res.Status == module.Change {
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
		tev.Step, tev.Module, tev.Then, tev.ThenPending = "", "", secret.PrintableLines(p.Step.ShownThen()), a.thens[*t]
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

// timerMargin is the time before the end of the rollback timer when apply
// stops trying the access and asks for the rollback itself.
const timerMargin = 10 * time.Second

// accessPoll is the time between the two checks of the access. sshd's
// PerSourcePenalties blocks an address after three failed logins, so apply
// tries twice: a third failed login would lock winch out after the rollback.
const accessPoll = 5 * time.Second

// confirm checks the access with a second SSH connection, at most twice, and
// not after shortly before the rollback timer ends after left. Then it stops
// the timer, or asks the helper to put back the old files.
func (a *hostApply) confirm(ctx context.Context, left time.Duration) error {
	ctx = context.WithoutCancel(ctx)
	deadline := time.Now().Add(left - timerMargin)
	err := a.conn.Access(ctx)
	if err != nil && time.Now().Add(accessPoll).Before(deadline) {
		time.Sleep(accessPoll)
		err = a.conn.Access(ctx)
	}
	if err == nil {
		return a.conn.Confirm(ctx)
	}
	if rerr := a.conn.Rollback(ctx); rerr != nil {
		return fmt.Errorf("no new SSH connection works: %w; the rollback failed: %w", err, rerr)
	}
	return fmt.Errorf("no new SSH connection works: %w; the old files are back", err)
}

// reboot reboots the host and waits until it is back. It returns the note of
// the apply line.
func (a *hostApply) reboot(ctx context.Context, r *module.Reboot) (string, error) {
	b, err := a.conn.Reboot(context.WithoutCancel(ctx), r.Wait())
	if err != nil {
		return "", err
	}
	if len(b.Failed) > 0 {
		return "rebooted; degraded, failed units: " + strings.Join(b.Failed, ", "), nil
	}
	return "rebooted", nil
}

// handler runs the steps of a slot's handler when it was notified, and then
// removes its record on the host.
func (a *hostApply) handler(ctx context.Context, stage *project.Stage, s *Slot) (bool, error) {
	h := s.Handler
	record := h.Record()
	if !a.notified[record] {
		return false, nil
	}
	changed, err := a.steps(ctx, stage, h.FullName(), s.Steps)
	if err != nil {
		return changed, err
	}
	if err := a.conn.Handled(context.WithoutCancel(ctx), record); err != nil {
		return changed, fmt.Errorf("%s: failed: handler %s: %w", h.Owner(), h.FullName(), err)
	}
	delete(a.notified, record)
	return changed, nil
}

// guard returns how the helper guards the step p of stage: it saves in the
// store of the recipe, or of the stage for a module step of the stage, when
// that has a step with confirm_access. A step that notifies a handler with
// confirm_access of another recipe saves in the store of that recipe, which
// the handler's timer puts back.
func guard(stage *project.Stage, p Planned) protocol.Guard {
	g := protocol.Guard{Confirm: p.Step.ConfirmAccess}
	if p.In != nil {
		g.Recipe, g.Save = p.In.Recipe.Name, p.In.Recipe.ConfirmsAccess()
	} else {
		g.Pipeline, g.Stage, g.Save = stage.Pipeline, stage.Name, stage.ConfirmsAccess()
	}
	if g.Save {
		return g
	}
	for _, h := range p.Step.Notify {
		if h.Recipe != nil && h.ConfirmsAccess() {
			return protocol.Guard{Recipe: h.Recipe.Name, Save: true}
		}
	}
	return g
}

// step applies one element of a step with the label l. A step that runs a
// command returns a change. After a step that started the rollback timer, it
// checks the access. After a changed reboot step, it reboots the host.
func (a *hostApply) step(ctx context.Context, ev StepEvent, l string, p Planned, g protocol.Guard) (module.Result, error) {
	res, err := a.conn.Apply(context.WithoutCancel(ctx), p.Step.Module, p.Step.Args, &a.state, p.Notify, p.Then, g)
	if err == nil && res.Timer > 0 {
		err = a.confirm(ctx, res.Timer)
	}
	if r, ok := p.Step.Args.(*module.Reboot); ok && err == nil && res.Status == module.Change {
		ev.Note, err = a.reboot(ctx, r)
	}
	if err != nil {
		ev.Status, ev.Error = "failed", err.Error()
		a.rep.Step(ev)
		return module.Result{}, fmt.Errorf("%s: failed: %s: %w", ev.scope(), l, err)
	}
	// A step that runs a command counts as changed.
	if res.Status == module.Unknown {
		res.Status, res.Action = module.Change, module.Modify
	}
	ev.Status, ev.Action = string(res.Status), string(res.Action)
	ev.Link = secret.Printable(res.Link)
	a.rep.Step(ev)
	if res.Status == module.Change {
		for _, n := range p.Notify {
			a.notified[n] = true
		}
	}
	return res, nil
}
