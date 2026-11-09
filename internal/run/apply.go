package run

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/session"
)

// ErrInterrupted is the error of a host that an interrupt stopped before its
// next step.
var ErrInterrupted = errors.New("interrupted")

// StepEvent is a step that the plan or apply checked, or a then.
type StepEvent struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	Stage   string `json:"stage"`
	Recipe  string `json:"recipe,omitempty"`
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
	// Validate is the validate command that apply runs.
	Validate string `json:"validate,omitempty"`
	Unless   string `json:"unless,omitempty"`
	// Pending is true for a step or a then that a run before left pending.
	Pending bool   `json:"pending,omitempty"`
	Error   string `json:"error,omitempty"`
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
	// Access reports an access check that passed: after a step of scope, or
	// after the run when scope is "".
	Access(host, scope string)
	// PutBack reports the files that the session end puts back on host,
	// because the step with confirm_access that reacts to their change did
	// not run.
	PutBack(host, line string)
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

// Text returns a reporter that prints one line per step that changes, and
// the errors to errOut.
func Text(out, errOut *color.Writer) Reporter { return text{out, errOut} }

type text struct{ out, errOut *color.Writer }

func (t text) Step(ev StepEvent) {
	var line color.Text
	switch {
	case ev.Address == rollbackEvent(ev.Host, nil).Address && ev.Status == "change":
		markLine(&line, ev.Host+": ", "!", " "+rollbackLabel+"\n")
	case ev.Health != "" && ev.Status == "ok":
		line.Add(color.Plain, ev.Host+": "+ev.Stage+": health passed:"+command(ev.Health, "    ")+"\n")
	case ev.Status != "change":
	case ev.Then != "" && ev.Pending:
		markLine(&line, ev.Host+": "+ev.scope()+": ", "!", " then:"+command(ev.Then, "    ")+"\n")
	case ev.Then == "":
		note := ""
		if ev.Note != "" {
			note = " (" + ev.Note + ")"
		}
		markLine(&line, ev.Host+": "+ev.scope()+": ", marks[module.Action(ev.Action)], " "+oneLine(ev.Step)+linkNote(ev.Link)+note+"\n")
	}
	if line != nil {
		color.Fprint(t.out, line)
	}
}

func (t text) Access(host, scope string) {
	if scope == "" {
		fmt.Fprintf(t.out, "%s: access check after the run passed\n", host)
		return
	}
	fmt.Fprintf(t.out, "%s: %s: access check passed\n", host, scope)
}

func (t text) PutBack(host, line string) {
	fmt.Fprintf(t.out, "%s: %s\n", host, secret.Printable(line))
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

// Apply applies every stage of a plan on the hosts with a change in the plan,
// and only removes the gone records on the other hosts. A stage can undo what
// an earlier stage does, so a stage without a change runs too. Each step is
// checked again right before it is applied, and the steps with on_change
// follow what apply changes. The hosts of a stage run at the same time, at most the stage's
// parallelism.
func Apply(ctx context.Context, plan *Plan, connect Connect, rep Reporter) *Outcome {
	rep = &lockedReporter{rep: rep}
	o := &Outcome{Hosts: len(plan.Hosts), Changed: map[string]bool{}, Failed: map[string]error{}}
	for name, err := range plan.Failed {
		o.Failed[name] = err
	}
	toApply := plan.hostKinds()
	// dial takes the session of the plan, or opens a new one when the plan
	// kept none or its session died during the question. It then removes the
	// records of the host that the plan found gone.
	dial := func(h project.Host) (Conn, error) {
		c := plan.take(h.Name)
		if c != nil {
			if _, err := c.Pending(context.WithoutCancel(ctx)); err != nil {
				c.Close() //nolint:errcheck // the session died
				c = nil
			}
		}
		if c == nil {
			plan.opts.progress().Busy(h.Name, "connecting")
			want := plan.Destinations[h.Name]
			var err error
			if c, err = connect.Open(context.WithoutCancel(ctx), plan.Project, h, &want); err != nil {
				return nil, err
			}
		}
		c.Mask(plan.hide(h.Name))
		if toApply[h.Name] != "" && c.Prompted(context.WithoutCancel(ctx)) {
			c.Close() //nolint:errcheck // the host fails already
			return nil, errors.New("the access check cannot log in without a prompt; add the key to the agent with ssh-add")
		}
		for _, gone := range plan.gone[h.Name] {
			if err := c.Passed(context.WithoutCancel(ctx), gone); err != nil {
				c.Close() //nolint:errcheck // the host fails already
				return nil, err
			}
		}
		for _, gone := range plan.goneReacts[h.Name] {
			if err := c.Drop(context.WithoutCancel(ctx), gone); err != nil {
				c.Close() //nolint:errcheck // the host fails already
				return nil, err
			}
		}
		if len(plan.Pending[h.Name].Old) > 0 {
			if err := c.DropOld(context.WithoutCancel(ctx)); err != nil {
				c.Close() //nolint:errcheck // the host fails already
				return nil, err
			}
		}
		return c, nil
	}
	var remove []project.Host
	for _, h := range plan.Hosts {
		if toApply[h.Name] == "" && plan.removes(h.Name) {
			remove = append(remove, h)
		}
	}
	for i, err := range rollout(ctx, "", remove, 0, nil, plan.opts, dial, func(_ int, c Conn) error {
		return c.Close()
	}) {
		if err != nil {
			err = maskError(err, plan.hide(remove[i].Name))
			o.Failed[remove[i].Name] = err
			rep.Host(HostEvent{Phase: "apply", Host: remove[i].Name, Status: hostStatus(err), Error: err.Error()})
		}
	}
	runs := map[string]*hostApply{}
	open := func(h project.Host) (Conn, error) {
		a := runs[h.Name]
		if a.conn == nil {
			c, err := dial(h)
			if err != nil {
				return nil, err
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
	// fail ends the run of each host in names with its error in errs. A host
	// whose session is still open gets the access check after the run first.
	fail := func(names []string, errs []error) {
		var wg sync.WaitGroup
		for i, name := range names {
			if a := runs[name]; a != nil && a.conn != nil {
				wg.Go(func() {
					defer a.progress.Idle(name)
					errs[i] = a.finish(ctx, o.Changed[name], errs[i])
				})
			}
		}
		wg.Wait()
		for i, name := range names {
			err := maskError(errs[i], plan.hide(name))
			o.Failed[name] = err
			delete(o.Changed, name)
			rep.Host(HostEvent{Phase: "apply", Host: name, Status: hostStatus(err), Error: err.Error()})
			if a := runs[name]; a != nil {
				for _, scope := range a.held {
					rep.Access(name, scope)
				}
			}
		}
	}
	for si, sp := range plan.Stages {
		planned := map[string]HostPlan{}
		for _, hp := range sp.Hosts {
			planned[hp.Host.Name] = hp
		}
		stage := sp.Stage
		var hps []HostPlan
		var hosts []project.Host
		planFailed := ""
		for _, h := range stage.Targets {
			name := h.Name
			if plan.Failed[name] != nil {
				planFailed = cmp.Or(planFailed, name)
				if stage.Parallelism > 0 {
					hps, hosts = append(hps, HostPlan{Host: h}), append(hosts, h)
				}
				continue
			}
			if toApply[name] == "" || o.Failed[name] != nil {
				continue
			}
			hp := planned[name]
			hps, hosts = append(hps, hp), append(hosts, hp.Host)
			if runs[name] == nil {
				runs[name] = &hostApply{host: name, hide: plan.hide(name), rep: rep, progress: plan.opts.progress(), state: module.State{Refreshed: plan.refreshed[name]}, started: map[string]int{}, pending: slices.Clone(plan.Pending[name].React), rollback: plan.Pending[name].Rollback}
			}
		}
		changed := make([]bool, len(hps))
		// With parallelism, the hosts with a pending gate run first, and the
		// others start only after those gates pass.
		var pending, others []int
		for i, hp := range hps {
			if stage.Parallelism > 0 && hp.PendingHealth {
				pending = append(pending, i)
			} else {
				others = append(others, i)
			}
		}
		errs := make([]error, len(hosts))
		failed := ""
		for _, group := range [][]int{pending, others} {
			if failed != "" {
				for _, i := range group {
					errs[i] = fmt.Errorf("not started: %s failed in stage %s", failed, stage.Name)
				}
				continue
			}
			var gh []project.Host
			for _, i := range group {
				gh = append(gh, hosts[i])
			}
			ge := rollout(ctx, stage.Name, gh, stage.Parallelism, plan.Failed, plan.opts, open, func(j int, _ Conn) error {
				i := group[j]
				a := runs[hosts[i].Name]
				due, err := a.due(ctx)
				if err == nil {
					changed[i], err = a.apply(ctx, stage, hps[i])
				}
				changed[i] = changed[i] || due
				if err != nil || last[hosts[i].Name] == si {
					return a.finish(ctx, changed[i] || o.Changed[hosts[i].Name], err)
				}
				return nil
			})
			for j, err := range ge {
				errs[group[j]] = err
				// After an interrupt, rollout marks the other hosts itself.
				if err != nil && !errors.Is(err, ErrInterrupted) && failed == "" {
					failed = gh[j].Name
				}
			}
		}
		failed = cmp.Or(failed, planFailed)
		for i, h := range hosts {
			if changed[i] {
				o.Changed[h.Name] = true
			}
		}
		var names []string
		var ferrs []error
		for i, h := range hosts {
			if errs[i] != nil && plan.Failed[h.Name] == nil {
				names, ferrs = append(names, h.Name), append(ferrs, errs[i])
			}
		}
		fail(names, ferrs)
		if ctx.Err() == nil && failed == "" {
			continue
		}
		reason := ErrInterrupted
		if ctx.Err() == nil {
			reason = fmt.Errorf("not started: %s failed in stage %s", failed, stage.Name)
		}
		names, ferrs = nil, nil
		for _, h := range plan.Hosts {
			if toApply[h.Name] != "" && o.Failed[h.Name] == nil && last[h.Name] > si {
				names, ferrs = append(names, h.Name), append(ferrs, reason)
			}
		}
		fail(names, ferrs)
		break
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

func (r *lockedReporter) Access(host, scope string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.Access(host, scope)
}

func (r *lockedReporter) PutBack(host, line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.PutBack(host, line)
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
	if errors.Is(err, session.ErrUnreachable) {
		return "unreachable"
	}
	return "failed"
}

// hostApply is what apply keeps about a host between its stages.
type hostApply struct {
	host string
	// hide masks text from the host with the secret parts of its steps.
	hide     func(string) string
	rep      Reporter
	progress Progress
	state    module.State
	// clock counts the changed steps and the starts of the run. changed are
	// the paths that the steps changed, with the clock of their step, and
	// started holds the clock of each unit's last start by a service step.
	clock   int
	changed []changeAt
	started map[string]int
	// pending are the records of an earlier run that no step ran yet.
	pending []protocol.React
	// putBack are the steps with confirm_access that react to a change of
	// the run and did not run yet.
	putBack []*putBack
	// gate is the gate of the current stage while it is not recorded and
	// will run after a change.
	gate *protocol.Check
	// conn is the session with the host, open across its stages.
	conn Conn
	// rollback is the plan of the rollback of an earlier run, until it runs.
	rollback []string
	// held are the scopes of the access checks that passed on a host that
	// failed, in the order they ran; "" is the check after the run. Apply
	// reports them after the error of the host.
	held []string
}

// putBack is a step with confirm_access that reacts to a change of the run:
// the line of its record, its label, and the paths whose old state its store
// keeps.
type putBack struct {
	line  string
	label string
	paths []string
}

// finish ends the run of the host with the error err of the run. When the
// run changed the host, it runs the access check after the run first. After
// an error, it reports the files that the session end puts back.
func (a *hostApply) finish(ctx context.Context, changed bool, err error) error {
	if err != nil {
		for _, b := range a.putBack {
			a.rep.PutBack(a.host, "put back "+strings.Join(b.paths, ", ")+": "+b.label+" did not run")
		}
	}
	passed := false
	if changed {
		a.progress.Busy(a.host, "access check")
		// The access check returns context.Canceled after a second Ctrl-C.
		aerr := a.access(context.WithoutCancel(ctx), time.Time{})
		switch {
		case aerr == nil:
			passed = true
		case !errors.Is(aerr, context.Canceled):
			aerr = fmt.Errorf("the access check after the run failed: %w", aerr)
			if err != nil {
				aerr = fmt.Errorf("%w\n%w", err, aerr)
			}
			err = aerr
		}
	}
	err = errors.Join(err, a.close())
	switch {
	case passed && err == nil:
		a.rep.Access(a.host, "")
	case passed:
		a.held = append(a.held, "")
	}
	return err
}

func (a *hostApply) close() error {
	if a.conn == nil {
		return nil
	}
	err := a.conn.Close()
	a.conn = nil
	return err
}

const rollbackLabel = "rollback of an earlier run"

// rollbackEvent returns the event of the rollback of an earlier run on host,
// with its plan lines.
func rollbackEvent(host string, lines []string) StepEvent {
	ev := StepEvent{Host: host, Address: host + ":rollback", Step: rollbackLabel, Status: "change"}
	for _, l := range lines {
		ev.Changes = append(ev.Changes, secret.PrintableLines(l))
	}
	return ev
}

// due runs the rollback of an earlier run that the plan showed, before the
// first step of the host. It reports whether it ran.
func (a *hostApply) due(ctx context.Context) (bool, error) {
	if a.rollback == nil {
		return false, nil
	}
	if ctx.Err() != nil {
		return false, ErrInterrupted
	}
	ev := rollbackEvent(a.host, a.rollback)
	a.rollback = nil
	a.progress.Busy(a.host, rollbackLabel)
	if err := maskError(a.conn.Due(context.WithoutCancel(ctx)), a.hide); err != nil {
		ev.Status, ev.Error = "failed", err.Error()
		a.rep.Step(ev)
		return false, fmt.Errorf("failed: %s: %w", rollbackLabel, err)
	}
	a.rep.Step(ev)
	return true, nil
}

// apply runs the steps of a stage on one host, then its health gate when the
// plan or apply has a change in the stage. It reports whether a step changed
// something.
func (a *hostApply) apply(ctx context.Context, stage *project.Stage, hp HostPlan) (bool, error) {
	gate := protocol.Check{Pipeline: stage.Pipeline, Stage: stage.Name}
	a.gate = nil
	if stage.Health != nil && !hp.PendingHealth {
		a.gate = &gate
		if hp.changes() {
			if err := a.pendGate(ctx); err != nil {
				return false, err
			}
		}
	}
	changed, err := a.steps(ctx, stage, hp.Steps)
	if err != nil {
		return changed, err
	}
	if stage.Health == nil || !changed && !hp.changes() {
		return changed, nil
	}
	if ctx.Err() != nil {
		return changed, ErrInterrupted
	}
	return changed, a.health(ctx, stage, gate)
}

// pendGate records the gate of the current stage, before the stage changes
// something, so that a run that stops before the gate leaves it pending.
func (a *hostApply) pendGate(ctx context.Context) error {
	if a.gate == nil {
		return nil
	}
	if err := a.conn.Pend(context.WithoutCancel(ctx), *a.gate); err != nil {
		return fmt.Errorf("%s: failed: health: %w", a.gate.Stage, err)
	}
	a.gate = nil
	return nil
}

// health runs the health gate of a stage.
func (a *hostApply) health(ctx context.Context, stage *project.Stage, gate protocol.Check) error {
	h := stage.Health
	ev := healthEvent(a.host, stage)
	a.progress.Busy(a.host, stage.Name+": health")
	err := a.conn.Health(context.WithoutCancel(ctx), protocol.Health{Command: h.Command,
		Stable: time.Duration(h.Stable) * time.Second, Timeout: time.Duration(h.Timeout) * time.Second, Check: gate})
	err = maskError(err, a.hide)
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

func (ev StepEvent) scope() string { return cmp.Or(ev.Recipe, ev.Stage) }

// result sets the status of ev and the fields of the result res of st.
func (ev *StepEvent) result(st project.Step, res module.Result) {
	ev.Status, ev.Action = string(res.Status), string(res.Action)
	if res.Status != module.Change {
		return
	}
	ev.Link = secret.Printable(res.Link)
	for _, c := range res.Changes {
		ev.Changes = append(ev.Changes, secret.PrintableLines(c))
	}
	shown := st.Shown().Args
	if v, ok := shown.(module.WithValidate); ok && res.Validates {
		ev.Validate = secret.PrintableLines(v.ValidateCommand())
	}
	if c, ok := shown.(*module.Cmd); ok {
		ev.Unless = secret.PrintableLines(c.UnlessCommand())
	}
}

// steps applies steps. A step with on_change acts only when an earlier step
// of the run changed a path that it reacts to, or when its record is pending.
// A step runs its then after its last element when an element of the step
// changed something, or when its then is pending on the host.
func (a *hostApply) steps(ctx context.Context, stage *project.Stage, steps []Planned) (changed bool, err error) {
	// reacted is true when an element of the current step acted on a
	// change, and stepChanged when an element changed something.
	reacted, stepChanged := false, false
	for _, p := range steps {
		if ctx.Err() != nil {
			return changed, ErrInterrupted
		}
		ev := stepEvent(a.host, stage, p)
		ev.Step, ev.Module = label(p.Step), p.Step.Module
		l := oneLine(ev.Step)
		acts := true
		if len(p.Step.OnChange) > 0 {
			_, at, hit := reaction(a.changed, p.Step.OnChange)
			acts = hit || slices.ContainsFunc(a.pending, p.Record.Matches)
			if acts {
				p.Step = afterStart(p.Step, a.started, at)
				reacted = true
				a.putBack = slices.DeleteFunc(a.putBack, func(b *putBack) bool { return b.line == p.Record.Line() })
			}
		}
		if acts {
			a.progress.Busy(a.host, ev.scope()+": "+l)
			res, err := a.step(ctx, ev, l, p, guard(p))
			changed = changed || res.Status == module.Change
			stepChanged = stepChanged || res.Status == module.Change
			if err != nil {
				return changed, err
			}
		} else {
			ev.Status = string(module.OK)
			a.rep.Step(ev)
		}
		if !p.Last {
			continue
		}
		thenRuns := stepChanged
		stepChanged = false
		if reacted {
			reacted = false
			if err := a.conn.Reacted(context.WithoutCancel(ctx), p.Record); err != nil {
				return changed, fmt.Errorf("%s: failed: %s: %w", ev.scope(), l, err)
			}
			a.pending = slices.DeleteFunc(a.pending, p.Record.Matches)
		}
		if p.Step.Then == "" {
			continue
		}
		t := p.thenRecord()
		pending := slices.ContainsFunc(a.pending, t.Matches)
		if !thenRuns && !pending {
			continue
		}
		thenLabel := l
		if p.Step.Loops() {
			thenLabel = p.Step.Module + " (loop)"
			if p.Step.Name != "" {
				thenLabel = stepHead(p.Step)
			}
		}
		tev := ev
		tev.Step, tev.Module, tev.Then, tev.Pending = "", "", secret.PrintableLines(p.Step.Shown().Then), pending
		a.progress.Busy(a.host, ev.scope()+": "+thenLabel+": then")
		if err := a.conn.Command(context.WithoutCancel(ctx), p.Step.Then, t); err != nil {
			err = maskError(err, p.hostText)
			tev.Status, tev.Error = "failed", err.Error()
			a.rep.Step(tev)
			return changed, fmt.Errorf("%s: failed: %s: then: %w", ev.scope(), thenLabel, err)
		}
		tev.Status = "change"
		a.rep.Step(tev)
		a.pending = slices.DeleteFunc(a.pending, t.Matches)
		changed = true
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
// the timer, or asks the helper to put back the old files. A negative left
// means that the step ended after the timer.
func (a *hostApply) confirm(ctx context.Context, left time.Duration) error {
	ctx = context.WithoutCancel(ctx)
	if left < 0 {
		// The timer may not have taken the job yet. The rollback also drops
		// the records of the step.
		if err := a.conn.Rollback(ctx); err != nil {
			return fmt.Errorf("the rollback timer ended first; the rollback failed: %w", err)
		}
		return errors.New("the rollback timer ended first; the old files are back")
	}
	err := a.access(ctx, time.Now().Add(left-timerMargin))
	if err == nil {
		return a.conn.Confirm(ctx)
	}
	// After a second Ctrl-C, the rollback fails with the error of the ended
	// session, and the helper rolls back at the session end. The kill of the
	// session may come after the rollback request.
	if errors.Is(err, context.Canceled) {
		if rerr := a.conn.Rollback(ctx); rerr != nil {
			return rerr
		}
		return ErrInterrupted
	}
	if rerr := a.conn.Rollback(ctx); rerr != nil {
		return fmt.Errorf("the access check failed: %w; the rollback failed: %w", err, rerr)
	}
	return fmt.Errorf("the access check failed: %w; the old files are back", err)
}

// access checks the access with a second SSH connection, at most twice. With
// a deadline, it does not start the second try after it.
func (a *hostApply) access(ctx context.Context, deadline time.Time) error {
	err := a.conn.Access(ctx)
	if err != nil && !errors.Is(err, context.Canceled) && (deadline.IsZero() || time.Now().Add(accessPoll).Before(deadline)) {
		time.Sleep(accessPoll)
		err = a.conn.Access(ctx)
	}
	return err
}

// reboot reboots the host, waits until it is back, and reads the facts again.
// It returns the note of the apply line.
func (a *hostApply) reboot(ctx context.Context, r *module.Reboot) (string, error) {
	ctx = context.WithoutCancel(ctx)
	b, err := a.conn.Reboot(ctx, r.Wait())
	if err != nil {
		return "", err
	}
	f, err := a.conn.Facts(ctx)
	if err != nil {
		return "", err
	}
	switch {
	case !f.RebootRequired:
	case b.Kernel != b.Newest:
		return "", fmt.Errorf("the host still needs a reboot after it rebooted: running kernel %s, newest kernel %s", b.Kernel, b.Newest)
	case len(b.Packages) > 0:
		return "", fmt.Errorf("the host still needs a reboot after it rebooted: /run/reboot-required lists the packages %s", strings.Join(b.Packages, ", "))
	default:
		return "", errors.New("the host still needs a reboot after it rebooted: /run/reboot-required exists")
	}
	if len(b.Failed) > 0 {
		return "rebooted with failed units: " + strings.Join(b.Failed, ", "), nil
	}
	return "rebooted", nil
}

// guard returns how the helper guards the step p: it saves in the store of
// each later step with confirm_access that reacts to a path of p, and in each
// store of p.SSHD.
func guard(p Planned) protocol.Guard {
	return protocol.Guard{Store: p.Record.Store(), Confirm: p.Step.ConfirmAccess, Guarded: p.Guarded, SSHD: p.SSHD, LoadsSSHD: p.LoadsSSHD && p.Step.ConfirmAccess}
}

// step applies one element of a step with the label l. A step that runs a
// command returns a change. After a step that started the rollback timer, it
// checks the access. After a changed reboot step, it reboots the host.
func (a *hostApply) step(ctx context.Context, ev StepEvent, l string, p Planned, g protocol.Guard) (module.Result, error) {
	a.conn.Mask(p.hostText)
	res, err := a.conn.Apply(context.WithoutCancel(ctx), p.Step.Module, p.Step.Args, &a.state, p.React, g, p.Step.MaskedContent())
	a.conn.Mask(a.hide)
	if res.Failed != "" {
		err = errors.New(res.Failed)
	}
	err = maskError(err, p.hostText)
	// The access check error is text of winch around host errors.
	passed := false
	if res.Timer != 0 {
		cerr := maskError(a.confirm(ctx, res.Timer), a.hide)
		passed = cerr == nil
		switch {
		case err == nil:
			err = cerr
		case cerr != nil:
			err = fmt.Errorf("%w; %w", err, cerr)
		}
	}
	if r, ok := p.Step.Args.(*module.Reboot); ok && err == nil && res.Status == module.Change {
		ev.Note, err = a.reboot(ctx, r)
		ev.Note, err = p.hostText(ev.Note), maskError(err, p.hostText)
	}
	if err != nil {
		ev.Status, ev.Error = "failed", err.Error()
	} else {
		// A step that runs a command counts as changed.
		if res.Status == module.Unknown {
			res.Status, res.Action = module.Change, module.Modify
		}
		maskResult(p.Step, p.parts, &res)
		ev.result(p.Step, res)
	}
	a.rep.Step(ev)
	switch {
	case passed && err == nil:
		a.rep.Access(a.host, ev.scope())
	case passed:
		a.held = append(a.held, ev.scope())
	}
	if err != nil {
		return module.Result{}, fmt.Errorf("%s: failed: %s: %w", ev.scope(), l, err)
	}
	if res.Status == module.Change {
		a.clock++
		for _, path := range p.paths {
			a.changed = append(a.changed, changeAt{path, a.clock})
		}
		var saved []string
		for _, s := range res.Saved {
			saved = append(saved, a.hide(s))
		}
		for i, g := range p.Guarded {
			if len(saved) == 0 {
				break
			}
			line := g.Line()
			j := slices.IndexFunc(a.putBack, func(b *putBack) bool { return b.line == line })
			if j < 0 {
				a.putBack = append(a.putBack, &putBack{line: line, label: p.guardedLabels[i]})
				j = len(a.putBack) - 1
			}
			b := a.putBack[j]
			for _, s := range saved {
				if !slices.Contains(b.paths, s) {
					b.paths = append(b.paths, s)
				}
			}
		}
		if res.Starts {
			a.clock++
			a.started[p.Step.Args.(*module.Service).Unit()] = a.clock
		}
		if err := a.pendGate(ctx); err != nil {
			return res, err
		}
	}
	return res, nil
}

// hide returns a mask of text from host with the secret parts of the
// evaluated steps of the host.
func (p *Plan) hide(host string) func(string) string {
	return func(s string) string { return secret.Hide(s, p.parts[host]) }
}
