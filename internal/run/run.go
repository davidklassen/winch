// Package run plans and applies a pipeline on its hosts.
package run

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/diff"
	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
)

// Conn is a session with one host.
type Conn interface {
	Facts(ctx context.Context) (facts.Facts, error)
	Pending(ctx context.Context) (protocol.Pending, error)
	Check(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error)
	// Apply records the handlers in notify and then on the host before it
	// changes something.
	Apply(ctx context.Context, name string, m module.Module, st *module.State, notify []string, then *protocol.Then) (module.Result, error)
	// Handled removes the record of a handler that succeeded.
	Handled(ctx context.Context, handler string) error
	// Command runs the command of a then, and then removes its record.
	Command(ctx context.Context, command string, then protocol.Then) error
	Close() error
}

// Connect opens a session with a host for the project named proj.
type Connect func(ctx context.Context, proj string, h project.Host) (Conn, error)

type Plan struct {
	// Project is the name of the project.
	Project string
	Stages  []StagePlan
	// Hosts are all hosts of the pipeline, in inventory order.
	Hosts  []project.Host
	Failed map[string]error
	// Pending are the records of each host, as the host reported them.
	Pending map[string]protocol.Pending
}

type StagePlan struct {
	Stage *project.Stage
	Hosts []HostPlan
}

// HostPlan holds the steps of a stage on one host, with their check results.
type HostPlan struct {
	Host  project.Host
	Steps []Planned
}

// Planned is a module step for one host, or a slot for a handler. In is the
// recipe step that the step or slot belongs to, or nil for a module step of
// the stage.
type Planned struct {
	Step   project.Step
	In     *project.Step
	Result module.Result
	// Last is true on the last element of a step with loop, and on a step
	// without loop.
	Last bool
	// Notify are the handlers that the step notifies on the host, as
	// <recipe>.<handler>.
	Notify []string
	// Handler is set on a slot. A slot has no step of its own.
	Handler *Slot
	// Then is the record of the step's then, or nil.
	Then *protocol.Then
	// PendingThen is true on the last element of a step whose then is
	// pending on the host.
	PendingThen bool
}

// Slot is a place where a handler runs when a step notified it, or when it is
// pending on the host.
type Slot struct {
	Handler *project.Handler
	Steps   []Planned
	// Runs is true when the plan expects the handler to run.
	Runs bool
}

// shows reports whether the plan shows p.
func (p Planned) shows() bool {
	return p.Result.Status == module.Change || p.Handler != nil && p.Handler.Runs || p.PendingThen
}

func (h HostPlan) changes() bool {
	return slices.ContainsFunc(h.Steps, Planned.shows)
}

// hostRun is what the plan keeps about a host between its stages.
type hostRun struct {
	state module.State
	// env is nil until the first contact with the host.
	env *project.Env
	// dirs are the directories that checked steps create, and the parents of
	// the paths they create.
	dirs map[string]bool
	// ran are the recipe steps that ran on the host, in order.
	ran []*project.Step
	// notified are the handlers that the plan expects to run later.
	notified map[string]bool
	// thens are the pending then records that no step matched yet.
	thens map[protocol.Then]bool
}

// MakePlan checks every step on every host, stage by stage. At the first
// contact with a host, it reads the facts and starts the host's evaluation.
// A host that fails stops there.
func MakePlan(ctx context.Context, p *project.Project, connect Connect) *Plan {
	plan := &Plan{Project: p.Name, Failed: map[string]error{}, Pending: map[string]protocol.Pending{}}
	inStages := map[string]bool{}
	runs := map[string]*hostRun{}
	for i := range p.Pipeline.Stages {
		stage := &p.Pipeline.Stages[i]
		sp := StagePlan{Stage: stage}
		for _, h := range stage.Targets {
			inStages[h.Name] = true
			if plan.Failed[h.Name] != nil {
				continue
			}
			if runs[h.Name] == nil {
				runs[h.Name] = &hostRun{dirs: map[string]bool{}, notified: map[string]bool{}, thens: map[protocol.Then]bool{}}
			}
			steps, err := check(ctx, connect, p, h, stage, runs[h.Name], plan.Pending)
			if err != nil {
				plan.Failed[h.Name] = err
				continue
			}
			sp.Hosts = append(sp.Hosts, HostPlan{Host: h, Steps: steps})
		}
		plan.Stages = append(plan.Stages, sp)
	}
	for _, h := range p.Inventory.Hosts {
		if inStages[h.Name] {
			plan.Hosts = append(plan.Hosts, h)
		}
	}
	return plan
}

// check checks the steps of a stage on one host. At the first contact, it
// reads the facts and the pending handlers, and starts the host's
// evaluation.
func check(ctx context.Context, connect Connect, p *project.Project, h project.Host, stage *project.Stage, hr *hostRun, pending map[string]protocol.Pending) (steps []Planned, err error) {
	conn, err := connect(ctx, p.Name, h)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	if hr.env == nil {
		f, err := conn.Facts(ctx)
		if err != nil {
			return nil, err
		}
		if hr.env, err = p.Start(h, f); err != nil {
			return nil, err
		}
		if pending[h.Name], err = conn.Pending(ctx); err != nil {
			return nil, err
		}
		for _, n := range pending[h.Name].Handlers {
			hr.notified[n] = true
		}
		for _, t := range pending[h.Name].Then {
			hr.thens[t] = true
		}
	}
	steps, err = evaluate(stage, hr)
	if err != nil {
		return nil, err
	}
	for i, p := range steps {
		if s := p.Handler; s != nil {
			name := s.Handler.FullName()
			s.Runs = hr.notified[name]
			delete(hr.notified, name)
			continue
		}
		steps[i].Result, err = conn.Check(ctx, p.Step.Module, p.Step.Args, &hr.state)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", scope(stage, p), label(p.Step), err)
		}
		hr.dropCreatedParents(p.Step.Args, &steps[i].Result)
		if steps[i].Result.Status == module.Change {
			for _, n := range p.Notify {
				hr.notified[n] = true
			}
		}
		if p.Last && p.Then != nil && hr.thens[*p.Then] {
			steps[i].PendingThen = true
			delete(hr.thens, *p.Then)
		}
	}
	return steps, nil
}

// dropCreatedParents removes the parent lines of directories that an earlier
// step creates. Each check sees the host as it is before the run, and apply
// creates a directory once.
func (hr *hostRun) dropCreatedParents(m module.Module, res *module.Result) {
	if res.Action != module.Create {
		return
	}
	var p string
	switch m := m.(type) {
	case *module.File:
		p = m.Path
	case *module.Dir:
		p = m.Path
	case *module.Link:
		p = m.Path
	default:
		return
	}
	for d := path.Dir(p); d != "/"; d = path.Dir(d) {
		if hr.dirs[d] {
			line := module.ParentChange(d)
			res.Changes = slices.DeleteFunc(res.Changes, func(c string) bool { return c == line })
		}
		hr.dirs[d] = true
	}
	if _, ok := m.(*module.Dir); ok {
		hr.dirs[p] = true
	}
}

// evaluate returns the module steps of a stage for one host, with recipe
// steps, when, and loop applied. A slot for each handler of a recipe follows
// the recipe's steps. A handler of a recipe that ran before a step of the
// stage notifies it gets a slot at the end of the stage.
func evaluate(stage *project.Stage, hr *hostRun) ([]Planned, error) {
	var out []Planned
	late := map[*project.Handler]bool{}
	add := func(st project.Step, in *project.Step) error {
		steps, err := st.Eval(hr.env)
		if err != nil {
			return err
		}
		var notify []string
		for _, h := range st.Notify {
			// A recipe that does not run on the host never runs its handler.
			if !hr.env.Runs(h.Recipe.Name) {
				continue
			}
			notify = append(notify, h.FullName())
			if slices.ContainsFunc(hr.ran, func(r *project.Step) bool { return r.Recipe == h.Recipe }) {
				late[h] = true
			}
		}
		for i, s := range steps {
			out = append(out, Planned{Step: s, In: in, Last: i == len(steps)-1, Notify: notify, Then: thenRecord(stage, in, s)})
		}
		return nil
	}
	for i := range stage.Steps {
		st := &stage.Steps[i]
		if st.Recipe == nil {
			if err := add(*st, nil); err != nil {
				return nil, err
			}
			continue
		}
		ok, err := st.Runs(hr.env)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		for _, rs := range st.Recipe.Steps {
			if err := add(rs, st); err != nil {
				return nil, err
			}
		}
		for _, h := range st.Recipe.Handlers {
			slot, err := handlerSlot(stage, h, hr.env, st)
			if err != nil {
				return nil, err
			}
			out = append(out, Planned{In: st, Handler: slot})
		}
		hr.ran = append(hr.ran, st)
	}
	for _, r := range hr.ran {
		for _, h := range r.Recipe.Handlers {
			if !late[h] {
				continue
			}
			slot, err := handlerSlot(stage, h, hr.env, r)
			if err != nil {
				return nil, err
			}
			out = append(out, Planned{In: r, Handler: slot})
		}
	}
	return out, nil
}

// handlerSlot evaluates the steps of a handler for a host.
func handlerSlot(stage *project.Stage, h *project.Handler, env *project.Env, in *project.Step) (*Slot, error) {
	slot := &Slot{Handler: h}
	for _, hs := range h.Steps {
		steps, err := hs.Eval(env)
		if err != nil {
			return nil, err
		}
		for i, s := range steps {
			slot.Steps = append(slot.Steps, Planned{Step: s, In: in, Last: i == len(steps)-1, Then: thenRecord(stage, in, s)})
		}
	}
	return slot, nil
}

// HasChanges reports whether a host that did not fail has changes.
func (p *Plan) HasChanges() bool {
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			if p.Failed[hp.Host.Name] == nil && hp.changes() {
				return true
			}
		}
	}
	return false
}

// scope is the recipe of a step, or the stage for a module step of a stage.
func scope(stage *project.Stage, p Planned) string {
	if p.In != nil {
		return secret.Printable(p.In.Recipe.Name)
	}
	return secret.Printable(stage.Name)
}

// thenRecord is the record of the then of st in the recipe step in, or nil
// for a step without then.
func thenRecord(stage *project.Stage, in *project.Step, st project.Step) *protocol.Then {
	if st.Then == "" {
		return nil
	}
	b := sha256.Sum256([]byte(st.Then))
	sum := hex.EncodeToString(b[:])
	if in != nil {
		return &protocol.Then{Recipe: in.Recipe.Name, SHA256: sum}
	}
	return &protocol.Then{Stage: stage.Name, SHA256: sum}
}

// label is the text of a step in the plan and the logs.
func label(st project.Step) string {
	l := st.Module + " " + st.ShownMain()
	if st.Name != "" {
		l = st.Name + ": " + l
	}
	return secret.Printable(l)
}

var marks = map[module.Action]string{module.Create: "+", module.Modify: "~", module.Remove: "-"}

// Write prints the changes per host, hosts with the same changes together,
// then the summary. Failures go to errOut.
func (p *Plan) Write(out, errOut io.Writer) {
	bodies := map[string]*strings.Builder{}
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			if !hp.changes() {
				continue
			}
			b := bodies[hp.Host.Name]
			if b == nil {
				b = &strings.Builder{}
				bodies[hp.Host.Name] = b
			}
			fmt.Fprintf(b, "  %s\n", secret.Printable(sp.Stage.Name))
			var in *project.Step
			for _, p := range hp.Steps {
				if !p.shows() {
					continue
				}
				indent := "    "
				if p.In != nil {
					if p.In != in {
						fmt.Fprintf(b, "    %s\n", recipeLabel(p.In))
					}
					indent = "      "
				}
				in = p.In
				if p.Handler != nil {
					fmt.Fprintf(b, "%s! handler %s\n", indent, secret.Printable(p.Handler.Handler.FullName()))
					continue
				}
				if p.Result.Status == module.Change {
					writeStep(b, indent, p.Step, p.Result)
				}
				if p.PendingThen {
					fmt.Fprintf(b, "%s! then: %s\n", indent, secret.Printable(p.Step.ShownThen()))
				}
			}
		}
	}
	type group struct {
		hosts []string
		body  string
	}
	var groups []*group
	changed := 0
	for _, h := range p.Hosts {
		b := bodies[h.Name]
		if b == nil || p.Failed[h.Name] != nil {
			continue
		}
		changed++
		i := slices.IndexFunc(groups, func(g *group) bool { return g.body == b.String() })
		if i < 0 {
			groups = append(groups, &group{body: b.String()})
			i = len(groups) - 1
		}
		groups[i].hosts = append(groups[i].hosts, h.Name)
	}
	for _, g := range groups {
		header := strings.Join(g.hosts, ", ")
		if len(g.hosts) > 1 {
			header += fmt.Sprintf(" (%d hosts)", len(g.hosts))
		}
		fmt.Fprintf(out, "%s\n%s\n", header, g.body)
	}
	for _, h := range p.Hosts {
		if err := p.Failed[h.Name]; err != nil {
			fmt.Fprintf(errOut, "%s: %v\n", h.Name, err)
		}
	}
	failed := len(p.Failed)
	fmt.Fprintf(out, "%s: %d to change, %d unchanged, 0 unknown%s\n",
		hosts(len(p.Hosts)), changed, len(p.Hosts)-changed-failed, failures(failed))
}

func recipeLabel(st *project.Step) string {
	l := st.Recipe.Name
	if st.Name != "" {
		l += ": " + st.Name
	}
	return secret.Printable(l)
}

func writeStep(w io.Writer, indent string, st project.Step, res module.Result) {
	l := label(st)
	if res.Link != "" {
		l += " (link to " + secret.Printable(res.Link) + ")"
	}
	fmt.Fprintf(w, "%s%s %s\n", indent, marks[res.Action], l)
	for _, c := range res.Changes {
		fmt.Fprintf(w, "%s    %s\n", indent, secret.Printable(c))
	}
	t, ok := st.Args.(module.WithContent)
	if res.Old == nil || !ok {
		return
	}
	text := t.Text()
	var d []byte
	switch {
	case text == nil:
		fmt.Fprintf(w, "%s    content (binary or larger than 1 MiB)\n", indent)
		return
	case st.Shown != nil && st.Shown.Hidden:
		d = []byte(secret.Mark + "\n")
	case st.Shown != nil && st.Shown.Lines != nil:
		d = secret.Diff([]byte(*res.Old), st.Shown.Lines)
	default:
		d = diff.Diff([]byte(*res.Old), []byte(*text))
	}
	for _, line := range strings.SplitAfter(string(d), "\n") {
		if line != "" {
			fmt.Fprintf(w, "%s    %s\n", indent, secret.Printable(strings.TrimSuffix(line, "\n")))
		}
	}
}

func hosts(n int) string {
	if n == 1 {
		return "1 host"
	}
	return fmt.Sprintf("%d hosts", n)
}

func failures(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d failed", n)
}

// Apply applies every stage of a plan on the hosts with a change in the plan.
// A stage can undo what an earlier stage does, so a stage without a change
// runs too. Each step is checked again right before it is applied, and the
// handlers follow what apply changes. Failures go to errOut. It returns false
// when a host failed, in the plan or in the apply.
func Apply(ctx context.Context, plan *Plan, connect Connect, out, errOut io.Writer) bool {
	failed := map[string]bool{}
	for name := range plan.Failed {
		failed[name] = true
	}
	toApply := map[string]bool{}
	for _, sp := range plan.Stages {
		for _, hp := range sp.Hosts {
			if hp.changes() {
				toApply[hp.Host.Name] = true
			}
		}
	}
	changed := map[string]bool{}
	runs := map[string]*hostApply{}
	for _, sp := range plan.Stages {
		for _, hp := range sp.Hosts {
			name := hp.Host.Name
			if !toApply[name] || failed[name] {
				continue
			}
			if runs[name] == nil {
				runs[name] = &hostApply{host: name, out: out, notified: map[string]bool{}, thens: map[protocol.Then]bool{}}
				for _, n := range plan.Pending[name].Handlers {
					runs[name].notified[n] = true
				}
				for _, t := range plan.Pending[name].Then {
					runs[name].thens[t] = true
				}
			}
			ok, err := runs[name].apply(ctx, connect, plan.Project, sp.Stage, hp)
			if err != nil {
				fmt.Fprintf(errOut, "%s: %v\n", name, err)
				failed[name] = true
				delete(changed, name)
				continue
			}
			if ok {
				changed[name] = true
			}
		}
	}
	fmt.Fprintf(out, "\n%s: %d changed, %d unchanged%s\n", hosts(len(plan.Hosts)),
		len(changed), len(plan.Hosts)-len(changed)-len(failed), failures(len(failed)))
	return len(failed) == 0
}

// hostApply is what apply keeps about a host between its stages.
type hostApply struct {
	host  string
	out   io.Writer
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
	a.conn, err = connect(ctx, proj, hp.Host)
	if err != nil {
		return false, fmt.Errorf("failed: %w", err)
	}
	defer func() {
		if cerr := a.conn.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("failed: %w", cerr)
		}
	}()
	return a.steps(ctx, func(p Planned) string { return scope(stage, p) }, "", hp.Steps)
}

// steps applies steps and runs the handlers of their slots. A step runs its
// then after its last element when an element changed something, or when its
// then is pending on the host.
func (a *hostApply) steps(ctx context.Context, scope func(Planned) string, prefix string, steps []Planned) (changed bool, err error) {
	// changedLabel is the label of the last element of the current step that
	// changed something, or "".
	changedLabel := ""
	for _, p := range steps {
		if p.Handler != nil {
			c, err := a.handler(ctx, p.Handler)
			changed = changed || c
			if err != nil {
				return changed, err
			}
			continue
		}
		l := prefix + label(p.Step)
		c, err := a.step(ctx, scope(p), l, p)
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
		if err := a.conn.Command(ctx, p.Step.Then, *t); err != nil {
			return changed, fmt.Errorf("%s: failed: %s: then: %w", scope(p), failLabel, err)
		}
		if a.thens[*t] {
			fmt.Fprintf(a.out, "%s: %s: ! then: %s\n", a.host, scope(p), secret.Printable(p.Step.ShownThen()))
			delete(a.thens, *t)
			changed = true
		}
	}
	return changed, nil
}

// handler runs the steps of a slot's handler when it was notified, and then
// removes its record on the host.
func (a *hostApply) handler(ctx context.Context, s *Slot) (bool, error) {
	name := s.Handler.FullName()
	if !a.notified[name] {
		return false, nil
	}
	recipe := secret.Printable(s.Handler.Recipe.Name)
	changed, err := a.steps(ctx, func(Planned) string { return recipe }, "handler "+secret.Printable(name)+": ", s.Steps)
	if err != nil {
		return changed, err
	}
	if err := a.conn.Handled(ctx, name); err != nil {
		return changed, fmt.Errorf("%s: failed: handler %s: %w", recipe, secret.Printable(name), err)
	}
	delete(a.notified, name)
	return changed, nil
}

// step applies one element of a step with the label l. It reports a change.
func (a *hostApply) step(ctx context.Context, scope, l string, p Planned) (bool, error) {
	res, err := a.conn.Apply(ctx, p.Step.Module, p.Step.Args, &a.state, p.Notify, p.Then)
	if err != nil {
		return false, fmt.Errorf("%s: failed: %s: %w", scope, l, err)
	}
	if res.Status != module.Change {
		return false, nil
	}
	fmt.Fprintf(a.out, "%s: %s: %s %s\n", a.host, scope, marks[res.Action], l)
	for _, n := range p.Notify {
		a.notified[n] = true
	}
	return true, nil
}
