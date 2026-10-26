// Package run plans and applies a pipeline on its hosts.
package run

import (
	"context"
	"fmt"
	"path"
	"slices"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
)

// Conn is a session with one host. The context of MakePlan and Apply ends at
// the first interrupt: they then start no new step. The calls of a Conn get a
// context that does not end, so a step that runs finishes.
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
	hash    string
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
	// Address is the scope, the number of the step in its list, and the loop
	// index: nginx#3[0]. A slot has the full name of its handler.
	Address string
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
	plan.hash = sumBytes(plan.HashInput())[:8]
	return plan
}

// check checks the steps of a stage on one host. At the first contact, it
// reads the facts and the pending handlers, and starts the host's
// evaluation.
func check(ctx context.Context, connect Connect, p *project.Project, h project.Host, stage *project.Stage, hr *hostRun, pending map[string]protocol.Pending) (steps []Planned, err error) {
	if ctx.Err() != nil {
		return nil, ErrInterrupted
	}
	conn, err := connect(context.WithoutCancel(ctx), p.Name, h)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	if hr.env == nil {
		f, err := conn.Facts(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		if hr.env, err = p.Start(h, f); err != nil {
			return nil, err
		}
		if pending[h.Name], err = conn.Pending(context.WithoutCancel(ctx)); err != nil {
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
		if ctx.Err() != nil {
			return nil, ErrInterrupted
		}
		steps[i].Result, err = conn.Check(context.WithoutCancel(ctx), p.Step.Module, p.Step.Args, &hr.state)
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
	add := func(st project.Step, in *project.Step, addr string) error {
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
			out = append(out, Planned{Step: s, In: in, Last: i == len(steps)-1, Notify: notify, Then: thenRecord(stage, in, s), Address: address(addr, st, i)})
		}
		return nil
	}
	for i := range stage.Steps {
		st := &stage.Steps[i]
		if st.Recipe == nil {
			if err := add(*st, nil, fmt.Sprintf("%s#%d", stage.Name, i+1)); err != nil {
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
		for j, rs := range st.Recipe.Steps {
			if err := add(rs, st, fmt.Sprintf("%s#%d", st.Recipe.Name, j+1)); err != nil {
				return nil, err
			}
		}
		for _, h := range st.Recipe.Handlers {
			slot, err := handlerSlot(stage, h, hr.env, st)
			if err != nil {
				return nil, err
			}
			out = append(out, Planned{In: st, Handler: slot, Address: h.FullName()})
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
			out = append(out, Planned{In: r, Handler: slot, Address: h.FullName()})
		}
	}
	return out, nil
}

// address is the address of the element i of the step st at addr.
func address(addr string, st project.Step, i int) string {
	if st.Loops() {
		return fmt.Sprintf("%s[%d]", addr, i)
	}
	return addr
}

// handlerSlot evaluates the steps of a handler for a host.
func handlerSlot(stage *project.Stage, h *project.Handler, env *project.Env, in *project.Step) (*Slot, error) {
	slot := &Slot{Handler: h}
	for j, hs := range h.Steps {
		steps, err := hs.Eval(env)
		if err != nil {
			return nil, err
		}
		addr := fmt.Sprintf("%s#%d", h.FullName(), j+1)
		for i, s := range steps {
			slot.Steps = append(slot.Steps, Planned{Step: s, In: in, Last: i == len(steps)-1, Then: thenRecord(stage, in, s), Address: address(addr, hs, i)})
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
	sum := sum(st.Then)
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
