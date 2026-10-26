// Package run plans and applies a pipeline on its hosts.
package run

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

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
	// Health runs a health gate.
	Health(ctx context.Context, h protocol.Health) error
	Close() error
}

// Options are the choices of a run.
type Options struct {
	// Serial starts the sessions one at a time, in inventory order, so ssh
	// can ask its questions on the terminal.
	Serial bool
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
	opts    Options
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
	// ThenRuns is true on the last element of a step whose then the plan
	// expects to run: an element changes, or the then is pending.
	ThenRuns bool
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
	return p.Result.Status == module.Change || p.Handler != nil && p.Handler.Runs || p.ThenRuns
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
	// pending are the records that the host reported at the first contact.
	pending *protocol.Pending
	// conn is the session with the host, open across its stages.
	conn Conn
	// needs are the users and groups, as "user <name>" or "group <name>",
	// that changed steps need, with the first such step.
	needs map[string]string
}

// close closes the session with the host, if one is open.
func (hr *hostRun) close() error {
	if hr.conn == nil {
		return nil
	}
	err := hr.conn.Close()
	hr.conn = nil
	return err
}

// MakePlan checks every step on every host, stage by stage. The hosts of a
// stage run at the same time. At the first contact with a host, it reads the
// facts and starts the host's evaluation. A host that fails stops there.
func MakePlan(ctx context.Context, p *project.Project, connect Connect, opts Options) *Plan {
	plan := &Plan{Project: p.Name, Failed: map[string]error{}, Pending: map[string]protocol.Pending{}, opts: opts}
	inStages := map[string]bool{}
	runs := map[string]*hostRun{}
	open := func(h project.Host) (Conn, error) {
		hr := runs[h.Name]
		if hr.conn == nil {
			c, err := connect(context.WithoutCancel(ctx), p.Name, h)
			if err != nil {
				return nil, err
			}
			hr.conn = c
		}
		return hr.conn, nil
	}
	last := map[string]int{}
	for i, stage := range p.Pipeline.Stages {
		if !stage.Skipped {
			for _, h := range stage.Targets {
				last[h.Name] = i
			}
		}
	}
	for si := range p.Pipeline.Stages {
		stage := &p.Pipeline.Stages[si]
		if stage.Skipped {
			continue
		}
		var hosts []project.Host
		for _, h := range stage.Targets {
			inStages[h.Name] = true
			if plan.Failed[h.Name] != nil {
				continue
			}
			hosts = append(hosts, h)
			if runs[h.Name] == nil {
				runs[h.Name] = &hostRun{dirs: map[string]bool{}, notified: map[string]bool{}, thens: map[protocol.Then]bool{}, needs: map[string]string{}}
			}
		}
		steps := make([][]Planned, len(hosts))
		errs := rollout(ctx, stage.Name, hosts, 0, opts.Serial, open, func(i int, conn Conn) error {
			hr := runs[hosts[i].Name]
			var err error
			steps[i], err = check(ctx, conn, p, hosts[i], stage, hr)
			if err != nil || last[hosts[i].Name] == si {
				if cerr := hr.close(); err == nil {
					err = cerr
				}
			}
			return err
		})
		sp := StagePlan{Stage: stage}
		for i, h := range hosts {
			if errs[i] != nil {
				runs[h.Name].close() //nolint:errcheck // the host failed already
				plan.Failed[h.Name] = errs[i]
				continue
			}
			sp.Hosts = append(sp.Hosts, HostPlan{Host: h, Steps: steps[i]})
		}
		plan.Stages = append(plan.Stages, sp)
	}
	for name, hr := range runs {
		if hr.pending != nil {
			plan.Pending[name] = *hr.pending
		}
	}
	for _, h := range p.Inventory.Hosts {
		if inStages[h.Name] {
			plan.Hosts = append(plan.Hosts, h)
		}
	}
	plan.hash = sumBytes(plan.HashInput())[:16]
	return plan
}

// check checks the steps of a stage on one host. At the first contact, it
// reads the facts and the pending handlers, and starts the host's evaluation.
func check(ctx context.Context, conn Conn, p *project.Project, h project.Host, stage *project.Stage, hr *hostRun) ([]Planned, error) {
	if hr.env == nil {
		f, err := conn.Facts(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		if hr.env, err = p.Start(h, f); err != nil {
			return nil, err
		}
		pending, err := conn.Pending(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		hr.pending = &pending
		for _, n := range pending.Handlers {
			hr.notified[n] = true
		}
		for _, t := range pending.Then {
			hr.thens[t] = true
		}
	}
	steps, err := evaluate(stage, hr)
	if err != nil {
		return nil, err
	}
	changed := false
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
		if err := hr.order(p.Step.Args, steps[i].Result, scope(stage, p)+": "+label(p.Step)); err != nil {
			return nil, err
		}
		hr.dropCreatedParents(p.Step.Args, &steps[i].Result)
		// The old answer can be an older secret, which the text filter does
		// not know.
		if _, ok := p.Step.Args.(*module.Debconf); ok && p.Step.Secret && steps[i].Result.Status == module.Change {
			steps[i].Result.Changes = []string{"answer (secret)"}
		}
		if steps[i].Result.Status == module.Change {
			changed = true
			for _, n := range p.Notify {
				hr.notified[n] = true
			}
		}
		if !p.Last {
			continue
		}
		if p.Then != nil && hr.thens[*p.Then] {
			steps[i].PendingThen = true
			delete(hr.thens, *p.Then)
		}
		steps[i].ThenRuns = p.Then != nil && (changed || steps[i].PendingThen)
		changed = false
	}
	return steps, nil
}

// order fails a user or group step that creates a user or a group that an
// earlier changed step needs as its owner or group: that step fails in
// apply. Otherwise it records what the step at where needs.
func (hr *hostRun) order(m module.Module, res module.Result, where string) error {
	if res.Status != module.Change {
		return nil
	}
	var needs, created []string
	switch m := m.(type) {
	case *module.File:
		needs = []string{"user " + string(m.Owner), "group " + string(m.Group)}
	case *module.Dir:
		needs = []string{"user " + string(m.Owner), "group " + string(m.Group)}
	case *module.User:
		needs = []string{"group " + string(m.Group)}
		if res.Action == module.Create {
			created = []string{"user " + m.Name}
		}
		// useradd -U creates the group.
		if slices.Contains(res.Changes, "group "+m.Name+" (new)") {
			created = append(created, "group "+m.Name)
		}
	case *module.Group:
		if res.Action == module.Create {
			created = []string{"group " + m.Name}
		}
	}
	for _, c := range created {
		if w, ok := hr.needs[c]; ok {
			return fmt.Errorf("%s: an earlier step needs it: %s; move this step before it", where, w)
		}
	}
	for _, n := range needs {
		_, name, _ := strings.Cut(n, " ")
		if _, err := strconv.ParseUint(name, 10, 32); name == "" || err == nil {
			continue
		}
		if _, ok := hr.needs[n]; !ok {
			hr.needs[n] = where
		}
	}
	return nil
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
	add := func(env *project.Env, st project.Step, in *project.Step, addr string) error {
		steps, err := st.Eval(env)
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
			if err := add(hr.env, *st, nil, fmt.Sprintf("%s#%d", stage.Name, i+1)); err != nil {
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
		env := hr.env.For(st)
		for j, rs := range st.Recipe.Steps {
			if err := add(env, rs, st, fmt.Sprintf("%s#%d", st.Recipe.Name, j+1)); err != nil {
				return nil, err
			}
		}
		for _, h := range st.Recipe.Handlers {
			slot, err := handlerSlot(stage, h, env, st)
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
			slot, err := handlerSlot(stage, h, hr.env.For(r), r)
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
		return p.In.Recipe.Name
	}
	return stage.Name
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
