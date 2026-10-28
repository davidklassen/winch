// Package run plans and applies a pipeline on its hosts.
package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

// Conn is a session with one host. The context of MakePlan and Apply ends at
// the first interrupt: they then start no new step. The calls of a Conn get a
// context that does not end, so a step that runs finishes. Exec gets the
// context of the run: an interrupt stops its command.
type Conn interface {
	Destination() protocol.Destination
	Facts(ctx context.Context) (facts.Facts, error)
	Pending(ctx context.Context) (protocol.Pending, error)
	Check(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error)
	// Apply records the handlers in notify and then on the host before it
	// changes something. It guards the step against a lockout as guard says.
	Apply(ctx context.Context, name string, m module.Module, st *module.State, notify []string, then *protocol.Then, guard protocol.Guard) (module.Result, error)
	// Access opens a second SSH connection and runs a command that needs the
	// login and sudo.
	Access(ctx context.Context) error
	// Confirm stops the rollback timer of the last apply.
	Confirm(ctx context.Context) error
	// Rollback ends the rollback timer at once: the old files come back.
	Rollback(ctx context.Context) error
	// Reboot reboots the host and connects again within wait.
	Reboot(ctx context.Context, wait time.Duration) (protocol.Boot, error)
	// Handled removes the record of a handler that succeeded.
	Handled(ctx context.Context, handler string) error
	// Command runs the command of a then, and then removes its record.
	Command(ctx context.Context, command string, then protocol.Then) error
	// Health runs a health gate.
	Health(ctx context.Context, h protocol.Health) error
	Exec(ctx context.Context, command string) (module.ExecResult, error)
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
	// Destinations are the destinations of the hosts, as their sessions
	// reported them.
	Destinations map[string]protocol.Destination
	hash         string
	opts         Options
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

// shows reports whether the plan shows p as something that apply changes or
// runs: a change, an unknown step, a handler, or a then.
func (p Planned) shows() bool {
	return p.Result.Status == module.Change || p.Result.Status == module.Unknown || p.Handler != nil && p.Handler.Runs || p.ThenRuns
}

func (h HostPlan) changes() bool {
	return slices.ContainsFunc(h.Steps, Planned.shows)
}

// known reports whether the plan shows a line other than an unknown step.
func (h HostPlan) known() bool {
	return slices.ContainsFunc(h.Steps, func(p Planned) bool {
		return p.shows() && (p.Result.Status != module.Unknown || p.PendingThen)
	})
}

// deferred reports whether a step runs in apply without a change.
func (h HostPlan) deferred() bool {
	return slices.ContainsFunc(h.Steps, func(p Planned) bool { return p.Result.Deferred })
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
	dest protocol.Destination
	// needs are the users, groups, and directories, as "user <name>",
	// "group <name>", or "dir <path>", that steps that run need, with the
	// first such step.
	needs map[string]string
	// units are the units that service steps name.
	units map[string]bool
	// startedBy are the errors for units that start a unit that a service
	// step stops or disables, while no service step names them.
	startedBy []startedBy
	// removed are the paths of the checked absent steps.
	removed []string
	// unitFiles are the contents of the unit files that checked unit steps
	// change, by name.
	unitFiles map[string][]byte
	// sources are the URIs and suites of repo steps, with the first step.
	sources map[string]string
	// managed are the paths, packages, units, users, and groups of the
	// checked steps, with the first step and its arguments.
	managed map[string]managed
	// lines are the checked line steps, by path.
	lines map[string][]lineStep
	// pkgs are the checked pkg steps.
	pkgs []pkgStep
	// written returns the paths that the project writes on the host, for dir
	// steps with purge. It is set at the first contact.
	written func() ([]string, error)
}

type managed struct {
	where  string
	module string
	args   module.Module
}

type lineStep struct {
	where string
	line  *module.Line
	re    *regexp.Regexp
}

// pkgStep is a checked pkg step. others are the other packages that it
// installs or upgrades, or that it removes. installs are the packages that it
// installs in this run.
type pkgStep struct {
	where    string
	pkg      *module.Pkg
	others   []string
	installs []string
}

type startedBy struct {
	unit string
	err  error
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
	plan := &Plan{Project: p.Name, Failed: map[string]error{}, Pending: map[string]protocol.Pending{}, Destinations: map[string]protocol.Destination{}, opts: opts}
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
			hr.dest = c.Destination()
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
				runs[h.Name] = &hostRun{dirs: map[string]bool{}, notified: map[string]bool{}, thens: map[protocol.Then]bool{}, needs: map[string]string{}, units: map[string]bool{}, unitFiles: map[string][]byte{}, sources: map[string]string{}, managed: map[string]managed{}, lines: map[string][]lineStep{}}
			}
		}
		steps := make([][]Planned, len(hosts))
		errs := rollout(ctx, stage.Name, hosts, 0, opts.Serial, open, func(i int, conn Conn) error {
			hr := runs[hosts[i].Name]
			var err error
			steps[i], err = check(ctx, conn, p, hosts[i], stage, hr)
			if err == nil && last[hosts[i].Name] == si {
				for _, s := range hr.startedBy {
					err = errors.Join(err, s.err)
				}
			}
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
		plan.Destinations[name] = hr.dest
	}
	for _, h := range p.Inventory.Hosts {
		if inStages[h.Name] {
			plan.Hosts = append(plan.Hosts, h)
		}
	}
	plan.suppressMissingUnitFiles()
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
		hr.written = sync.OnceValues(func() ([]string, error) { return p.Written(h, f) })
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
			name := s.Handler.Record()
			s.Runs = hr.notified[name]
			delete(hr.notified, name)
			if s.Runs {
				for j, hs := range s.Steps {
					if hs.Last && hs.Then != nil && hr.thens[*hs.Then] {
						s.Steps[j].PendingThen = true
						delete(hr.thens, *hs.Then)
					}
				}
			}
			continue
		}
		if ctx.Err() != nil {
			return nil, ErrInterrupted
		}
		where := scope(stage, p) + ": " + label(p.Step)
		if err := hr.repo(&steps[i].Step, where); err != nil {
			return nil, err
		}
		hr.removedPkgs(&steps[i].Step)
		if err := hr.same(p.Step, where); err != nil {
			return nil, err
		}
		hr.newUnitFile(&steps[i].Step)
		steps[i].Result, err = conn.Check(context.WithoutCancel(ctx), p.Step.Module, steps[i].Step.Args, &hr.state)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		hr.trackRemoved(p.Step.Args)
		hr.trackUnitFile(p.Step.Args, steps[i].Result)
		if err := hr.order(p.Step.Args, steps[i].Result, where); err != nil {
			return nil, err
		}
		if err := hr.packages(p.Step.Args, steps[i].Result, where); err != nil {
			return nil, err
		}
		hr.dropCreatedParents(p.Step.Args, &steps[i].Result)
		hr.trackUnits(p.Step.Args, steps[i].Result, where)
		// The old answer can be an older secret, which the text filter does
		// not know.
		if _, ok := p.Step.Args.(*module.Debconf); ok && p.Step.Secret && steps[i].Result.Status == module.Change {
			steps[i].Result.Changes = []string{"answer (secret)"}
		}
		if _, ok := p.Step.Args.(*module.Certbot); ok && p.Step.Secret {
			for j, c := range steps[i].Result.Changes {
				if key, _, _ := strings.Cut(c, " "); strings.HasSuffix(key, "_hook") {
					steps[i].Result.Changes[j] = key + " (secret)"
				}
			}
		}
		if steps[i].Result.Status != module.OK {
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

// order fails a step that creates a user, a group, or a directory that an
// earlier step that runs needs: as its owner, group, one of its groups, or the
// user or directory of a cmd. That earlier step fails in apply. Otherwise it
// records what the step at where needs.
func (hr *hostRun) order(m module.Module, res module.Result, where string) error {
	if res.Status == module.OK {
		return nil
	}
	var needs, created []string
	for n := range hr.needs {
		if d, ok := strings.CutPrefix(n, "dir "); ok && slices.Contains(res.Changes, module.ParentChange(d)) {
			created = append(created, n)
		}
	}
	slices.Sort(created)
	switch m := m.(type) {
	case *module.Cmd:
		needs = []string{"user " + m.User}
		if !hr.dirs[m.Dir] {
			needs = append(needs, "dir "+m.Dir)
		}
	case *module.File:
		needs = []string{"user " + string(m.Owner), "group " + string(m.Group)}
	case *module.Dir:
		needs = []string{"user " + string(m.Owner), "group " + string(m.Group)}
		if res.Action == module.Create {
			created = append(created, "dir "+m.Path)
		}
	case *module.Download:
		needs = []string{"user " + string(m.Owner), "group " + string(m.Group)}
	case *module.User:
		needs = []string{"group " + string(m.Group)}
		if m.Groups != nil {
			for _, g := range *m.Groups {
				needs = append(needs, "group "+g)
			}
		}
		if res.Action == module.Create {
			created = append(created, "user "+m.Name)
		}
		// useradd -U creates the group.
		if slices.Contains(res.Changes, "group "+m.Name+" (new)") {
			created = append(created, "group "+m.Name)
		}
	case *module.Group:
		if res.Action == module.Create {
			created = append(created, "group "+m.Name)
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
	// Directories that exist after the step, which dropCreatedParents does
	// not see.
	var made []string
	switch m := m.(type) {
	case *module.Cmd:
		if m.Creates != "" {
			made = []string{path.Dir(m.Creates)}
		}
	case *module.User:
		if w := m.Writes(); w != nil {
			made = w[:1]
		}
	case *module.Download:
		if m.Unpack != "" {
			made = []string{m.Unpack}
		}
	}
	for _, d := range made {
		for ; d != "/"; d = path.Dir(d) {
			hr.dirs[d] = true
		}
	}
	return nil
}

// repo fails a repo step whose source an earlier repo step of the host has.
// Otherwise it gives the step the paths that earlier steps remove.
func (hr *hostRun) repo(st *project.Step, where string) error {
	r, ok := st.Args.(*module.Repo)
	if !ok {
		return nil
	}
	key := r.Source()
	if w, ok := hr.sources[key]; ok {
		return fmt.Errorf("%s: the source %s %s is also in %s; use one step", where, r.URL, r.Suite, w)
	}
	hr.sources[key] = where
	c := *r
	c.Removed = hr.removed
	st.Args = &c
	return nil
}

// removedPkgs gives a pkg step the packages that earlier absent pkg steps of
// the host remove, with the packages that apt removes with them.
func (hr *hostRun) removedPkgs(st *project.Step) {
	p, ok := st.Args.(*module.Pkg)
	if !ok || p.Absent {
		return
	}
	var removed []string
	for _, e := range hr.pkgs {
		if e.pkg.Absent {
			removed = slices.Concat(removed, e.pkg.Name, e.others)
		}
	}
	c := *p
	c.Removed = removed
	st.Args = &c
}

// same fails a step that manages a path, package, unit, user, or group that
// an earlier step of the host manages with other arguments. The host would
// change on every run.
func (hr *hostRun) same(st project.Step, where string) error {
	add := func(thing string, args module.Module) error {
		m, ok := hr.managed[thing]
		if !ok {
			hr.managed[thing] = managed{where, st.Module, args}
			return nil
		}
		a, err := json.Marshal(m.args)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		b, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if m.module != st.Module || !bytes.Equal(a, b) {
			return fmt.Errorf("%s: %s is also in %s, with other arguments", where, thing, m.where)
		}
		return nil
	}
	switch m := st.Args.(type) {
	case *module.File, *module.Dir, *module.Link, *module.Download:
		return add("the path "+m.Main(), m)
	case *module.Unit:
		return add("the path "+m.Path(), m)
	case *module.Pkg:
		for _, n := range m.Name {
			c := *m
			c.Name = yamlx.Strings{n}
			if err := add("the package "+n, &c); err != nil {
				return err
			}
		}
	case *module.Service:
		c := *m
		c.Name = m.Unit()
		return add("the unit "+c.Name, &c)
	case *module.Line:
		// Line steps on one path share this entry; another module's step on
		// the path fails.
		if err := add("the path "+m.Path, &module.Line{Path: m.Path}); err != nil {
			return err
		}
		return hr.overlap(m, where)
	case *module.User:
		return add("the user "+m.Name, m)
	case *module.Group:
		return add("the group "+m.Name, m)
	case *module.Hostname:
		return add("the host name", m)
	case *module.Timezone:
		return add("the time zone", m)
	case *module.Certbot:
		return add("the certificate "+m.Name, m)
	}
	return nil
}

// overlap fails a line step when its match finds the line of an earlier line
// step on the path, or the earlier step's match finds its line, and the lines
// differ. The error leaves out the lines: a line can hold a secret.
func (hr *hostRun) overlap(l *module.Line, where string) error {
	re, err := regexp.Compile(l.Match)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	for _, e := range hr.lines[l.Path] {
		el := e.line
		if el.Line == l.Line {
			continue
		}
		if !el.Absent && re.MatchString(el.Line) {
			return fmt.Errorf("%s: the match %q finds the line of %s; the two steps change it on every run", where, l.Match, e.where)
		}
		if !l.Absent && e.re.MatchString(l.Line) {
			return fmt.Errorf("%s: the match %q of %s finds the line of this step; the two steps change it on every run", where, el.Match, e.where)
		}
	}
	hr.lines[l.Path] = append(hr.lines[l.Path], lineStep{where, l, re})
	return nil
}

// packages fails a pkg step that undoes another pkg step of the host: a
// removal takes a package that the other step installs, or an install pulls a
// package that the other step removes. It fails a debconf step whose package
// an earlier step installs in this run: the install read the old answer.
func (hr *hostRun) packages(m module.Module, res module.Result, where string) error {
	switch m := m.(type) {
	case *module.Debconf:
		for _, s := range hr.pkgs {
			if slices.Contains(s.installs, m.Package) {
				return fmt.Errorf("%s: %s installs %s before this step sets the answer; move this step before it", where, s.where, m.Package)
			}
		}
	case *module.Pkg:
		cur := pkgStep{where: where, pkg: m}
		cur.installs, cur.others = module.PkgPlan(res.Changes)
		self := cur
		self.where = "this step"
		for _, e := range hr.pkgs {
			if e.pkg.Absent == m.Absent {
				continue
			}
			gone, kept := e, self
			if m.Absent {
				gone, kept = self, e
			}
			for _, n := range gone.others {
				if slices.Contains(kept.pkg.Name, n) {
					return fmt.Errorf("%s: %s also removes %s, which %s installs; the two steps undo each other on every run", where, gone.where, n, kept.where)
				}
			}
			for _, n := range kept.others {
				if slices.Contains(gone.pkg.Name, n) {
					return fmt.Errorf("%s: %s also installs %s, which %s removes; the two steps undo each other on every run", where, kept.where, n, gone.where)
				}
			}
		}
		hr.pkgs = append(hr.pkgs, cur)
	}
	return nil
}

// newUnitFile gives a service step the unit file that an earlier unit step of
// the host changes.
func (hr *hostRun) newUnitFile(st *project.Step) {
	sv, ok := st.Args.(*module.Service)
	if !ok {
		return
	}
	data, ok := hr.unitFiles[sv.UnitFile()]
	if !ok {
		return
	}
	c := *sv
	c.NewFile = data
	st.Args = &c
}

// trackUnitFile records the unit file of a unit step that changes it.
func (hr *hostRun) trackUnitFile(m module.Module, res module.Result) {
	if u, ok := m.(*module.Unit); ok && res.Status == module.Change {
		hr.unitFiles[u.Name] = u.Data
	}
}

// trackRemoved records the path of an absent step.
func (hr *hostRun) trackRemoved(m module.Module) {
	switch m := m.(type) {
	case *module.File:
		if m.Absent {
			hr.removed = append(hr.removed, m.Path)
		}
	case *module.Dir:
		if m.Absent {
			hr.removed = append(hr.removed, m.Path)
		}
	case *module.Link:
		if m.Absent {
			hr.removed = append(hr.removed, m.Path)
		}
	}
}

// trackUnits records the unit of a service step, and the units that start it
// while no service step names them.
func (hr *hostRun) trackUnits(m module.Module, res module.Result, where string) {
	sv, ok := m.(*module.Service)
	if !ok {
		return
	}
	unit := sv.Unit()
	hr.units[unit] = true
	hr.startedBy = slices.DeleteFunc(hr.startedBy, func(s startedBy) bool { return s.unit == unit })
	for _, u := range res.StartedBy {
		if !hr.units[u] {
			hr.startedBy = append(hr.startedBy, startedBy{u, fmt.Errorf("%s: %s is started by %s; add a step for %s", where, unit, u, u)})
		}
	}
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
	case *module.File, *module.Dir, *module.Link, *module.Download:
		p = m.Main()
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
// stage notifies it gets a slot at the end of the stage. The slots of the
// stage's own handlers come last.
func evaluate(stage *project.Stage, hr *hostRun) ([]Planned, error) {
	var out []Planned
	late := map[*project.Handler]bool{}
	add := func(env *project.Env, st project.Step, in *project.Step, addr string, place protocol.Then) error {
		steps, err := st.Eval(env)
		if err != nil {
			return err
		}
		if err := hr.keep(steps); err != nil {
			return err
		}
		var notify []string
		for _, h := range st.Notify {
			// A recipe that does not run on the host never runs its handler.
			if h.Recipe != nil && !hr.env.Runs(h.Recipe.Name) {
				continue
			}
			notify = append(notify, h.Record())
			if h.Recipe != nil && slices.ContainsFunc(hr.ran, func(r *project.Step) bool { return r.Recipe == h.Recipe }) {
				late[h] = true
			}
		}
		then := thenRecord(steps, place)
		for i, s := range steps {
			out = append(out, Planned{Step: s, In: in, Last: i == len(steps)-1, Notify: notify, Then: then, Address: address(addr, st, i)})
		}
		return nil
	}
	for i := range stage.Steps {
		st := &stage.Steps[i]
		if st.Recipe == nil {
			if err := add(hr.env, *st, nil, fmt.Sprintf("%s#%d", stage.Name, i+1), protocol.Then{Pipeline: stage.Pipeline, Stage: stage.Name, Step: i + 1}); err != nil {
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
			if err := add(env, rs, st, fmt.Sprintf("%s#%d", st.Recipe.Name, j+1), protocol.Then{Recipe: st.Recipe.Name, Step: j + 1}); err != nil {
				return nil, err
			}
		}
		for _, h := range st.Recipe.Handlers {
			slot, err := handlerSlot(h, env, st, hr)
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
			slot, err := handlerSlot(h, hr.env.For(r), r, hr)
			if err != nil {
				return nil, err
			}
			out = append(out, Planned{In: r, Handler: slot, Address: h.FullName()})
		}
	}
	for _, h := range stage.Handlers {
		slot, err := handlerSlot(h, hr.env, nil, hr)
		if err != nil {
			return nil, err
		}
		out = append(out, Planned{Handler: slot, Address: h.FullName()})
	}
	return out, nil
}

// keep gives each dir step with purge the paths below its path that the
// project writes on the host.
func (hr *hostRun) keep(steps []project.Step) error {
	for i := range steps {
		d, ok := steps[i].Args.(*module.Dir)
		if !ok || !d.Purge {
			continue
		}
		written, err := hr.written()
		if err != nil {
			return fmt.Errorf("dir %s: the paths that the project writes: %w", d.Path, err)
		}
		c := *d
		c.Keep = nil
		for _, p := range written {
			if strings.HasPrefix(p, d.Path+"/") {
				c.Keep = append(c.Keep, p)
			}
		}
		steps[i].Args = &c
	}
	return nil
}

// address is the address of the element i of the step st at addr.
func address(addr string, st project.Step, i int) string {
	if st.Loops() {
		return fmt.Sprintf("%s[%d]", addr, i)
	}
	return addr
}

// handlerSlot evaluates the steps of a handler for a host. in is the recipe
// step of a handler of a recipe, or nil for a handler of a stage.
func handlerSlot(h *project.Handler, env *project.Env, in *project.Step, hr *hostRun) (*Slot, error) {
	slot := &Slot{Handler: h}
	place := protocol.Then{Pipeline: h.Pipeline, Stage: h.Stage, Handler: h.Name}
	if h.Recipe != nil {
		place.Recipe = h.Recipe.Name
	}
	for j, hs := range h.Steps {
		steps, err := hs.Eval(env)
		if err != nil {
			return nil, err
		}
		if err := hr.keep(steps); err != nil {
			return nil, err
		}
		addr := fmt.Sprintf("%s#%d", h.FullName(), j+1)
		place.Step = j + 1
		then := thenRecord(steps, place)
		for i, s := range steps {
			slot.Steps = append(slot.Steps, Planned{Step: s, In: in, Last: i == len(steps)-1, Then: then, Address: address(addr, hs, i)})
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

// thenRecord is the record of the then of the evaluated steps at place, or nil
// for a step without then.
func thenRecord(steps []project.Step, place protocol.Then) *protocol.Then {
	if len(steps) == 0 || steps[0].Then == "" {
		return nil
	}
	last := steps[len(steps)-1]
	place.Module, place.Main = last.Module, last.Args.Main()
	return &place
}

// label is the text of a step in the plan and the logs.
func label(st project.Step) string {
	l := st.Module
	if m := st.ShownMain(); m != "" {
		l += " " + m
	}
	if st.Name != "" {
		l = st.Name + ": " + l
	}
	return secret.Printable(l)
}

var marks = map[module.Action]string{module.Create: "+", module.Modify: "~", module.Remove: "-"}
