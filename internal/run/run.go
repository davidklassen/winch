// Package run plans and applies a pipeline on its hosts.
package run

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
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
	// Prompted reports whether the login needed a prompt, which the access
	// check cannot answer.
	Prompted(ctx context.Context) bool
	// Mask sets the mask of the notes, warnings, and progress lines that the
	// helper sends from now on. A nil mask masks nothing.
	Mask(mask func(string) string)
	Facts(ctx context.Context) (facts.Facts, error)
	Pending(ctx context.Context) (protocol.Pending, error)
	Check(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error)
	// Apply records the handlers in notify and then on the host before it
	// changes something, and the record check of an assert that fails. It
	// guards the step against a lockout as guard says.
	Apply(ctx context.Context, name string, m module.Module, st *module.State, notify []string, then *protocol.Then, check *protocol.Check, guard protocol.Guard) (module.Result, error)
	// Access opens a second SSH connection and runs a command that needs the
	// login and sudo.
	Access(ctx context.Context) error
	// Confirm stops the rollback timer of the last apply.
	Confirm(ctx context.Context) error
	// Rollback ends the rollback timer at once: the old files come back.
	Rollback(ctx context.Context) error
	// Due runs the rollback of an earlier run whose timer process is gone.
	Due(ctx context.Context) error
	// Reboot reboots the host and connects again within wait.
	Reboot(ctx context.Context, wait time.Duration) (protocol.Boot, error)
	// Handled removes the record of a handler that succeeded.
	Handled(ctx context.Context, handler string) error
	// Pend records a pending health gate or assert.
	Pend(ctx context.Context, c protocol.Check) error
	// Passed removes the record of a health gate or assert.
	Passed(ctx context.Context, c protocol.Check) error
	// DropThen removes the record of a then that matches no step.
	DropThen(ctx context.Context, t protocol.Then) error
	// Command runs the command of a then, and then removes the records that
	// match it.
	Command(ctx context.Context, command string, then protocol.Then) error
	// Health runs a health gate, and then removes its record.
	Health(ctx context.Context, h protocol.Health) error
	Exec(ctx context.Context, e protocol.Exec) (module.ExecResult, error)
	Close() error
}

// Options are the choices of a run.
type Options struct {
	// Serial starts the sessions one at a time, in inventory order, so ssh
	// can ask its questions on the terminal.
	Serial bool
	// Progress is nil, or shows the busy hosts.
	Progress Progress
	// Keep keeps the sessions of the hosts with work open after the plan,
	// for Apply. The caller closes the plan.
	Keep bool
}

// Progress shows what each host does now. The text of a step is its scope
// and its label, as an apply line shows them after the host.
type Progress interface {
	Busy(host, text string)
	Idle(host string)
}

type quiet struct{}

func (quiet) Busy(string, string) {}

func (quiet) Idle(string) {}

// progress returns Progress, or a Progress that shows nothing.
func (o Options) progress() Progress {
	if o.Progress == nil {
		return quiet{}
	}
	return o.Progress
}

// Route is how ssh reaches a host: the host name and port, through the jump
// host, a ProxyJump or ProxyCommand, when it is not empty.
type Route struct {
	HostName, Port, Jump string
}

// Connect reaches hosts.
type Connect struct {
	// Resolve returns the route that ssh resolves for h, without a contact
	// with the host.
	Resolve func(ctx context.Context, h project.Host) (Route, error)
	// Open opens a session with h for the project named proj. When want is
	// not nil, the session fails when its destination differs from want.
	Open func(ctx context.Context, proj string, h project.Host, want *protocol.Destination) (Conn, error)
}

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
	Warnings     []*yamlx.Error
	// gone are the records of each host for gates and asserts that the
	// pipeline no longer has.
	gone map[string][]protocol.Check
	// goneThens are the then records of each host that match no step.
	goneThens map[string][]protocol.Then
	// pipeline is the name of the pipeline of the plan.
	pipeline string
	// goneHandlers are the pending handlers of each host that the project no
	// longer has.
	goneHandlers map[string][]string
	// waiting are the handlers of each host, pending or notified by a changed
	// step, whose recipe or stage the plan does not reach on the host.
	waiting map[string][]string
	// refreshed are the hosts whose package index a step refreshed in the
	// plan.
	refreshed map[string]bool
	// parts are the secret parts of the evaluated steps of each host.
	parts map[string][]string
	hash  string
	// sums are the SHA-256 of the project files, and set the --set flags.
	sums map[string]string
	set  []string
	opts Options
	// mu guards conns, the sessions that the plan kept for Apply.
	mu    sync.Mutex
	conns map[string]Conn
}

type StagePlan struct {
	Stage *project.Stage
	Hosts []HostPlan
}

// HostPlan holds the steps of a stage on one host, with their check results.
type HostPlan struct {
	Host  project.Host
	Steps []Planned
	// PendingHealth is true when the health gate of the stage is pending on
	// the host.
	PendingHealth bool
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
	// Check is the record of an assert step, or nil.
	Check *protocol.Check
	// PendingAssert is true on an assert step whose record is pending on the
	// host.
	PendingAssert bool
	// Address is the scope, the number of the step in its list, and the loop
	// index: nginx#3[0]. A slot has the full name of its handler.
	Address string
	// parts are the secret parts of the steps of the host. Text from the host
	// of one step can hold a value that another step built from a secret.
	parts []string
	// SSHD is set on a step that changes sshd's config: the stores of the
	// later steps of the host with confirm_access that restart or reload
	// sshd.
	SSHD []store
	// LoadsSSHD is true on a step that the plan counts as a load of sshd.
	LoadsSSHD bool
}

// hostText returns text from the host of the step with each secret part of
// the steps of its host as secret.Mark.
func (p Planned) hostText(s string) string { return p.Step.HostText(s, p.parts) }

// Slot is a place where a handler runs when a step notified it, or when it is
// pending on the host.
type Slot struct {
	Handler *project.Handler
	Steps   []Planned
	// Runs is true when the plan expects the handler to run.
	Runs bool
}

// shows reports whether the plan shows p as something that apply changes or
// runs: a change, an unknown step, a handler, a then, or a pending assert.
func (p Planned) shows() bool {
	return p.Result.Status == module.Change || p.Result.Status == module.Unknown || p.Handler != nil && p.Handler.Runs || p.ThenRuns || p.PendingAssert
}

func (h HostPlan) changes() bool {
	return h.PendingHealth || slices.ContainsFunc(h.Steps, Planned.shows)
}

// known reports whether the plan shows a line other than an unknown step.
func (h HostPlan) known() bool {
	return h.PendingHealth || slices.ContainsFunc(h.Steps, func(p Planned) bool {
		return p.shows() && (p.Result.Status != module.Unknown || p.PendingThen)
	})
}

// deferred reports whether a step runs in apply without a change.
func (h HostPlan) deferred() bool {
	return slices.ContainsFunc(h.Steps, func(p Planned) bool { return p.Result.Deferred })
}

// hostRun is what the plan keeps about a host between its stages.
type hostRun struct {
	state     module.State
	refreshed bool
	// env is nil until the first contact with the host.
	env *project.Env
	// dirs are the directories that checked steps create, and the parents of
	// the paths they create.
	dirs map[string]bool
	// ran are the recipe steps that ran on the host, in order.
	ran []*project.Step
	// notified are the handlers that the plan expects to run later.
	notified map[string]bool
	// thens are the pending then records.
	thens []*pendingThen
	// checks are the pending gates and asserts.
	checks map[protocol.Check]bool
	// pending are the records that the host reported at the first contact.
	pending *protocol.Pending
	// conn is the session with the host, open across its stages.
	conn Conn
	dest protocol.Destination
	// needs are the users, groups, and directories, as "user <name>",
	// "group <name>", or "dir <path>", that steps that run need.
	needs map[string]need
	// created are the users, groups, and directories, in the form of needs,
	// that checked steps create.
	created map[string]bool
	// units are the units that service steps name.
	units map[string]bool
	// startedBy are the errors for units that start a unit that a service
	// step stops or disables, while no service step names them.
	startedBy []startedBy
	// sshOff are the errors for steps that stop or disable one unit of the
	// SSH server, by the other unit, while no step starts and enables it.
	sshOff []startedBy
	// sshOn are the SSH server units that a step starts and enables.
	sshOn map[string]bool
	// removed are the paths of the checked absent steps.
	removed []string
	// services are the unit files that service steps start or enable, with
	// the first step, or with "" when a unit step wrote the file first.
	services map[string]string
	// started are the units that service steps start or enable, by name and
	// by unit file, with the first step.
	started map[string]string
	// trees are the paths of steps that remove the tree there, and writes the
	// paths that steps write, with the step.
	trees, writes []pathStep
	// owned are the paths whose owner and group steps set, with the step.
	owned []ownedStep
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
	// texts are the text contents of the checked steps, by SHA-256. A later
	// copy_from of a file that a step writes shows its diff from them.
	texts map[string]sourceText
	// step names the step that the plan checks now in the messages of later
	// steps: its address and label, as two steps can have one label.
	step string
	// stages are the evaluated steps of each stage, from the first contact.
	stages map[*project.Stage][]Planned
	// parts are the secret parts of the evaluated steps, each once. Text from
	// the host of one step can hold a value that another step built.
	parts []string
	// written returns the paths that the project writes on the host, for dir
	// steps with purge. It is set at the first contact.
	written func() (project.Writes, error)
}

// pendingThen is a pending then record. matched is set when a step of the
// plan matches it, and ran when the plan runs its then.
type pendingThen struct {
	protocol.Then
	matched, ran bool
}

// matchThen marks the pending records that match t as matched, and with run
// as run. It reports whether one of them had not run yet.
func (hr *hostRun) matchThen(t *protocol.Then, run bool) bool {
	if t == nil {
		return false
	}
	pending := false
	for _, p := range hr.thens {
		if !t.Matches(p.Then) {
			continue
		}
		p.matched = true
		pending = pending || !p.ran
		p.ran = p.ran || run
	}
	return pending
}

type managed struct {
	where  string
	module string
	args   module.Module
}

type pathStep struct {
	path  string
	where string
}

type ownedStep struct {
	module.Owned
	where string
}

type lineStep struct {
	where string
	line  *module.Line
	re    *regexp.Regexp
}

// pkgStep is a checked pkg step. others are the other packages that it
// installs or upgrades, or that it removes. installs are the packages that it
// installs in this run. unknown is set when the package index does not know
// its other packages yet.
type pkgStep struct {
	where    string
	pkg      *module.Pkg
	others   []string
	installs []string
	unknown  bool
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

// Close closes the sessions that the plan kept and Apply did not take.
func (p *Plan) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	var wg sync.WaitGroup
	for _, c := range p.conns {
		wg.Go(func() {
			c.Close() //nolint:errcheck // the run does not use the session
		})
	}
	wg.Wait()
	clear(p.conns)
}

// take returns the session that the plan kept for host, or nil. The caller
// closes it.
func (p *Plan) take(host string) Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.conns[host]
	delete(p.conns, host)
	return c
}

// rollsBack reports whether apply runs the rollback of an earlier run on
// host.
func (p *Plan) rollsBack(host string) bool {
	return p.Pending[host].Rollback != nil
}

// changed returns the hosts with changes in the plan.
func (p *Plan) changed() map[string]bool {
	hosts := map[string]bool{}
	for name := range p.Pending {
		if p.rollsBack(name) {
			hosts[name] = true
		}
	}
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			if hp.changes() {
				hosts[hp.Host.Name] = true
			}
		}
	}
	return hosts
}

// MakePlan checks every step on every host, stage by stage. The hosts of a
// stage run at the same time. At the first contact with a host, it reads the
// facts and starts the host's evaluation. A host that fails stops there.
func MakePlan(ctx context.Context, p *project.Project, connect Connect, opts Options) *Plan {
	plan := &Plan{Project: p.Name, pipeline: p.Pipeline.Name, Failed: map[string]error{}, Pending: map[string]protocol.Pending{}, Destinations: map[string]protocol.Destination{}, opts: opts,
		sums: p.Sums(), set: p.SetFlags()}
	inStages := map[string]bool{}
	runs := map[string]*hostRun{}
	open := func(h project.Host) (Conn, error) {
		hr := runs[h.Name]
		if hr.conn == nil {
			opts.progress().Busy(h.Name, "connecting")
			c, err := connect.Open(context.WithoutCancel(ctx), p.Name, h, nil)
			if err != nil {
				return nil, err
			}
			hr.conn = c
			hr.dest = c.Destination()
			c.Mask(hr.hide)
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
	var running []project.Host
	for _, h := range p.Inventory.Hosts {
		if _, ok := last[h.Name]; ok {
			running = append(running, h)
		}
	}
	maps.Copy(plan.Failed, sharedDestinations(context.WithoutCancel(ctx), running, connect.Resolve))
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
				runs[h.Name] = &hostRun{dirs: map[string]bool{}, notified: map[string]bool{}, checks: map[protocol.Check]bool{}, needs: map[string]need{}, created: map[string]bool{}, units: map[string]bool{}, services: map[string]string{}, started: map[string]string{}, sshOn: map[string]bool{}, unitFiles: map[string][]byte{}, sources: map[string]string{}, managed: map[string]managed{}, lines: map[string][]lineStep{}, texts: map[string]sourceText{}}
			}
		}
		steps := make([][]Planned, len(hosts))
		errs := rollout(ctx, stage.Name, hosts, 0, nil, opts, open, func(i int, conn Conn) error {
			hr := runs[hosts[i].Name]
			var err error
			steps[i], err = check(ctx, conn, opts.progress(), p, hosts[i], stage, hr)
			if err == nil && last[hosts[i].Name] == si {
				for _, s := range hr.startedBy {
					err = errors.Join(err, s.err)
				}
				for _, s := range hr.sshOff {
					err = errors.Join(err, s.err)
				}
			}
			if err != nil || !opts.Keep && last[hosts[i].Name] == si {
				if cerr := hr.close(); err == nil {
					err = cerr
				}
			}
			return maskError(err, hr.hide)
		})
		sp := StagePlan{Stage: stage}
		for i, h := range hosts {
			if errs[i] != nil {
				runs[h.Name].close() //nolint:errcheck // the host failed already
				plan.Failed[h.Name] = errs[i]
				continue
			}
			gate := protocol.Check{Pipeline: stage.Pipeline, Stage: stage.Name}
			sp.Hosts = append(sp.Hosts, HostPlan{Host: h, Steps: steps[i], PendingHealth: stage.Health != nil && runs[h.Name].checks[gate]})
		}
		plan.Stages = append(plan.Stages, sp)
	}
	for _, sp := range plan.Stages {
		for _, hp := range sp.Hosts {
			maskHost(hp.Steps, runs[hp.Host.Name].parts)
		}
	}
	plan.gone = map[string][]protocol.Check{}
	plan.goneThens = map[string][]protocol.Then{}
	plan.goneHandlers = map[string][]string{}
	plan.waiting = map[string][]string{}
	plan.refreshed = map[string]bool{}
	plan.parts = map[string][]string{}
	o := newOwners(p)
	for name, hr := range runs {
		plan.refreshed[name] = hr.refreshed
		plan.parts[name] = hr.parts
		if hr.pending != nil {
			plan.Pending[name] = *hr.pending
			if !p.Pipeline.AdHoc {
				plan.gone[name] = o.goneChecks(hr.pending.Checks)
				plan.goneThens[name] = o.goneThens(name, hr)
				plan.goneHandlers[name], plan.waiting[name] = o.pendingHandlers(hr.pending.Handlers, hr.notified)
			}
		}
		plan.Destinations[name] = hr.dest
	}
	plan.conns = map[string]Conn{}
	changed := plan.changed()
	var idle []string
	for name, hr := range runs {
		if hr.conn == nil {
			continue
		}
		if plan.Failed[name] == nil && (changed[name] || plan.removes(name)) {
			plan.conns[name] = hr.conn
		} else {
			idle = append(idle, name)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, name := range idle {
		wg.Go(func() {
			if err := runs[name].close(); err != nil {
				mu.Lock()
				plan.Failed[name] = maskError(err, runs[name].hide)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	for _, h := range p.Inventory.Hosts {
		if inStages[h.Name] {
			plan.Hosts = append(plan.Hosts, h)
		}
	}
	plan.suppressMissingUnitFiles()
	plan.sshdStores()
	plan.Warnings = append(plan.sshdWarnings(), plan.publicWarnings()...)
	plan.hash = sumBytes(plan.HashInput())[:16]
	return plan
}

// sharedDestinations returns errors for the hosts whose host name, port, and
// jump host, as ssh resolves them, are those of another host: the sessions of
// both would share the lock of one helper.
func sharedDestinations(ctx context.Context, hosts []project.Host, resolve func(context.Context, project.Host) (Route, error)) map[string]error {
	errs := map[string]error{}
	byRoute := map[Route][]string{}
	routes := map[string]Route{}
	for _, h := range hosts {
		r, err := resolve(ctx, h)
		if err != nil {
			errs[h.Name] = err
			continue
		}
		routes[h.Name] = r
		r.HostName = strings.ToLower(r.HostName)
		byRoute[r] = append(byRoute[r], h.Name)
	}
	for _, names := range byRoute {
		if len(names) < 2 {
			continue
		}
		for i, name := range names {
			other := names[0]
			if i == 0 {
				other = names[1]
			}
			r := routes[name]
			shown := net.JoinHostPort(r.HostName, r.Port)
			if r.Jump != "" {
				shown += " through " + r.Jump
			}
			errs[name] = fmt.Errorf("host %s has the same SSH destination, %s; keep one host for this destination, or give each host its own address or port", other, shown)
		}
	}
	return errs
}

// check checks the steps of a stage on one host. At the first contact, it
// reads the facts and the pending handlers, and evaluates all stages of the
// host: the text from the host then passes the secret parts of all its steps.
func check(ctx context.Context, conn Conn, progress Progress, p *project.Project, h project.Host, stage *project.Stage, hr *hostRun) ([]Planned, error) {
	if hr.env == nil {
		f, err := conn.Facts(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		if hr.env, err = p.Start(h, f); err != nil {
			return nil, err
		}
		hr.written = sync.OnceValues(func() (project.Writes, error) { return p.Written(h, f) })
		hr.stages = map[*project.Stage][]Planned{}
		for i := range p.Pipeline.Stages {
			s := &p.Pipeline.Stages[i]
			if s.Skipped || !slices.ContainsFunc(s.Targets, func(t project.Host) bool { return t.Name == h.Name }) {
				continue
			}
			steps, err := evaluate(s, hr)
			if err != nil {
				return nil, err
			}
			for _, p := range steps {
				hr.addParts(p.Step.Parts)
				if s := p.Handler; s != nil {
					for _, hs := range s.Steps {
						hr.addParts(hs.Step.Parts)
					}
				}
			}
			hr.stages[s] = steps
		}
		pending, err := conn.Pending(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		for i, l := range pending.Rollback {
			pending.Rollback[i] = hr.hide(l)
		}
		hr.pending = &pending
		for _, n := range pending.Handlers {
			hr.notified[n] = true
		}
		for _, t := range pending.Then {
			hr.thens = append(hr.thens, &pendingThen{Then: t})
		}
		for _, c := range pending.Checks {
			hr.checks[c] = true
		}
	}
	steps := hr.stages[stage]
	changed := false
	for i, p := range steps {
		if s := p.Handler; s != nil {
			name := s.Handler.Record()
			s.Runs = hr.notified[name]
			delete(hr.notified, name)
			for j, hs := range s.Steps {
				if hs.Last {
					pending := hr.matchThen(hs.Then, s.Runs)
					s.Steps[j].PendingThen = s.Runs && pending
				}
				s.Steps[j].PendingAssert = s.Runs && hs.Check != nil && hr.checks[*hs.Check]
			}
			continue
		}
		if ctx.Err() != nil {
			return nil, ErrInterrupted
		}
		l := oneLine(label(p.Step))
		where := scope(stage, p) + ": " + l
		hr.step = p.Address + " " + l
		if err := hr.repo(&steps[i].Step, where); err != nil {
			return nil, err
		}
		hr.earlierPkgs(&steps[i].Step)
		if err := hr.same(p.Step, where); err != nil {
			return nil, err
		}
		if err := hr.tree(p.Step.Args, where); err != nil {
			return nil, err
		}
		if err := hr.ownerTree(p.Step.Args, where); err != nil {
			return nil, err
		}
		if err := hr.unitOrder(p, where); err != nil {
			return nil, err
		}
		hr.newUnitFile(&steps[i].Step)
		progress.Busy(h.Name, where)
		mask := func(s string) string { return p.Step.HostText(s, hr.parts) }
		conn.Mask(mask)
		var err error
		steps[i].Result, err = conn.Check(context.WithoutCancel(ctx), p.Step.Module, steps[i].Step.Args, &hr.state)
		conn.Mask(hr.hide)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, maskError(err, mask))
		}
		hr.refreshed = hr.refreshed || hr.state.Refreshed
		hr.newText(p.Step, &steps[i].Result)
		hr.trackRemoved(p.Step.Args)
		hr.trackUnitFile(p.Step.Args, steps[i].Result)
		hr.dropCreated(&steps[i].Result)
		if err := hr.order(p.Step, steps[i].Result, where); err != nil {
			return nil, err
		}
		if err := hr.packages(p.Step.Args, steps[i].Result, where); err != nil {
			return nil, err
		}
		if err := hr.sshServer(p.Step.Args, steps[i].Result, where); err != nil {
			return nil, err
		}
		hr.dropCreatedParents(p.Step.Args, &steps[i].Result)
		hr.trackUnits(p.Step.Args, steps[i].Result, where)
		steps[i].PendingAssert = p.Check != nil && hr.checks[*p.Check]
		if steps[i].Result.Status != module.OK {
			if err := hr.leftOut(p.Step, where); err != nil {
				return nil, err
			}
			changed = true
			for _, n := range p.Notify {
				hr.notified[n] = true
			}
		}
		if !p.Last {
			continue
		}
		steps[i].PendingThen = hr.matchThen(p.Then, true)
		steps[i].ThenRuns = p.Then != nil && (changed || steps[i].PendingThen)
		changed = false
	}
	return steps, nil
}

// leftOut fails a changed step that notifies a handler with confirm_access
// whose recipe runs in a stage that the selection leaves out. The session end
// would put back the step's files.
func (hr *hostRun) leftOut(st project.Step, where string) error {
	for _, h := range st.Notify {
		if h.Recipe == nil || !h.ConfirmsAccess() {
			continue
		}
		if s := hr.env.RunsIn(h.Recipe.Name); s != nil && s.Skipped {
			return fmt.Errorf("%s: the confirm_access handler %s runs in stage %s, which --stages leaves out", where, h.FullName(), s.Name)
		}
	}
	return nil
}

// need is a step that needs a user, a group, or a directory, and that need as
// the output shows it.
type need struct {
	step, shown string
}

// needsOf returns the users, groups, and directories that the module m needs.
func needsOf(m module.Module) []string {
	switch m := m.(type) {
	case *module.Cmd:
		return []string{"user " + m.User, "dir " + m.Dir}
	case *module.File:
		return []string{"user " + string(m.Owner), "group " + string(m.Group)}
	case *module.Dir:
		return []string{"user " + string(m.Owner), "group " + string(m.Group)}
	case *module.Download:
		return []string{"user " + string(m.Owner), "group " + string(m.Group)}
	case *module.User:
		out := []string{"group " + string(m.Group)}
		if groups := cmp.Or(m.Groups, m.AddGroups); groups != nil {
			for _, g := range *groups {
				out = append(out, "group "+g)
			}
		}
		return out
	}
	return nil
}

// order fails a step that creates a user, a group, or a directory that an
// earlier step that runs needs: as its owner, group, one of its groups, or the
// user or directory of a cmd. That earlier step fails in apply. Otherwise it
// records what the step at where needs.
func (hr *hostRun) order(st project.Step, res module.Result, where string) error {
	if res.Status == module.OK {
		return nil
	}
	var created []string
	for n := range hr.needs {
		if d, ok := strings.CutPrefix(n, "dir "); ok && slices.Contains(res.Changes, module.ParentChange(d)) {
			created = append(created, n)
		}
	}
	slices.Sort(created)
	switch m := st.Args.(type) {
	case *module.Dir:
		if res.Action == module.Create {
			created = append(created, "dir "+m.Path)
		}
	case *module.User:
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
			return fmt.Errorf("%s: this step creates %s, which an earlier step needs: %s; move this step before it", where, w.shown, w.step)
		}
		hr.created[c] = true
	}
	needs, shown := needsOf(st.Args), needsOf(st.Shown().Args)
	for i, n := range needs {
		kind, name, _ := strings.Cut(n, " ")
		if _, err := strconv.ParseUint(name, 10, 32); name == "" || err == nil || kind == "dir" && hr.dirs[name] {
			continue
		}
		if _, ok := hr.needs[n]; !ok {
			hr.needs[n] = need{step: hr.step, shown: shown[i]}
		}
	}
	// Directories that exist after the step, which dropCreatedParents does
	// not see.
	var made []string
	switch m := st.Args.(type) {
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

// dropCreated keeps in the missing user and dir of a cmd only those that no
// earlier step creates, and in the missing tools only those whose package no
// earlier pkg step installs.
func (hr *hostRun) dropCreated(res *module.Result) {
	res.Missing = slices.DeleteFunc(res.Missing, func(n string) bool {
		d, ok := strings.CutPrefix(n, "dir ")
		return hr.created[n] || ok && hr.dirs[d]
	})
	res.MissingTools = slices.DeleteFunc(res.MissingTools, func(t module.Tool) bool {
		return slices.ContainsFunc(hr.pkgs, func(e pkgStep) bool {
			return !e.pkg.Absent && (slices.Contains(e.pkg.Name, t.Package) || slices.Contains(e.others, t.Package))
		})
	})
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
	hr.sources[key] = hr.step
	c := *r
	c.Removed = hr.removed
	st.Args = &c
	return nil
}

// earlierPkgs gives a pkg step the packages that earlier absent pkg steps of
// the host remove. It gives an absent step also the packages that earlier
// install steps install or upgrade. Both include the other packages that apt
// changes with them. An install whose other packages are not known yet adds
// nothing: its packages alone can miss their dependencies.
func (hr *hostRun) earlierPkgs(st *project.Step) {
	p, ok := st.Args.(*module.Pkg)
	if !ok {
		return
	}
	c := *p
	for _, e := range hr.pkgs {
		switch {
		case e.pkg.Absent:
			c.Removed = slices.Concat(c.Removed, e.pkg.Name, e.others)
		case p.Absent && !e.unknown:
			c.Installed = slices.Concat(c.Installed, e.installs, e.others)
		}
	}
	slices.Sort(c.Installed)
	c.Installed = slices.Compact(c.Installed)
	st.Args = &c
}

// removesTimezoneFile reports whether a removes /etc/timezone and b is a
// timezone step. The timezone step writes the file only when it exists, so
// the two converge in any order.
func removesTimezoneFile(a, b module.Module) bool {
	f, ok := a.(*module.File)
	_, tz := b.(*module.Timezone)
	return ok && tz && f.Absent && f.Path == module.TimezoneFile
}

// same fails a step that manages a path, package, unit, user, or group that
// an earlier step of the host manages with other arguments. The host would
// change on every run.
func (hr *hostRun) same(st project.Step, where string) error {
	add := func(thing string, args module.Module) error {
		m, ok := hr.managed[thing]
		if !ok {
			hr.managed[thing] = managed{hr.step, st.Module, args}
			return nil
		}
		if removesTimezoneFile(m.args, args) || removesTimezoneFile(args, m.args) {
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
			return fmt.Errorf("%s: %s is also in %s, with other arguments; use one step", where, thing, m.where)
		}
		return nil
	}
	addWrites := func(thing string, w module.Writer) error {
		if err := add(thing, st.Args); err != nil {
			return err
		}
		for _, p := range w.Writes() {
			if err := add("the path "+p, st.Args); err != nil {
				return err
			}
		}
		return nil
	}
	switch m := st.Args.(type) {
	case *module.Download:
		// A dir step may manage the unpack directory, and purge keeps the tree.
		if m.Unpack != "" {
			return add("the unpack directory "+m.Unpack, m)
		}
		return add("the path "+m.Path, m)
	case *module.File, *module.Dir, *module.Link:
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
		// Steps that only add groups combine with the other steps for the
		// user, except with a step that sets the exact groups.
		addOnly := m.OnlyAddsGroups()
		if addOnly || m.Groups != nil {
			key := "the groups of the user " + m.Name
			e, ok := hr.managed[key]
			if !ok {
				hr.managed[key] = managed{hr.step, st.Module, m}
			} else if (e.args.(*module.User).Groups != nil) != (m.Groups != nil) {
				return fmt.Errorf("%s: the user %s is also in %s, with other arguments; use one step", where, m.Name, e.where)
			}
		}
		if addOnly {
			return nil
		}
		return add("the user "+m.Name, m)
	case *module.Group:
		return add("the group "+m.Name, m)
	case *module.Hostname:
		return addWrites("the host name", m)
	case *module.Timezone:
		return addWrites("the time zone", m)
	case *module.Certbot:
		return addWrites("the certificate "+m.Name, m)
	case *module.Firewall:
		if other, ok := hr.managed["the firewall"]; ok {
			return fmt.Errorf("%s: the firewall is also in %s; a host has one firewall step", where, other.where)
		}
		hr.managed["the firewall"] = managed{hr.step, st.Module, m}
		if err := add("the unit "+module.FirewallUnit, m); err != nil {
			return err
		}
		for _, t := range module.Touches(m) {
			if err := add("the path "+t.Path, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// tree fails a step that removes a tree that holds a path that another step of
// the host writes, in either order. A dir or link step with replace removes a
// tree only once: the paths below then go into the new directory, or through
// the link. A download with unpack removes the tree of its directory only for
// the earlier steps: a later step writes into the new tree.
func (hr *hostRun) tree(m module.Module, where string) error {
	removes, later := "", true
	switch m := m.(type) {
	case *module.Dir:
		if m.Absent {
			removes = m.Path
		}
	case *module.File:
		if m.Replace {
			removes = m.Path
		}
	case *module.Download:
		removes, later = m.Unpack, false
	}
	if removes != "" {
		for _, w := range hr.writes {
			if strings.HasPrefix(w.path, removes+"/") {
				return fmt.Errorf("%s: this step removes %s, which %s writes; the two steps undo each other on every run", where, w.path, w.where)
			}
		}
		if later {
			hr.trees = append(hr.trees, pathStep{removes, hr.step})
		}
	}
	w, ok := m.(module.Writer)
	if !ok {
		return nil
	}
	for _, p := range w.Writes() {
		for _, t := range hr.trees {
			if strings.HasPrefix(p, t.path+"/") {
				return fmt.Errorf("%s: %s removes %s, which this step writes; the two steps undo each other on every run", where, t.where, p)
			}
		}
		hr.writes = append(hr.writes, pathStep{p, hr.step})
	}
	return nil
}

// ownerTree fails a step that gives a path another owner or group than a dir
// step with recurse gives the tree that holds the path, in either order.
func (hr *hostRun) ownerTree(m module.Module, where string) error {
	for _, o := range module.Owns(m) {
		for _, e := range hr.owned {
			if otherOwner(o, e.Owned) {
				return fmt.Errorf("%s: this step sets the owner and group of its tree, and %s gives %s another owner or group; the two steps undo each other on every run", where, e.where, e.Path)
			}
			if otherOwner(e.Owned, o) {
				return fmt.Errorf("%s: %s sets the owner and group of its tree, and this step gives %s another owner or group; the two steps undo each other on every run", where, e.where, o.Path)
			}
		}
		hr.owned = append(hr.owned, ownedStep{o, hr.step})
	}
	return nil
}

// otherOwner reports whether tree recurses and holds o, and o sets another
// owner or group.
func otherOwner(tree, o module.Owned) bool {
	if !tree.Tree || o.Path != tree.Path && !strings.HasPrefix(o.Path, tree.Path+"/") {
		return false
	}
	return o.Owner != "" && o.Owner != tree.Owner || o.Group != "" && o.Group != tree.Group
}

// unitOrder fails a unit step whose unit file an earlier service step needs to
// start or enable the unit. Such a step fails on a new host. It also fails a
// step that changes a drop-in of a unit that an earlier service step starts or
// enables, when the step notifies no handler on the host: daemon-reload does
// not restart the unit.
func (hr *hostRun) unitOrder(p Planned, where string) error {
	var dropIn string
	switch m := p.Step.Args.(type) {
	case *module.Service:
		if m.Running != nil && *m.Running || m.Enabled != nil && *m.Enabled {
			if _, ok := hr.services[m.UnitFile()]; !ok {
				hr.services[m.UnitFile()] = hr.step
			}
			for _, u := range []string{m.Unit(), m.UnitFile()} {
				if _, ok := hr.started[u]; !ok {
					hr.started[u] = hr.step
				}
			}
		}
	case *module.Unit:
		if w := hr.services[m.Name]; w != "" {
			return fmt.Errorf("%s: %s uses %s before this step writes it; move this step before it", where, w, m.Name)
		}
		// Later service steps find the unit file.
		hr.services[m.Name] = ""
	case *module.File:
		dropIn = m.Path
	case *module.Line:
		dropIn = m.Path
	case *module.Link:
		dropIn = m.Path
	}
	unit, ok := strings.CutPrefix(path.Dir(dropIn), "/etc/systemd/system/")
	if !ok || len(p.Notify) > 0 {
		return nil
	}
	unit, ok = strings.CutSuffix(unit, ".d")
	if w, found := hr.started[unit]; ok && found {
		return fmt.Errorf("%s: %s starts or enables %s before this step changes its drop-in; move this step before it", where, w, unit)
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
	hr.lines[l.Path] = append(hr.lines[l.Path], lineStep{hr.step, l, re})
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
		cur := pkgStep{where: hr.step, pkg: m}
		cur.installs, cur.others = module.PkgPlan(res.Changes)
		cur.unknown = slices.Contains(res.Changes, module.OthersUnknown)
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

// sshServer fails a step that masks the SSH server. It records a
// step that stops or disables one of the SSH server units: the plan fails it
// unless another step starts and enables the other unit.
func (hr *hostRun) sshServer(m module.Module, res module.Result, where string) error {
	switch m := m.(type) {
	case *module.Service:
		unit := m.Unit()
		other := module.SSHPair(unit)
		if other == "" {
			return nil
		}
		if m.Running != nil && *m.Running && m.Enabled != nil && *m.Enabled {
			hr.sshOn[unit] = true
			hr.sshOff = slices.DeleteFunc(hr.sshOff, func(s startedBy) bool { return s.unit == unit })
		}
		stops := m.Running != nil && !*m.Running && slices.Contains(res.Changes, "stop")
		disables := m.Enabled != nil && !*m.Enabled && slices.Contains(res.Changes, "disable")
		if (stops || disables) && !hr.sshOn[other] {
			verb := "stops"
			switch {
			case stops && disables:
				verb = "stops and disables"
			case disables:
				verb = "disables"
			}
			hr.sshOff = append(hr.sshOff, startedBy{other, fmt.Errorf("%s: this %s %s and cuts off winch's access, since no step starts and enables %s; start and enable %[4]s in a service step", where, verb, unit, other)})
		}
	case *module.Link:
		if res.Status == module.OK || m.Target == nil {
			return nil
		}
		target := *m.Target
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(m.Path), target)
		}
		unit := path.Base(m.Path)
		if target == "/dev/null" &&
			module.SSHPair(unit) != "" && (&module.Unit{Name: unit}).Path() == m.Path {
			return fmt.Errorf("%s: this cuts off winch's access", where)
		}
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

// newText records the text content of a step, or why the plan shows no diff
// of it. It adds the new text of a copy_from whose source an earlier step
// writes, or drops the old text when no new text is known.
func (hr *hostRun) newText(st project.Step, res *module.Result) {
	if t, ok := st.Args.(module.WithText); ok {
		if text, reason := t.Text(); text != nil {
			if shown := st.Shown(); shown.Hidden || shown.Lines != nil {
				reason = secret.Mark
			}
			hr.texts[sumBytes(text)] = sourceText{string(text), reason}
		}
	}
	if res.SourceSHA256 == "" {
		return
	}
	if t, ok := hr.texts[res.SourceSHA256]; ok && res.New == nil && res.Old != nil {
		if t.reason != "" {
			res.Old, res.OldReason = nil, t.reason
			return
		}
		res.New = &t.text
	}
	switch {
	case res.New != nil:
		hr.texts[res.SourceSHA256] = sourceText{text: *res.New}
	// The plan knows no new content to show.
	case res.OldReason == "":
		res.Old = nil
	}
}

// sourceText is the text content of a step, or the reason the plan shows no
// diff of it.
type sourceText struct{ text, reason string }

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
			hr.startedBy = append(hr.startedBy, startedBy{u, fmt.Errorf("%s: %s starts %s; add a service step that stops and disables %s", where, u, unit, u)})
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
	add := func(env *project.Env, st project.Step, in *project.Step, addr string, place protocol.Check) error {
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
			if h.Recipe != nil && hr.env.RunsIn(h.Recipe.Name) == nil {
				continue
			}
			notify = append(notify, h.Record())
			if h.Recipe != nil && slices.ContainsFunc(hr.ran, func(r *project.Step) bool { return r.Recipe == h.Recipe }) {
				late[h] = true
			}
		}
		then, check := thenRecord(steps, place), checkRecord(st, place)
		for i, s := range steps {
			out = append(out, Planned{Step: s, In: in, Last: i == len(steps)-1, Notify: notify, Then: then, Check: check, Address: address(addr, st, i)})
		}
		return nil
	}
	for i := range stage.Steps {
		st := &stage.Steps[i]
		if st.Recipe == nil {
			if err := add(hr.env, *st, nil, fmt.Sprintf("%s#%d", stage.Name, i+1), protocol.Check{Pipeline: stage.Pipeline, Stage: stage.Name, Step: i + 1}); err != nil {
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
			if err := add(env, rs, st, fmt.Sprintf("%s#%d", st.Recipe.Name, j+1), protocol.Check{Recipe: st.Recipe.Name, Step: j + 1}); err != nil {
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
		for _, p := range written.Paths {
			if strings.HasPrefix(p, d.Path+"/") {
				c.Keep = append(c.Keep, p)
			}
		}
		// A download unpack writes everything in its tree.
		if slices.ContainsFunc(written.Trees, func(t string) bool { return t == d.Path || strings.HasPrefix(d.Path, t+"/") }) {
			c.Purge = false
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
	place := protocol.Check{Pipeline: h.Pipeline, Stage: h.Stage, Handler: h.Name}
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
		then, check := thenRecord(steps, place), checkRecord(hs, place)
		for i, s := range steps {
			slot.Steps = append(slot.Steps, Planned{Step: s, In: in, Last: i == len(steps)-1, Then: then, Check: check, Address: address(addr, hs, i)})
		}
	}
	return slot, nil
}

// HasChanges reports whether a host that did not fail has changes.
func (p *Plan) HasChanges() bool {
	for name := range p.changed() {
		if p.Failed[name] == nil {
			return true
		}
	}
	return false
}

// HasWork reports whether apply has work on a host that did not fail: a
// change, or a gone record to remove.
func (p *Plan) HasWork() bool {
	return p.HasChanges() || slices.ContainsFunc(p.Hosts, func(h project.Host) bool { return p.removes(h.Name) })
}

// removes reports whether apply removes gone records on host.
func (p *Plan) removes(host string) bool {
	return p.Failed[host] == nil && (len(p.gone[host]) > 0 || len(p.goneThens[host]) > 0 || len(p.goneHandlers[host]) > 0)
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
func thenRecord(steps []project.Step, place protocol.Check) *protocol.Then {
	if len(steps) == 0 || steps[0].Then == "" {
		return nil
	}
	t := &protocol.Then{Recipe: place.Recipe, Pipeline: place.Pipeline, Stage: place.Stage, Handler: place.Handler, Module: steps[0].Module}
	for _, st := range steps {
		t.Mains = append(t.Mains, sum(st.Args.Main()))
	}
	return t
}

// checkRecord is the record of the assert step st at place, or nil for
// another step.
func checkRecord(st project.Step, place protocol.Check) *protocol.Check {
	if st.Module != "assert" {
		return nil
	}
	return &place
}

// owners are the pipelines and recipes of the project, which own the records
// on a host. pl is the pipeline of the run.
type owners struct {
	pl        *project.Pipeline
	pipelines map[string]*project.Pipeline
	recipes   map[string]*project.Recipe
	// all is false when a pipeline of the project did not load.
	all bool
}

func newOwners(p *project.Project) owners {
	o := owners{pl: p.Pipeline, pipelines: map[string]*project.Pipeline{}, recipes: map[string]*project.Recipe{}}
	var pls []*project.Pipeline
	pls, o.all = p.Pipelines()
	for _, pl := range pls {
		o.pipelines[pl.Name] = pl
		for _, s := range pl.Stages {
			for _, st := range s.Steps {
				if st.Recipe != nil {
					o.recipes[st.Recipe.Name] = st.Recipe
				}
			}
		}
	}
	return o
}

// has reports whether the project has the recipe, or the pipeline and the
// stage, and the handler of a record. When a pipeline did not load, a recipe
// or a pipeline that the project lacks counts as there.
func (o owners) has(c protocol.Check) bool {
	var handlers []*project.Handler
	if c.Recipe != "" {
		r := o.recipes[c.Recipe]
		if r == nil {
			return !o.all
		}
		handlers = r.Handlers
	} else {
		pl := o.pipelines[c.Pipeline]
		if pl == nil {
			return !o.all
		}
		i := slices.IndexFunc(pl.Stages, func(s project.Stage) bool { return s.Name == c.Stage })
		if i < 0 {
			return false
		}
		handlers = pl.Stages[i].Handlers
	}
	return c.Handler == "" || slices.ContainsFunc(handlers, func(h *project.Handler) bool { return h.Name == c.Handler })
}

// pendingHandlers returns the pending handlers whose recipe, pipeline, stage,
// or handler the project no longer has, and the other handlers that no slot of
// the plan took from notified, the records first.
func (o owners) pendingHandlers(records []string, notified map[string]bool) (gone, waiting []string) {
	for _, n := range records {
		recipe, pipeline, stage, handler := project.ParseRecord(n)
		switch {
		case !o.has(protocol.Check{Recipe: recipe, Pipeline: pipeline, Stage: stage, Handler: handler}):
			gone = append(gone, n)
		case notified[n]:
			waiting = append(waiting, n)
		}
	}
	for _, n := range slices.Sorted(maps.Keys(notified)) {
		if !slices.Contains(records, n) {
			waiting = append(waiting, n)
		}
	}
	return gone, waiting
}

// goneThens returns the then records of host that no step of the plan
// matches, in a recipe that runs on the host, or in a stage of pl that the
// plan checks on the host. A record whose recipe, pipeline, stage, or handler
// the project no longer has is gone too. A record of a recipe or stage that
// the plan does not check stays.
func (o owners) goneThens(host string, hr *hostRun) []protocol.Then {
	var gone []protocol.Then
	for _, t := range hr.thens {
		if t.matched {
			continue
		}
		reach := false
		switch {
		case t.Recipe != "":
			reach = slices.ContainsFunc(hr.ran, func(r *project.Step) bool { return r.Recipe.Name == t.Recipe })
		case t.Pipeline == o.pl.Name:
			i := slices.IndexFunc(o.pl.Stages, func(s project.Stage) bool { return s.Name == t.Stage })
			reach = i < 0 || !o.pl.Stages[i].Skipped && slices.ContainsFunc(o.pl.Stages[i].Targets, func(h project.Host) bool { return h.Name == host })
		}
		if reach || !o.has(protocol.Check{Recipe: t.Recipe, Pipeline: t.Pipeline, Stage: t.Stage, Handler: t.Handler}) {
			gone = append(gone, t.Then)
		}
	}
	return gone
}

// goneChecks returns the records of gates and asserts that the project no
// longer has: the gate of a stage without health, an assert whose place holds
// no assert step, and a record whose recipe, pipeline, stage, or handler is
// gone. Only the stages of pl count for gates and steps.
func (o owners) goneChecks(records []protocol.Check) []protocol.Check {
	var gone []protocol.Check
	for _, c := range records {
		if !o.has(c) {
			gone = append(gone, c)
			continue
		}
		var steps []project.Step
		var handlers []*project.Handler
		switch {
		case c.Recipe != "":
			r := o.recipes[c.Recipe]
			if r == nil {
				continue
			}
			steps, handlers = r.Steps, r.Handlers
		case c.Pipeline == o.pl.Name:
			i := slices.IndexFunc(o.pl.Stages, func(s project.Stage) bool { return s.Name == c.Stage })
			if i < 0 {
				gone = append(gone, c)
				continue
			}
			if c.Step == 0 {
				if o.pl.Stages[i].Health == nil {
					gone = append(gone, c)
				}
				continue
			}
			steps, handlers = o.pl.Stages[i].Steps, o.pl.Stages[i].Handlers
		default:
			continue
		}
		if c.Handler != "" {
			i := slices.IndexFunc(handlers, func(h *project.Handler) bool { return h.Name == c.Handler })
			if i < 0 {
				gone = append(gone, c)
				continue
			}
			steps = handlers[i].Steps
		}
		if c.Step < 1 || c.Step > len(steps) || steps[c.Step-1].Module != "assert" {
			gone = append(gone, c)
		}
	}
	return gone
}

// label is the text of a step in JSON events, with each line of a command of
// several lines.
func label(st project.Step) string {
	l := stepHead(st)
	if m := st.Shown().Args.Main(); m != "" {
		l += " " + m
	}
	return secret.PrintableLines(l)
}

// stepHead is the label of a step without its main argument.
func stepHead(st project.Step) string {
	if st.Name != "" {
		return st.Name + ": " + st.Module
	}
	return st.Module
}

// oneLine is a label for a line of text: its first line, and " ..." when it
// has more.
func oneLine(label string) string {
	first, rest, _ := strings.Cut(label, "\n")
	if rest != "" {
		return first + " ..."
	}
	return first
}

var marks = map[module.Action]string{module.Create: "+", module.Modify: "~", module.Remove: "-"}

// maskResult masks the text from the host in the result of a step with the
// secret parts of the steps of its host. A change line whose new value holds a
// secret part loses its old value, which can be an older secret.
func maskResult(st project.Step, parts []string, res *module.Result) {
	if len(parts) == 0 {
		return
	}
	changes := make([]string, len(res.Changes))
	for i, c := range res.Changes {
		if head, after, ok := strings.Cut(c, " →"); ok && secret.Hide(after, parts) != after {
			c = withoutOld(head) + " →" + after
		}
		changes[i] = st.HostText(c, parts)
	}
	res.Changes = changes
	res.Link = st.HostText(res.Link, parts)
}

// hide returns text from the host with each secret part of the evaluated
// steps as secret.Mark.
func (hr *hostRun) hide(s string) string { return secret.Hide(s, hr.parts) }

// addParts adds the parts that hr does not have yet.
func (hr *hostRun) addParts(parts []string) {
	for _, p := range parts {
		if !slices.Contains(hr.parts, p) {
			hr.parts = append(hr.parts, p)
		}
	}
}

// maskHost gives each step of a host the secret parts of all evaluated steps
// of the host, and masks its result. The checks of later steps read the plain
// results.
func maskHost(steps []Planned, parts []string) {
	for i := range steps {
		if s := steps[i].Handler; s != nil {
			maskHost(s.Steps, parts)
			continue
		}
		steps[i].parts = parts
		maskResult(steps[i].Step, parts, &steps[i].Result)
	}
}

// withoutOld returns the head of a change line, "<field> <old>", without
// the old value: a quoted string at its end, or its last word.
func withoutOld(head string) string {
	for i := range len(head) - 1 {
		if head[i] != ' ' {
			continue
		}
		if _, err := strconv.Unquote(head[i+1:]); err == nil {
			return head[:i]
		}
	}
	if i := strings.LastIndex(head, " "); i >= 0 {
		return head[:i]
	}
	return head
}

// maskedError is an error with its text masked.
type maskedError struct {
	text string
	err  error
}

func (e maskedError) Error() string { return e.text }

func (e maskedError) Unwrap() error { return e.err }

// maskError returns err with its text masked by mask, or nil.
func maskError(err error, mask func(string) string) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	if t := mask(s); t != s {
		return maskedError{t, err}
	}
	return err
}
