// Package run plans and applies a pipeline on its hosts.
package run

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"

	"github.com/davidklassen/winch/internal/diff"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
)

// Conn is a session with one host.
type Conn interface {
	Check(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error)
	Apply(ctx context.Context, name string, m module.Module, st *module.State) (module.Result, error)
	Close() error
}

type Connect func(ctx context.Context, h project.Host) (Conn, error)

type Plan struct {
	Stages []StagePlan
	// Hosts are all hosts of the pipeline, in inventory order.
	Hosts  []project.Host
	Failed map[string]error
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

type Planned struct {
	Step   project.Step
	Result module.Result
}

func (h HostPlan) changes() bool {
	return slices.ContainsFunc(h.Steps, func(p Planned) bool { return p.Result.Status == module.Change })
}

// MakePlan checks every step on every host, stage by stage. A host that
// fails stops there.
func MakePlan(ctx context.Context, p *project.Project, connect Connect) *Plan {
	plan := &Plan{Failed: map[string]error{}}
	inStages := map[string]bool{}
	states := map[string]*module.State{}
	for i := range p.Pipeline.Stages {
		stage := &p.Pipeline.Stages[i]
		sp := StagePlan{Stage: stage}
		for _, h := range stage.Targets {
			inStages[h.Name] = true
			if plan.Failed[h.Name] != nil {
				continue
			}
			if states[h.Name] == nil {
				states[h.Name] = &module.State{}
			}
			steps, err := check(ctx, connect, h, stage, states[h.Name])
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

func check(ctx context.Context, connect Connect, h project.Host, stage *project.Stage, state *module.State) (steps []Planned, err error) {
	conn, err := connect(ctx, h)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	for _, st := range stage.Steps {
		res, err := conn.Check(ctx, st.Module, st.Args, state)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label(st), err)
		}
		steps = append(steps, Planned{Step: st, Result: res})
	}
	return steps, nil
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

func label(st project.Step) string {
	return st.Module + " " + st.Args.Main()
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
			fmt.Fprintf(b, "  %s\n", sp.Stage.Name)
			for _, p := range hp.Steps {
				if p.Result.Status == module.Change {
					writeStep(b, p.Step, p.Result)
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

func writeStep(w io.Writer, st project.Step, res module.Result) {
	fmt.Fprintf(w, "    %s %s\n", marks[res.Action], label(st))
	for _, c := range res.Changes {
		fmt.Fprintf(w, "        %s\n", printable(c))
	}
	t, ok := st.Args.(module.WithContent)
	if res.Old == nil || !ok || t.Text() == nil {
		return
	}
	d := diff.Diff([]byte(*res.Old), []byte(*t.Text()))
	for _, line := range strings.SplitAfter(string(d), "\n") {
		if line != "" {
			fmt.Fprintf(w, "        %s\n", printable(strings.TrimSuffix(line, "\n")))
		}
	}
}

// printable replaces control characters in text from a host, so the text
// cannot move the cursor or change the terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\t' && (unicode.IsControl(r) || r == '\u2028' || r == '\u2029') {
			return '?'
		}
		return r
	}, s)
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

// Apply applies the stages of a plan on the hosts with changes. Each step is
// checked again right before it is applied. Failures go to errOut. It returns
// false when a host failed, in the plan or in the apply.
func Apply(ctx context.Context, plan *Plan, connect Connect, out, errOut io.Writer) bool {
	failed := map[string]bool{}
	for name := range plan.Failed {
		failed[name] = true
	}
	changed := map[string]bool{}
	states := map[string]*module.State{}
	for _, sp := range plan.Stages {
		for _, hp := range sp.Hosts {
			if !hp.changes() || failed[hp.Host.Name] {
				continue
			}
			if states[hp.Host.Name] == nil {
				states[hp.Host.Name] = &module.State{}
			}
			ok, err := apply(ctx, connect, hp, states[hp.Host.Name], out)
			if err != nil {
				fmt.Fprintf(errOut, "%s: failed: %v\n", hp.Host.Name, err)
				failed[hp.Host.Name] = true
				delete(changed, hp.Host.Name)
				continue
			}
			if ok {
				changed[hp.Host.Name] = true
			}
		}
	}
	fmt.Fprintf(out, "\n%s: %d changed, %d unchanged%s\n", hosts(len(plan.Hosts)),
		len(changed), len(plan.Hosts)-len(changed)-len(failed), failures(len(failed)))
	return len(failed) == 0
}

// apply runs the planned steps of a stage on one host. It reports whether a
// step changed something.
func apply(ctx context.Context, connect Connect, hp HostPlan, state *module.State, out io.Writer) (changed bool, err error) {
	conn, err := connect(ctx, hp.Host)
	if err != nil {
		return false, err
	}
	defer func() {
		if cerr := conn.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	for _, p := range hp.Steps {
		res, err := conn.Apply(ctx, p.Step.Module, p.Step.Args, state)
		if err != nil {
			return changed, fmt.Errorf("%s: %w", label(p.Step), err)
		}
		if res.Status == module.Change {
			changed = true
			fmt.Fprintf(out, "%s: %s %s\n", hp.Host.Name, marks[res.Action], label(p.Step))
		}
	}
	return changed, nil
}
