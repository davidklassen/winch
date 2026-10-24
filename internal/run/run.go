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
	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
)

// Conn is a session with one host.
type Conn interface {
	Facts(ctx context.Context) (facts.Facts, error)
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

// Planned is a module step for one host. In is the recipe step that the step
// belongs to, or nil for a module step of the stage.
type Planned struct {
	Step   project.Step
	In     *project.Step
	Result module.Result
}

func (h HostPlan) changes() bool {
	return slices.ContainsFunc(h.Steps, func(p Planned) bool { return p.Result.Status == module.Change })
}

// hostRun is what the plan keeps about a host between its stages.
type hostRun struct {
	state module.State
	// facts are nil until the first contact with the host.
	facts *facts.Facts
}

// MakePlan checks every step on every host, stage by stage. At the first
// contact with a host, it reads the facts and checks the requirements of the
// recipes that the host runs. A host that fails stops there.
func MakePlan(ctx context.Context, p *project.Project, connect Connect) *Plan {
	plan := &Plan{Failed: map[string]error{}}
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
				runs[h.Name] = &hostRun{}
			}
			steps, err := check(ctx, connect, h, stage, p.Pipeline.Recipes[h.Name], runs[h.Name])
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
// reads the facts and checks the requirements of the host's recipes.
func check(ctx context.Context, connect Connect, h project.Host, stage *project.Stage, recipes []*project.Recipe, hr *hostRun) (steps []Planned, err error) {
	conn, err := connect(ctx, h)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	if hr.facts == nil {
		f, err := conn.Facts(ctx)
		if err != nil {
			return nil, err
		}
		hr.facts = &f
		for _, r := range recipes {
			if err := r.Check(f); err != nil {
				return nil, err
			}
		}
	}
	steps, err = evaluate(stage, h)
	if err != nil {
		return nil, err
	}
	for i, p := range steps {
		steps[i].Result, err = conn.Check(ctx, p.Step.Module, p.Step.Args, &hr.state)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label(p.Step), err)
		}
	}
	return steps, nil
}

// evaluate returns the module steps of a stage for one host, with the recipe
// steps expanded.
func evaluate(stage *project.Stage, h project.Host) ([]Planned, error) {
	var out []Planned
	for i := range stage.Steps {
		var in *project.Step
		todo := stage.Steps[i : i+1]
		if stage.Steps[i].Recipe != nil {
			in = &stage.Steps[i]
			todo = in.Recipe.Steps
		}
		for _, st := range todo {
			st, err := st.For(h)
			if err != nil {
				return nil, err
			}
			out = append(out, Planned{Step: st, In: in})
		}
	}
	return out, nil
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

// label is the text of a step in the plan and the logs.
func label(st project.Step) string {
	l := st.Module + " " + st.Args.Main()
	if st.Name != "" {
		l = st.Name + ": " + l
	}
	return printable(l)
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
			var in *project.Step
			for _, p := range hp.Steps {
				if p.Result.Status != module.Change {
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
				writeStep(b, indent, p.Step, p.Result)
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
	if st.Name != "" {
		return printable(st.Name)
	}
	return st.Recipe.Name
}

func writeStep(w io.Writer, indent string, st project.Step, res module.Result) {
	fmt.Fprintf(w, "%s%s %s\n", indent, marks[res.Action], label(st))
	for _, c := range res.Changes {
		fmt.Fprintf(w, "%s    %s\n", indent, printable(c))
	}
	t, ok := st.Args.(module.WithContent)
	if res.Old == nil || !ok {
		return
	}
	text := t.Text()
	if text == nil {
		fmt.Fprintf(w, "%s    content (binary or larger than 1 MiB)\n", indent)
		return
	}
	d := diff.Diff([]byte(*res.Old), []byte(*text))
	for _, line := range strings.SplitAfter(string(d), "\n") {
		if line != "" {
			fmt.Fprintf(w, "%s    %s\n", indent, printable(strings.TrimSuffix(line, "\n")))
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

// Apply applies every stage of a plan on the hosts with a change in the plan.
// A stage can undo what an earlier stage does, so a stage without a change
// runs too. Each step is checked again right before it is applied. Failures
// go to errOut. It returns false when a host failed, in the plan or in the
// apply.
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
	states := map[string]*module.State{}
	for _, sp := range plan.Stages {
		for _, hp := range sp.Hosts {
			if !toApply[hp.Host.Name] || failed[hp.Host.Name] {
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

// apply runs the steps of a stage on one host. It reports whether a
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
