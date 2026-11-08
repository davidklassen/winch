package run

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
)

// Counts returns the number of hosts with changes, without changes, with
// only unknown steps, and failed.
func (p *Plan) Counts() (change, unchanged, unknown, failed int) {
	kinds := p.hostKinds()
	for _, h := range p.Hosts {
		switch {
		case p.Failed[h.Name] != nil:
			failed++
		case kinds[h.Name] == "change":
			change++
		case kinds[h.Name] == "unknown":
			unknown++
		default:
			unchanged++
		}
	}
	return change, unchanged, unknown, failed
}

// hostKinds returns "change" for each host whose plan has a change, and
// "unknown" for each host whose plan has only unknown steps.
func (p *Plan) hostKinds() map[string]string {
	kinds := map[string]string{}
	for name := range p.Pending {
		if p.rollsBack(name) {
			kinds[name] = "change"
		}
	}
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			switch {
			case hp.known():
				kinds[hp.Host.Name] = "change"
			case hp.changes() && kinds[hp.Host.Name] == "":
				kinds[hp.Host.Name] = "unknown"
			}
		}
	}
	return kinds
}

// Write prints the changes per host, hosts with the same changes together,
// then the summary and the plan hash. Failures go to errOut.
func (p *Plan) Write(out, errOut *color.Writer) {
	p.WriteNotes(errOut)
	bodies := map[string]*color.Text{}
	for name, pending := range p.Pending {
		if !p.rollsBack(name) {
			continue
		}
		b := &color.Text{}
		markLine(b, "  ", "!", " "+rollbackLabel+"\n")
		for _, l := range pending.Rollback {
			first, rest, _ := strings.Cut(l, "\n")
			fmt.Fprintf(b, "      %s%s\n", secret.Printable(first), lines(rest, "          "))
		}
		bodies[name] = b
	}
	kinds := p.hostKinds()
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			// A deferred step runs in each stage of a host that apply runs.
			if !hp.changes() && (!hp.deferred() || kinds[hp.Host.Name] == "") {
				continue
			}
			b := bodies[hp.Host.Name]
			if b == nil {
				b = &color.Text{}
				bodies[hp.Host.Name] = b
			}
			header(b, "  ", sp.Stage.Name)
			var in *project.Step
			for _, p := range hp.Steps {
				if !p.shows() && !p.Result.Deferred {
					continue
				}
				indent := "    "
				if p.In != nil {
					if p.In != in {
						header(b, "    ", recipeLabel(p.In))
					}
					indent = "      "
				}
				in = p.In
				if p.Handler != nil {
					markLine(b, indent, "!", " handler "+p.Handler.Handler.FullName()+"\n")
					for _, hs := range p.Handler.Steps {
						if hs.PendingThen {
							markLine(b, indent+"    ", "!", " then:"+command(hs.Step.Shown().Then, indent+"        ")+"\n")
						}
					}
					continue
				}
				if p.Result.Status != module.OK || p.Result.Deferred {
					writeStep(b, indent, p)
				}
				switch {
				case p.PendingThen:
					markLine(b, indent, "!", " then:"+command(p.Step.Shown().Then, indent+"    ")+"\n")
				case p.ThenRuns:
					fmt.Fprintf(b, "%s    then:%s\n", indent, command(p.Step.Shown().Then, indent+"      "))
				}
			}
			if h := sp.Stage.Health; h != nil && hp.changes() {
				mark := "*"
				if hp.PendingHealth {
					mark = "!"
				}
				markLine(b, "    ", mark, " health:"+command(h.Command, "        ")+"\n")
			}
		}
	}
	type group struct {
		hosts []string
		body  color.Text
		// key is the body without styles.
		key string
	}
	var groups []*group
	for _, h := range p.Hosts {
		b := bodies[h.Name]
		if b == nil || p.Failed[h.Name] != nil {
			continue
		}
		key := b.String()
		i := slices.IndexFunc(groups, func(g *group) bool { return g.key == key })
		if i < 0 {
			groups = append(groups, &group{body: *b, key: key})
			i = len(groups) - 1
		}
		groups[i].hosts = append(groups[i].hosts, h.Name)
	}
	for _, g := range groups {
		var t color.Text
		header(&t, "", groupName(g.hosts))
		t = append(t, g.body...)
		t.Add(color.Plain, "\n")
		color.Fprint(out, t)
	}
	for _, h := range p.Hosts {
		if err := p.Failed[h.Name]; err != nil {
			hostError(errOut, h.Name, err.Error())
		}
	}
	change, unchanged, unknown, failed := p.Counts()
	fmt.Fprintf(out, "%s: %d to change, %d unchanged, %d unknown%s\nplan %s\n",
		hosts(len(p.Hosts)), change, unchanged, unknown, failures(failed), p.Hash())
}

// Note is a fact about a host that needs no fix, or with Warning, a problem
// on a host to fix.
type Note struct {
	Host, Text string
	Warning    bool
}

// Notes returns the notes of the plan about the hosts that did not fail, each
// once.
func (p *Plan) Notes() []Note {
	var notes []Note
	add := func(host, text string, warning bool) {
		if n := (Note{host, text, warning}); !slices.Contains(notes, n) {
			notes = append(notes, n)
		}
	}
	for _, stage := range p.Stages {
		for _, host := range stage.Hosts {
			for _, step := range host.Steps {
				if p.Failed[host.Host.Name] != nil {
					continue
				}
				if len(step.Result.MissingUnitFiles) > 0 {
					s := module.Service{Name: step.Step.Shown().Args.Main()}
					add(host.Host.Name, s.Unit()+" does not exist", false)
				}
				for _, n := range step.missing {
					add(n.Host, n.Text, n.Warning)
				}
				for _, t := range step.Result.MissingTools {
					add(host.Host.Name, fmt.Sprintf("%s is missing; install the package %s in an earlier pkg step", t.Name, t.Package), true)
				}
			}
		}
	}
	for _, h := range p.Hosts {
		if p.Failed[h.Name] != nil {
			continue
		}
		for _, n := range p.goneHandlers[h.Name] {
			recipe, pipeline, stage, handler := project.ParseRecord(n)
			add(h.Name, "a pending "+p.place(recipe, pipeline, stage, handler)+" matches no handler and will not run", false)
		}
		for _, t := range p.goneThens[h.Name] {
			add(h.Name, goneThenNote(t, p.place(t.Recipe, t.Pipeline, t.Stage, t.Handler))+" and will not run", false)
		}
		for _, c := range p.gone[h.Name] {
			add(h.Name, goneNote(c, p.place(c.Recipe, c.Pipeline, c.Stage, c.Handler))+" and will not run", false)
		}
		for _, n := range p.waiting[h.Name] {
			recipe, pipeline, stage, handler := project.ParseRecord(n)
			owner := "stage"
			if recipe != "" {
				owner = "recipe"
			}
			add(h.Name, "a pending "+p.place(recipe, pipeline, stage, handler)+" waits until its "+owner+" runs on this host", false)
		}
	}
	return notes
}

func (p *Plan) WriteNotes(out *color.Writer) {
	for _, n := range p.Notes() {
		WriteNote(out, n)
	}
}

// WriteNote writes a note or a warning about a host.
func WriteNote(out *color.Writer, n Note) {
	kind := "note"
	if n.Warning {
		kind = "warning"
	}
	fmt.Fprintf(out, "%s: %s: %s\n", n.Host, kind, secret.Printable(n.Text))
}

// goneNote names the gate, or the assert of an older winch, of record c at
// place.
func goneNote(c protocol.Check, place string) string {
	if c.Step == 0 {
		return "a pending health gate of " + place + " matches no gate"
	}
	return fmt.Sprintf("a pending assert of %s step %d matches no assert", place, c.Step)
}

// goneThenNote names the module and the scope of then record t that no step
// matches. A main argument can hold a secret: a record of winch 0.1.0 holds
// the plain argument.
func goneThenNote(t protocol.Then, place string) string {
	noun := "a " + t.Module + " step"
	if m, ok := module.New(t.Module); ok {
		noun = m.(interface{ Noun() string }).Noun()
	}
	return fmt.Sprintf("a pending then of %s in %s matches no step", noun, place)
}

// place names the recipe, stage, or handler of a record, with the pipeline of
// a stage when it is not the pipeline of the plan.
func (p *Plan) place(recipe, pipeline, stage, handler string) string {
	var s string
	switch {
	case handler != "":
		s = "handler " + cmp.Or(recipe, stage) + "." + handler
	case recipe != "":
		s = "recipe " + recipe
	default:
		s = "stage " + stage
	}
	if recipe == "" && pipeline != p.pipeline {
		s += " of pipeline " + pipeline
	}
	return s
}

var markStyles = map[string]color.Style{"+": color.Green, "-": color.Red, "~": color.Yellow, "!": color.Cyan, "*": color.Cyan}

// markLine adds a line with a mark in its color after prefix.
func markLine(t *color.Text, prefix, mark, rest string) {
	t.Add(color.Plain, prefix)
	t.Add(markStyles[mark], mark)
	t.Add(color.Plain, rest)
}

// groupName names the hosts of a block of output that they share.
func groupName(hosts []string) string {
	name := strings.Join(hosts, ", ")
	if len(hosts) > 1 {
		name += fmt.Sprintf(" (%d hosts)", len(hosts))
	}
	return name
}

// header adds a bold line of a host, stage, or recipe.
func header(t *color.Text, indent, name string) {
	t.Add(color.Plain, indent)
	t.Add(color.Bold, name)
	t.Add(color.Plain, "\n")
}

// hostError writes the error of a host in red, with its later lines
// indented under the first.
func hostError(w *color.Writer, host, err string) {
	first, rest, _ := strings.Cut(secret.PrintableLines(err), "\n")
	color.Fprint(w, color.Text{{Style: color.Red, Text: host + ": " + first + lines(rest, "  ") + "\n"}})
}

// command returns a command for the end of a line: after a space when it has
// one line, else as a block of lines with indent.
func command(cmd, indent string) string {
	cmd = strings.TrimSuffix(cmd, "\n")
	if !strings.Contains(cmd, "\n") {
		return " " + secret.Printable(cmd)
	}
	return lines(cmd, indent)
}

// lines returns text, when it is not empty, as a block of lines with indent
// for the end of a line.
func lines(text, indent string) string {
	if text == "" {
		return ""
	}
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		b.WriteString("\n")
		if line != "" {
			b.WriteString(indent + secret.Printable(line))
		}
	}
	return b.String()
}

func recipeLabel(st *project.Step) string {
	l := st.Recipe.Name
	if st.Name != "" {
		l += ": " + st.Name
	}
	return l
}

// linkNote names the symbolic link that a step follows.
func linkNote(link string) string {
	if link == "" {
		return ""
	}
	return " (link to " + secret.Printable(link) + ")"
}

func writeStep(t *color.Text, indent string, p Planned) {
	st, res := p.Step, p.Result
	mark := marks[res.Action]
	switch {
	case res.Status == module.Unknown:
		mark = "?"
	case res.Deferred:
		mark = "*"
	}
	main := ""
	shown := st.Shown()
	if m := shown.Args.Main(); m != "" {
		main = command(m, indent+"    ")
	}
	markLine(t, indent, mark, " "+secret.Printable(stepHead(st))+main+linkNote(res.Link)+"\n")
	for _, c := range res.Changes {
		first, rest, _ := strings.Cut(c, "\n")
		fmt.Fprintf(t, "%s    %s%s\n", indent, secret.Printable(first), lines(rest, indent+"        "))
	}
	for _, l := range diffLines(p) {
		t.Add(color.Plain, indent+"    ")
		t.Add(diffStyle(l), l)
		t.Add(color.Plain, "\n")
	}
	if v, ok := shown.Args.(module.WithValidate); ok && res.Validates {
		fmt.Fprintf(t, "%s    validate:%s\n", indent, command(v.ValidateCommand(), indent+"      "))
	}
	c, ok := shown.Args.(*module.Cmd)
	if !ok {
		return
	}
	if c.User != "" {
		fmt.Fprintf(t, "%s    user:%s\n", indent, command(c.User, indent+"      "))
	}
	if c.Dir != "" {
		fmt.Fprintf(t, "%s    dir:%s\n", indent, command(c.Dir, indent+"      "))
	}
	if u := c.UnlessCommand(); u != "" {
		fmt.Fprintf(t, "%s    unless:%s\n", indent, command(u, indent+"      "))
	}
	if res.Stderr != "" {
		fmt.Fprintf(t, "%s    stderr:%s\n", indent, lines(res.Stderr, indent+"      "))
	}
}

func diffStyle(line string) color.Style {
	switch {
	case strings.HasPrefix(line, "@@"):
		return color.Cyan
	case strings.HasPrefix(line, "+"):
		return color.Green
	case strings.HasPrefix(line, "-"):
		return color.Red
	}
	return color.Plain
}

// diffLines returns the diff of the content of a step, as the output shows
// it.
func diffLines(p Planned) []string {
	st, res := p.Step, p.Result
	t, ok := st.Args.(module.WithText)
	if res.Old == nil && res.OldReason == "" || !ok {
		return nil
	}
	text, reason := t.Text()
	if res.New != nil {
		text = []byte(*res.New)
	}
	if res.OldReason != "" {
		reason = res.OldReason
	}
	shown := st.Shown()
	switch {
	// The reason can come from the secret, also of the source of copy_from.
	case shown.Hidden || reason != "" && shown.Lines != nil || reason == secret.Mark:
		return []string{secret.Mark}
	case reason != "":
		return []string{"content (" + reason + ")"}
	}
	content := shown.Lines
	if content == nil {
		content = secret.Plain(text)
	}
	_, isLine := st.Args.(*module.Line)
	d := secret.Diff([]byte(*res.Old), res.Masked, content, isLine)
	var lines []string
	for _, line := range strings.SplitAfter(p.hostText(string(d)), "\n") {
		// The line numbers of a line step's hunk are not those of the file.
		if isLine && strings.HasPrefix(line, "@@") {
			continue
		}
		if line != "" {
			lines = append(lines, secret.Printable(strings.TrimSuffix(line, "\n")))
		}
	}
	return lines
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
