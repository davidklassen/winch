package run

import (
	"fmt"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/diff"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
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
							markLine(b, indent+"    ", "!", " then:"+command(hs.Step.ShownThen(), indent+"        ")+"\n")
						}
					}
					continue
				}
				if p.Result.Status != module.OK || p.Result.Deferred {
					writeStep(b, indent, p.Step, p.Result)
				}
				switch {
				case p.PendingThen:
					markLine(b, indent, "!", " then:"+command(p.Step.ShownThen(), indent+"    ")+"\n")
				case p.ThenRuns:
					fmt.Fprintf(b, "%s    then:%s\n", indent, command(p.Step.ShownThen(), indent+"      "))
				}
			}
			if h := sp.Stage.Health; h != nil && hp.changes() {
				markLine(b, "    ", "*", " health:"+command(h.Command, "        ")+"\n")
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

func (p *Plan) WriteNotes(out *color.Writer) {
	for _, stage := range p.Stages {
		for _, host := range stage.Hosts {
			for _, step := range host.Steps {
				if len(step.Result.MissingUnitFiles) > 0 && p.Failed[host.Host.Name] == nil {
					s := module.Service{Name: step.Step.ShownMain()}
					fmt.Fprintf(out, "%s: %s: unit file not found\n", host.Host.Name, secret.Printable(s.Unit()))
				}
			}
		}
	}
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

// hostError writes the error of a host in red.
func hostError(w *color.Writer, host, err string) {
	color.Fprint(w, color.Text{{Style: color.Red, Text: host + ": " + secret.PrintableLines(err) + "\n"}})
}

// command returns a command for the end of a line: after a space when it has
// one line, else as a block of lines with indent.
func command(cmd, indent string) string {
	cmd = strings.TrimSuffix(cmd, "\n")
	if !strings.Contains(cmd, "\n") {
		return " " + secret.Printable(cmd)
	}
	var b strings.Builder
	for line := range strings.SplitSeq(cmd, "\n") {
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

func writeStep(t *color.Text, indent string, st project.Step, res module.Result) {
	mark := marks[res.Action]
	switch {
	case res.Status == module.Unknown:
		mark = "?"
	case res.Deferred:
		mark = "*"
	}
	markLine(t, indent, mark, " "+label(st)+linkNote(res.Link)+"\n")
	for _, c := range res.Changes {
		fmt.Fprintf(t, "%s    %s\n", indent, secret.Printable(c))
	}
	for _, l := range diffLines(st, res) {
		t.Add(color.Plain, indent+"    ")
		t.Add(diffStyle(l), l)
		t.Add(color.Plain, "\n")
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
func diffLines(st project.Step, res module.Result) []string {
	t, ok := st.Args.(module.WithText)
	if res.Old == nil && res.OldReason == "" || !ok {
		return nil
	}
	text, reason := t.Text()
	if res.OldReason != "" {
		reason = res.OldReason
	}
	hidden := st.Shown != nil && st.Shown.Hidden
	masked := st.Shown != nil && st.Shown.Lines != nil
	var d []byte
	switch {
	// The reason can come from the secret.
	case hidden || reason != "" && masked:
		return []string{secret.Mark}
	case reason != "":
		return []string{"content (" + reason + ")"}
	case masked:
		d = secret.Diff([]byte(*res.Old), st.Shown.Lines)
	default:
		d = diff.Diff([]byte(*res.Old), text)
	}
	_, isLine := st.Args.(*module.Line)
	var lines []string
	for _, line := range strings.SplitAfter(string(d), "\n") {
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
