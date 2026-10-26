package run

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/diff"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

// Counts returns the number of hosts with changes, without changes, and
// failed.
func (p *Plan) Counts() (change, unchanged, failed int) {
	for _, h := range p.Hosts {
		switch {
		case p.Failed[h.Name] != nil:
			failed++
		case p.changes(h.Name):
			change++
		default:
			unchanged++
		}
	}
	return change, unchanged, failed
}

// changes reports whether the host has changes in a stage.
func (p *Plan) changes(host string) bool {
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			if hp.Host.Name == host && hp.changes() {
				return true
			}
		}
	}
	return false
}

// Write prints the changes per host, hosts with the same changes together,
// then the summary and the plan hash. Failures go to errOut.
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
					fmt.Fprintf(b, "%s! handler %s\n", indent, p.Handler.Handler.FullName())
					continue
				}
				if p.Result.Status == module.Change {
					writeStep(b, indent, p.Step, p.Result)
				}
				switch {
				case p.PendingThen:
					fmt.Fprintf(b, "%s! then:%s\n", indent, command(p.Step.ShownThen(), indent+"    "))
				case p.ThenRuns:
					fmt.Fprintf(b, "%s    then:%s\n", indent, command(p.Step.ShownThen(), indent+"      "))
				}
			}
			if h := sp.Stage.Health; h != nil {
				fmt.Fprintf(b, "    * health:%s\n", command(h.Command, "        "))
			}
		}
	}
	type group struct {
		hosts []string
		body  string
	}
	var groups []*group
	for _, h := range p.Hosts {
		b := bodies[h.Name]
		if b == nil || p.Failed[h.Name] != nil {
			continue
		}
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
			fmt.Fprintf(errOut, "%s: %s\n", h.Name, secret.PrintableLines(err.Error()))
		}
	}
	change, unchanged, failed := p.Counts()
	fmt.Fprintf(out, "%s: %d to change, %d unchanged, 0 unknown%s\nplan %s\n",
		hosts(len(p.Hosts)), change, unchanged, failures(failed), p.Hash())
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

func writeStep(w io.Writer, indent string, st project.Step, res module.Result) {
	fmt.Fprintf(w, "%s%s %s%s\n", indent, marks[res.Action], label(st), linkNote(res.Link))
	for _, c := range res.Changes {
		fmt.Fprintf(w, "%s    %s\n", indent, secret.Printable(c))
	}
	for _, l := range diffLines(st, res) {
		fmt.Fprintf(w, "%s    %s\n", indent, l)
	}
}

// diffLines returns the diff of the content of a step, as the output shows
// it.
func diffLines(st project.Step, res module.Result) []string {
	t, ok := st.Args.(module.WithContent)
	if res.Old == nil || !ok {
		return nil
	}
	text := t.Text()
	var d []byte
	switch {
	case text == nil:
		return []string{"content (binary or larger than 1 MiB)"}
	case st.Shown != nil && st.Shown.Hidden:
		d = []byte(secret.Mark + "\n")
	case st.Shown != nil && st.Shown.Lines != nil:
		d = secret.Diff([]byte(*res.Old), st.Shown.Lines)
	default:
		d = diff.Diff([]byte(*res.Old), []byte(*text))
	}
	var lines []string
	for _, line := range strings.SplitAfter(string(d), "\n") {
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
