package cli

import (
	"cmp"
	"context"
	_ "embed"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/davidklassen/winch/internal/doc"
	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/yamlx"
)

const docHelp = `Examples:
  winch doc
  winch doc project
  winch doc step.when
  winch doc file
  winch doc file.mode
  winch doc firewall.allow.tcp

Show the reference: the index of topics and modules, a topic, the keys
of one module with an example step, or the full text of one key.

Usage: winch doc [<topic> | <module>][.<key>...]

doc needs no project.
`

//go:embed plan.md
var planTopic string

// topics returns the topics of winch doc, in index order.
func topics() []doc.Topic {
	return append(project.Topics(), facts.Topic(), doc.NewTopic("plan", planTopic, nil))
}

func docCommand(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) > 1 {
		printError(env.stderr, "winch: doc takes one topic, module, or key")
		return exitInvalid
	}
	ts := topics()
	if len(args) == 0 {
		writeIndex(env.stdout, ts)
		return exitOK
	}
	path := strings.Split(args[0], ".")
	name := path[0]
	var keys []doc.Key
	var d module.Doc
	i := slices.IndexFunc(ts, func(t doc.Topic) bool { return t.Name == name })
	isModule := false
	if i < 0 {
		d, isModule = module.Reference(name)
	}
	switch {
	case i >= 0:
		keys = ts[i].Keys
	case isModule:
		keys = d.Keys
	default:
		var names, paths []string
		for _, t := range ts {
			names = append(names, t.Name)
			if hasKeyPath(t.Keys, path) {
				paths = append(paths, t.Name+"."+args[0])
			}
		}
		names = append(names, module.Names()...)
		suggest := yamlx.Suggest(name, names)
		if len(paths) > 0 {
			if c := yamlx.Closest(args[0], names); c != "" {
				paths = append([]string{c}, paths...)
			}
			suggest = yamlx.DidYouMean(paths...)
		}
		printError(env.stderr, fmt.Sprintf("winch doc: unknown topic or module %q%s", name, suggest))
		return exitInvalid
	}
	if len(path) == 1 && i >= 0 {
		writeTopic(env.stdout, ts[i])
		return exitOK
	}
	if len(path) == 1 {
		fmt.Fprintf(env.stdout, "%s: %s\n\nKeys:\n", name, d.Text)
		writeKeys(env.stdout, d.Keys)
		fmt.Fprintln(env.stdout, "\nExample:")
		for line := range strings.Lines(d.Example) {
			if line != "\n" {
				line = "  " + line
			}
			fmt.Fprint(env.stdout, line)
		}
		fmt.Fprintf(env.stdout, "\nRun \"winch doc %s.<key>\" for the full text of a key.\n", name)
		return exitOK
	}
	var k doc.Key
	for j, key := range path[1:] {
		i := slices.IndexFunc(keys, func(k doc.Key) bool { return k.Name == key })
		if i < 0 {
			var names []string
			for _, k := range keys {
				names = append(names, k.Name)
			}
			printError(env.stderr, fmt.Sprintf("winch doc: %s has no key %q%s", strings.Join(path[:j+1], "."), key, yamlx.Suggest(key, names)))
			return exitInvalid
		}
		k, keys = keys[i], keys[i].Keys
	}
	head := k.Type
	switch k.Default {
	case "":
	case "required":
		head += ", required"
	default:
		head += ", default " + k.Default
	}
	fmt.Fprintf(env.stdout, "%s: %s\n\n%s\n", args[0], head, wrap(k.Text, 72))
	if len(k.Keys) > 0 {
		if k.Type == "list of maps" {
			fmt.Fprintln(env.stdout, "\nKeys of each element:")
		} else {
			fmt.Fprintln(env.stdout, "\nKeys:")
		}
		writeKeys(env.stdout, k.Keys)
	}
	return exitOK
}

// hasKeyPath reports whether path names a key in keys, one part per level.
func hasKeyPath(keys []doc.Key, path []string) bool {
	for _, name := range path {
		i := slices.IndexFunc(keys, func(k doc.Key) bool { return k.Name == name })
		if i < 0 {
			return false
		}
		keys = keys[i].Keys
	}
	return true
}

func writeIndex(out io.Writer, ts []doc.Topic) {
	fmt.Fprint(out, `winch configures Linux servers over SSH from a project of YAML files.
Each step of a project uses a module, which checks and changes one kind of thing.

Topics:
`)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, t := range ts {
		fmt.Fprintf(w, "  %s\t%s\n", t.Name, t.Text)
	}
	w.Flush()
	fmt.Fprint(out, "\nModules:\n")
	w = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, name := range module.Names() {
		d, _ := module.Reference(name)
		fmt.Fprintf(w, "  %s\t%s\n", name, d.Text)
	}
	w.Flush()
	fmt.Fprintln(out, "\nRun \"winch doc <topic>\" or \"winch doc <module>\" for more.")
}

// writeTopic writes the text of t, then each of its keys with the keys of
// their values, by their path.
func writeTopic(out io.Writer, t doc.Topic) {
	fmt.Fprintf(out, "%s: %s\n\n%s", t.Name, t.Text, t.Body)
	if len(t.Keys) == 0 {
		return
	}
	var all []doc.Key
	var add func(prefix string, keys []doc.Key)
	add = func(prefix string, keys []doc.Key) {
		for _, k := range keys {
			sub := k.Keys
			k.Name, k.Keys = prefix+k.Name, nil
			all = append(all, k)
			add(k.Name+".", sub)
		}
	}
	add("", t.Keys)
	fmt.Fprintln(out, "\nKeys:")
	writeKeys(out, all)
	fmt.Fprintf(out, "\nRun \"winch doc %s.<key>\" for the full text of a key.\n", t.Name)
}

// writeKeys writes a line for each key: its name, type, default, and the
// first sentence of its text.
func writeKeys(out io.Writer, keys []doc.Key) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, k := range keys {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", k.Name, k.Type, cmp.Or(k.Default, "-"), k.Summary())
	}
	w.Flush()
}

// wrap breaks text into lines of at most width characters at spaces.
func wrap(text string, width int) string {
	var b strings.Builder
	n := 0
	for i, word := range strings.Fields(text) {
		switch {
		case i == 0:
		case n+1+len(word) > width:
			b.WriteByte('\n')
			n = 0
		default:
			b.WriteByte(' ')
			n++
		}
		b.WriteString(word)
		n += len(word)
	}
	return b.String()
}
