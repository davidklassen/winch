package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/davidklassen/winch/internal/doc"
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
  winch doc --json

Show the reference: the index of topics and modules, a topic, the keys
of one module with an example step, or the full text of one key or
function.

Usage: winch doc [<topic> | <module>][.<key>...] [flags]

doc needs no project.

Flags:
  --json                        Print the whole reference as one JSON
                                document.
`

const docIntro = `Winch is a server configuration tool. It describes the desired state
of your servers in declarative YAML and provides commands to manage
that state.`

func docCommand(ctx context.Context, env Env, f *flags, args []string) int {
	if f.json {
		if len(args) > 0 {
			printError(env.stderr, "winch: doc --json takes no topic, module, or key")
			return exitInvalid
		}
		writeDocJSON(env.stdout)
		return exitOK
	}
	if len(args) > 1 {
		printError(env.stderr, "winch: doc takes one topic, module, or key")
		return exitInvalid
	}
	ts := project.Topics()
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
		keys = slices.Concat(ts[i].Keys, ts[i].Functions)
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
		fmt.Fprintf(env.stdout, "%s: %s\n\n", name, d.Text)
		if d.Body != "" {
			fmt.Fprintf(env.stdout, "%s\n\n", wrap(d.Body, 72))
		}
		fmt.Fprintln(env.stdout, "Keys:")
		writeKeys(env.stdout, d.Keys)
		writeExample(env.stdout, d.Example)
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
	fmt.Fprintf(out, "%s\n\nTopics:\n", docIntro)
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
// their values, by their path, or its functions, then its example.
func writeTopic(out io.Writer, t doc.Topic) {
	fmt.Fprintf(out, "%s: %s\n\n%s", t.Name, t.Text, t.Body)
	if len(t.Keys) > 0 {
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
	}
	if len(t.Functions) > 0 {
		fmt.Fprintln(out, "\nFunctions:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, f := range t.Functions {
			fmt.Fprintf(w, "  %s\t%s\n", f.Name, f.Summary())
		}
		w.Flush()
	}
	if t.Example != "" {
		writeExample(out, t.Example)
	}
	if len(t.Keys) > 0 {
		fmt.Fprintf(out, "\nRun \"winch doc %s.<key>\" for the full text of a key.\n", t.Name)
	}
	if len(t.Functions) > 0 {
		fmt.Fprintf(out, "\nRun \"winch doc %s.<function>\" for the full text of a function.\n", t.Name)
	}
}

func writeExample(out io.Writer, example string) {
	fmt.Fprintln(out, "\nExample:")
	for line := range strings.Lines(example) {
		if line != "\n" {
			line = "  " + line
		}
		fmt.Fprint(out, line)
	}
}

// writeKeys writes a line for each key: its name, type, default, and line.
func writeKeys(out io.Writer, keys []doc.Key) {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, k := range keys {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", k.Name, k.Type, cmp.Or(k.Default, "-"), k.Line)
	}
	w.Flush()
	for line := range strings.Lines(b.String()) {
		fmt.Fprintln(out, strings.TrimRight(line, " \n"))
	}
}

// wrap breaks each paragraph of text into lines of at most width characters
// at spaces.
func wrap(text string, width int) string {
	var b strings.Builder
	for i, para := range strings.Split(text, "\n\n") {
		if i > 0 {
			b.WriteString("\n\n")
		}
		n := 0
		for j, word := range strings.Fields(para) {
			switch {
			case j == 0:
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
	}
	return b.String()
}
