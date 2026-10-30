package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/yamlx"
)

const docHelp = `Examples:
  winch doc
  winch doc file
  winch doc file.mode
  winch doc firewall.allow.tcp

Show the module reference: the list of modules, the keys of one module
with an example step, or the full text of one key.

Usage: winch doc [<module>[.<key>[.<key>]]]

doc needs no project.
`

func doc(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) > 1 {
		printError(env.stderr, "winch: doc takes one module or one key")
		return exitInvalid
	}
	if len(args) == 0 {
		w := tabwriter.NewWriter(env.stdout, 0, 0, 2, ' ', 0)
		for _, name := range module.Names() {
			d, _ := module.Reference(name)
			fmt.Fprintf(w, "%s\t%s\n", name, d.Text)
		}
		w.Flush()
		fmt.Fprintln(env.stdout, "\nRun \"winch doc <module>\" for the keys of a module.")
		return exitOK
	}
	path := strings.Split(args[0], ".")
	name := path[0]
	d, ok := module.Reference(name)
	if !ok {
		printError(env.stderr, fmt.Sprintf("winch doc: unknown module %q%s", name, yamlx.Suggest(name, module.Names())))
		return exitInvalid
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
	var k module.Key
	keys := d.Keys
	for j, key := range path[1:] {
		i := slices.IndexFunc(keys, func(k module.Key) bool { return k.Name == key })
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
		fmt.Fprintln(env.stdout, "\nKeys of each element:")
		writeKeys(env.stdout, k.Keys)
	}
	return exitOK
}

// writeKeys writes a line for each key: its name, type, default, and the
// first sentence of its text.
func writeKeys(out io.Writer, keys []module.Key) {
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
