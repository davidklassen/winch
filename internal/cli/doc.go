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
	if len(args) == 0 {
		writeIndex(env.stdout, project.Groups())
		return exitOK
	}
	ts := project.Topics()
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

func writeIndex(out io.Writer, groups []doc.Group) {
	fmt.Fprintf(out, "%s\n", docIntro)
	// One width for all groups, so that the topic lines align.
	width := 0
	for _, g := range groups {
		for _, t := range g.Topics {
			width = max(width, len(t.Name))
		}
	}
	for _, g := range groups {
		fmt.Fprintf(out, "\n%s:\n", g.Title)
		for _, t := range g.Topics {
			fmt.Fprintf(out, "  %-*s  %s\n", width, t.Name, t.Text)
		}
	}
	fmt.Fprint(out, "\nModules:\n")
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, name := range module.Names() {
		d, _ := module.Reference(name)
		fmt.Fprintf(w, "  %s\t%s\n", name, d.Text)
	}
	w.Flush()
	fmt.Fprintln(out, "\nRun \"winch doc <topic>\" or \"winch doc <module>\" for more.")
}

// writeTopic writes the blocks of t, then each of its keys with the keys of
// their values, by their path, or its functions, then its example.
func writeTopic(out io.Writer, t doc.Topic) {
	fmt.Fprintf(out, "%s: %s\n\n", t.Name, t.Text)
	blocks, example := t.Blocks, ""
	if n := len(blocks); n > 0 && blocks[n-1].Kind == doc.KindExample {
		blocks, example = blocks[:n-1], blocks[n-1].Text
	}
	writeBlocks(out, blocks)
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
	if example != "" {
		writeExample(out, example)
	}
	if len(t.Keys) > 0 {
		fmt.Fprintf(out, "\nRun \"winch doc %s.<key>\" for the full text of a key.\n", t.Name)
	}
	if len(t.Functions) > 0 {
		fmt.Fprintf(out, "\nRun \"winch doc %s.<function>\" for the full text of a function.\n", t.Name)
	}
}

// writeBlocks writes the blocks of a topic page. Blocks after a heading are
// indented by two spaces. A table, a code block, or a numbered list after a
// paragraph is indented by two more. A list follows a paragraph without an
// empty line.
func writeBlocks(out io.Writer, blocks []doc.Block) {
	indent := ""
	var prev doc.Block
	for i, b := range blocks {
		listAfterParagraph := b.Kind == doc.KindList && !b.Ordered && prev.Kind == doc.KindParagraph
		if i > 0 && prev.Kind != doc.KindHeading && !listAfterParagraph {
			fmt.Fprintln(out)
		}
		in := indent
		if prev.Kind == doc.KindParagraph && (b.Kind == doc.KindTable || b.Kind == doc.KindCode || b.Ordered) {
			in += "  "
		}
		switch b.Kind {
		case doc.KindHeading:
			fmt.Fprintf(out, "%s:\n", b.Text)
			indent = "  "
		case doc.KindParagraph:
			writeLines(out, in, in, b.Text)
		case doc.KindCode:
			writeLines(out, in, in, strings.TrimSuffix(b.Text, "\n"))
		case doc.KindList:
			for j, item := range b.Items {
				marker := "- "
				if b.Ordered {
					marker = fmt.Sprintf("%d. ", j+1)
				}
				writeLines(out, in+marker, in+strings.Repeat(" ", len(marker)), item)
			}
		case doc.KindTable:
			var t strings.Builder
			w := tabwriter.NewWriter(&t, 0, 0, 2, ' ', 0)
			for _, row := range b.Rows {
				// A line break in a cell continues the cell on a row of
				// its own.
				lines := make([][]string, len(row))
				n := 0
				for c, cell := range row {
					lines[c] = strings.Split(cell, "\n")
					n = max(n, len(lines[c]))
				}
				for l := range n {
					cells := make([]string, len(row))
					for c := range row {
						if l < len(lines[c]) {
							cells[c] = lines[c][l]
						}
					}
					fmt.Fprintf(w, "%s%s\n", in, strings.Join(cells, "\t"))
				}
			}
			w.Flush()
			for line := range strings.Lines(t.String()) {
				fmt.Fprintln(out, strings.TrimRight(line, " \n"))
			}
		}
		prev = b
	}
}

// writeLines writes each line of text, the first after first, the others
// after rest. An empty line stays empty.
func writeLines(out io.Writer, first, rest, text string) {
	for j, line := range strings.Split(text, "\n") {
		switch {
		case line == "":
			fmt.Fprintln(out)
		case j == 0:
			fmt.Fprintf(out, "%s%s\n", first, line)
		default:
			fmt.Fprintf(out, "%s%s\n", rest, line)
		}
	}
}

func writeExample(out io.Writer, example string) {
	fmt.Fprintln(out, "\nExample:")
	writeLines(out, "  ", "  ", strings.TrimSuffix(example, "\n"))
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
