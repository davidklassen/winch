package secret

import (
	"bytes"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/diff"
)

// Mark replaces a secret in the output.
const Mark = "(secret)"

// placeholders replace each secret in the variants 1 and 2. They share no
// character, and their lengths differ, so no part of a secret is common to
// all three results. They have no control character, which a path cannot
// hold.
var placeholders = [3]string{1: "~^^^^^^~", 2: "`|||||||`"}

// Placeholder returns the placeholder of the variant n, 1 or 2.
func Placeholder(n int) string { return placeholders[n] }

// Mask returns real with the part that differs from a or b replaced by Mark,
// and that part of real. a and b are the results with placeholders.
func Mask(real, a, b string) (shown, part string) {
	if real == a && real == b {
		return real, ""
	}
	pre, suf := common(real, a, b)
	return pre + Mark + suf, real[len(pre) : len(real)-len(suf)]
}

// common returns the prefix and the suffix that real, a, and b share, without
// overlap.
func common(real, a, b string) (pre, suf string) {
	n := 0
	for n < len(real) && n < len(a) && n < len(b) && real[n] == a[n] && real[n] == b[n] {
		n++
	}
	m := 0
	for m < len(real)-n && m < len(a)-n && m < len(b)-n &&
		real[len(real)-1-m] == a[len(a)-1-m] && real[len(real)-1-m] == b[len(b)-1-m] {
		m++
	}
	return real[:n], real[len(real)-m:]
}

// Parts returns the parts of the value real that differ from a or b, the
// same value with placeholders: the masked part of each string, line by line,
// and the text of every other leaf that differs. Map keys are not parts.
func Parts(real, a, b any) []string {
	var out []string
	parts(real, a, b, &out)
	return out
}

func parts(real, a, b any, out *[]string) {
	switch r := real.(type) {
	case map[string]any:
		am, ok1 := a.(map[string]any)
		bm, ok2 := b.(map[string]any)
		if !ok1 || !ok2 {
			leaves(r, out)
			return
		}
		for _, k := range slices.Sorted(maps.Keys(r)) {
			parts(r[k], am[k], bm[k], out)
		}
	case []any:
		al, ok1 := a.([]any)
		bl, ok2 := b.([]any)
		if !ok1 || !ok2 || len(al) != len(r) || len(bl) != len(r) {
			leaves(r, out)
			return
		}
		for i := range r {
			parts(r[i], al[i], bl[i], out)
		}
	case string:
		as, ok1 := a.(string)
		bs, ok2 := b.(string)
		if !ok1 || !ok2 {
			leaves(r, out)
			return
		}
		rl, al, bl := strings.Split(r, "\n"), strings.Split(as, "\n"), strings.Split(bs, "\n")
		if len(rl) != len(al) || len(rl) != len(bl) {
			rl, al, bl = []string{r}, []string{as}, []string{bs}
		}
		for i := range rl {
			if _, part := Mask(rl[i], al[i], bl[i]); part != "" {
				*out = append(*out, part)
			}
		}
	default:
		if !reflect.DeepEqual(r, a) || !reflect.DeepEqual(r, b) {
			leaves(r, out)
		}
	}
}

// leaves adds the text of each leaf of v.
func leaves(v any, out *[]string) {
	switch v := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(v)) {
			leaves(v[k], out)
		}
	case []any:
		for _, x := range v {
			leaves(x, out)
		}
	case nil:
	default:
		if s := fmt.Sprint(v); s != "" {
			*out = append(*out, s)
		}
	}
}

// Line is a line of new content: its text for the host, and its text for the
// output.
type Line struct {
	Text string
	Show string
	// Secret is true when Show has a Mark.
	Secret bool
	// Block is true for a line of a secret that has another number of lines
	// than its placeholders. An old line never fits it.
	Block bool
	// prefix and suffix are the parts of Text around the Mark.
	prefix, suffix string
}

// Lines returns the lines of real, the content for the host, with each part
// that differs from the placeholder results a and b masked. It returns false
// when a and b have different numbers of lines.
func Lines(real, a, b []byte) ([]Line, bool) {
	x, ya, yb := diff.Lines(real), diff.Lines(a), diff.Lines(b)
	if len(ya) != len(yb) {
		return nil, false
	}
	out := make([]Line, len(x))
	for i, s := range x {
		out[i] = Line{Text: s, Show: s}
	}
	pairA, blockA := pairs(x, ya)
	pairB, blockB := pairs(x, yb)
	for i, s := range x {
		j, ok := pairA[i]
		if !ok {
			j, ok = pairB[i]
		}
		// The diff can pair a line that is the same in all three.
		ok = ok && (s != ya[j] || s != yb[j])
		switch {
		case blockA[i] || blockB[i]:
			out[i] = Line{Text: s, Show: withEnd(Mark, s), Secret: true, Block: true}
		case ok:
			pre, suf := common(s, ya[j], yb[j])
			out[i] = Line{Text: s, Show: pre + Mark + suf, Secret: true, prefix: pre, suffix: suf}
		}
	}
	return out, true
}

// pairs returns, for each line of x that differs from y, the line of y in
// its place, or block when the change has other line counts.
func pairs(x, y []string) (pair map[int]int, block map[int]bool) {
	pair, block = map[int]int{}, map[int]bool{}
	for _, h := range diff.Hunks(x, y) {
		for _, c := range changes(h) {
			if len(c.del) != len(c.add) {
				for _, i := range c.del {
					block[i] = true
				}
				continue
			}
			for k, i := range c.del {
				pair[i] = c.add[k]
			}
		}
	}
	return pair, block
}

// change is a run of removed and added lines in a hunk, by index.
type change struct {
	del, add []int
}

func changes(h diff.Hunk) []change {
	var out []change
	for k := 0; k < len(h.Ops); {
		if h.Ops[k].Kind == ' ' {
			k++
			continue
		}
		var c change
		for ; k < len(h.Ops) && h.Ops[k].Kind != ' '; k++ {
			if op := h.Ops[k]; op.Kind == '-' {
				c.del = append(c.del, op.X)
			} else {
				c.add = append(c.add, op.Y)
			}
		}
		out = append(out, c)
	}
	return out
}

// withEnd returns s with the line end of line.
func withEnd(s, line string) string {
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		return s + line[i:]
	}
	return s
}

const (
	hidden  = "(line hidden: may hold a secret)\n"
	changed = " (secret value changed)"
)

// Diff returns the diff of old, the content on the host, to the new lines,
// in the format of diff.Diff. In a change with a new secret line, an old line
// that fits a masked new line, first of the change and then of the whole
// content, is masked at the same places, and another old line is hidden. A new line
// whose old line had another secret gets a note.
func Diff(old []byte, lines []Line) []byte {
	x := diff.Lines(old)
	y := make([]string, len(lines))
	for i, l := range lines {
		y[i] = l.Text
	}
	if slices.Equal(x, y) {
		return nil
	}
	secrets := slices.DeleteFunc(slices.Clone(lines), func(l Line) bool { return !l.Secret || l.Block })
	var out bytes.Buffer
	for _, h := range diff.Hunks(x, y) {
		out.WriteString(h.Header())
		k := 0
		for _, c := range changes(h) {
			for ; h.Ops[k].Kind == ' '; k++ {
				out.WriteString(" " + lines[h.Ops[k].Y].Show)
			}
			k += len(c.del) + len(c.add)
			var add []Line
			for _, j := range c.add {
				add = append(add, lines[j])
			}
			hasSecret := slices.ContainsFunc(add, func(l Line) bool { return l.Secret })
			masked := map[string]bool{}
			for _, i := range c.del {
				if s, ok := fit(x[i], add, secrets); ok && hasSecret {
					masked[s] = true
					out.WriteString("-" + s)
					continue
				}
				if hasSecret {
					out.WriteString("-" + hidden)
					continue
				}
				out.WriteString("-" + x[i])
			}
			for _, l := range add {
				show := l.Show
				if l.Secret && !l.Block && masked[show] {
					head, tail, _ := strings.Cut(show, "\n")
					show = head + changed + "\n" + tail
				}
				out.WriteString("+" + show)
			}
		}
		for ; k < len(h.Ops); k++ {
			out.WriteString(" " + lines[h.Ops[k].Y].Show)
		}
	}
	return out.Bytes()
}

// fit returns the old line masked like the first secret line that it fits:
// it starts with the line's prefix and ends with its suffix.
func fit(old string, add, all []Line) (string, bool) {
	for _, set := range [][]Line{add, all} {
		for _, l := range set {
			if !l.Secret || l.Block {
				continue
			}
			if len(old) >= len(l.prefix)+len(l.suffix) && strings.HasPrefix(old, l.prefix) && strings.HasSuffix(old, l.suffix) {
				return l.prefix + Mark + l.suffix, true
			}
		}
	}
	return "", false
}

// Part returns the part of the line that comes from a secret, or "".
func (l Line) Part() string {
	if !l.Secret {
		return ""
	}
	if l.Block {
		return strings.TrimSuffix(strings.SplitAfter(l.Text, "\n")[0], "\n")
	}
	return l.Text[len(l.prefix) : len(l.Text)-len(l.suffix)]
}
