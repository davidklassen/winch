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
// all three results. As letters, they pass the checks of names, paths, and
// base64. Their bytes differ in the top 6 bits, so their base64 forms start
// with different characters.
var placeholders = [3]string{1: "aaaaaaaa", 2: "zzzzzzzzzzzz"}

// Placeholder returns the placeholder of the variant n, 1 or 2.
func Placeholder(n int) string { return placeholders[n] }

// Mask returns real with each part that differs from a or b replaced by Mark,
// and these parts of real. a and b are the results with placeholders.
func Mask(real, a, b string) (string, []string) {
	pieces, parts := mask(real, a, b)
	return strings.Join(pieces, Mark), parts
}

// mask returns the pieces of real that the output shows, with Mark between
// two pieces, and the non-empty parts of real in place of the marks. The
// pieces are the text between the placeholders in a and b. A placeholder
// letter next to plain text can split a at another place than b. The pieces
// then differ, and the whole text between the common prefix and suffix is
// one part. So does a change of the placeholder, such as base64. A secret
// can hold the text of a piece, so the parts are those of the first and of
// the last place of each piece in real.
func mask(real, a, b string) (pieces, parts []string) {
	if real == a && real == b {
		return []string{real}, nil
	}
	pre, suf := common(real, a, b)
	r := real[pre : len(real)-suf]
	pa := strings.Split(a[pre:len(a)-suf], placeholders[1])
	pb := strings.Split(b[pre:len(b)-suf], placeholders[2])
	var found []string
	from := 0
	if len(pa) > 1 && slices.Equal(pa, pb) {
		for _, p := range pa {
			i := strings.Index(r[from:], p)
			if p == "" || i < 0 {
				continue
			}
			parts = append(parts, r[from:from+i])
			found = append(found, p)
			from += i + len(p)
		}
	}
	parts = append(parts, r[from:])
	last := make([]string, len(found)+1)
	to := len(r)
	for k, p := range slices.Backward(found) {
		i := strings.LastIndex(r[:to], p)
		last[k+1], to = r[i+len(p):to], i
	}
	last[0] = r[:to]
	for _, p := range last {
		if !slices.Contains(parts, p) {
			parts = append(parts, p)
		}
	}
	pieces = append(append([]string{real[:pre]}, found...), real[len(real)-suf:])
	return pieces, slices.DeleteFunc(parts, func(p string) bool { return p == "" })
}

// MaskLines is Mask for text with lines, such as a command: it masks each
// line on its own when a and b have the lines of real. It returns the masked
// parts of real.
func MaskLines(real, a, b string) (shown string, parts []string) {
	rl, al, bl := strings.Split(real, "\n"), strings.Split(a, "\n"), strings.Split(b, "\n")
	if len(rl) != len(al) || len(rl) != len(bl) {
		rl, al, bl = []string{real}, []string{a}, []string{b}
	}
	for i := range rl {
		var p []string
		rl[i], p = Mask(rl[i], al[i], bl[i])
		parts = append(parts, p...)
	}
	return strings.Join(rl, "\n"), parts
}

// common returns the length of the prefix and of the suffix that real, a,
// and b share, without overlap.
func common(real, a, b string) (pre, suf int) {
	for pre < len(real) && pre < len(a) && pre < len(b) && real[pre] == a[pre] && real[pre] == b[pre] {
		pre++
	}
	for suf < len(real)-pre && suf < len(a)-pre && suf < len(b)-pre &&
		real[len(real)-1-suf] == a[len(a)-1-suf] && real[len(real)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	return pre, suf
}

// MaskValue returns the value real with each part that differs from a or b,
// the same value with placeholders, as Mark: the masked part of each string,
// line by line, and every other leaf that differs. It also returns these
// parts of real. Map keys are not parts.
func MaskValue(real, a, b any) (shown any, parts []string) {
	shown = maskValue(real, a, b, &parts)
	return shown, parts
}

func maskValue(real, a, b any, parts *[]string) any {
	switch r := real.(type) {
	case map[string]any:
		am, ok1 := a.(map[string]any)
		bm, ok2 := b.(map[string]any)
		if !ok1 || !ok2 {
			return leaves(r, parts)
		}
		m := make(map[string]any, len(r))
		for _, k := range slices.Sorted(maps.Keys(r)) {
			m[k] = maskValue(r[k], am[k], bm[k], parts)
		}
		return m
	case []any:
		al, ok1 := a.([]any)
		bl, ok2 := b.([]any)
		if !ok1 || !ok2 || len(al) != len(r) || len(bl) != len(r) {
			return leaves(r, parts)
		}
		l := make([]any, len(r))
		for i := range r {
			l[i] = maskValue(r[i], al[i], bl[i], parts)
		}
		return l
	case string:
		as, ok1 := a.(string)
		bs, ok2 := b.(string)
		if !ok1 || !ok2 {
			return leaves(r, parts)
		}
		shown, p := MaskLines(r, as, bs)
		*parts = append(*parts, p...)
		return shown
	}
	if !reflect.DeepEqual(real, a) || !reflect.DeepEqual(real, b) {
		return leaves(real, parts)
	}
	return real
}

// leaves returns v with each leaf as Mark, and adds the text of each leaf.
func leaves(v any, parts *[]string) any {
	switch v := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(v))
		for _, k := range slices.Sorted(maps.Keys(v)) {
			m[k] = leaves(v[k], parts)
		}
		return m
	case []any:
		l := make([]any, len(v))
		for i, x := range v {
			l[i] = leaves(x, parts)
		}
		return l
	case nil:
		return nil
	}
	if s := fmt.Sprint(v); s != "" {
		*parts = append(*parts, s)
	}
	return Mark
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
	// pieces are the parts of Text between the marks of Show, and parts the
	// parts of Text in their place.
	pieces, parts []string
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
			pieces, parts := mask(s, ya[j], yb[j])
			out[i] = Line{Text: s, Show: strings.Join(pieces, Mark), Secret: true, pieces: pieces, parts: parts}
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
// it holds the pieces of the line in order, the first at its start and the
// last at its end.
func fit(old string, add, all []Line) (string, bool) {
	for _, set := range [][]Line{add, all} {
		for _, l := range set {
			if !l.Secret || l.Block {
				continue
			}
			if fits(old, l.pieces) {
				return l.Show, true
			}
		}
	}
	return "", false
}

func fits(s string, pieces []string) bool {
	first, last := pieces[0], pieces[len(pieces)-1]
	if len(s) < len(first)+len(last) || !strings.HasPrefix(s, first) || !strings.HasSuffix(s, last) {
		return false
	}
	s = s[len(first) : len(s)-len(last)]
	for _, p := range pieces[1 : len(pieces)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return true
}

// Parts returns the parts of the line that come from a secret.
func (l Line) Parts() []string {
	if l.Block {
		return []string{strings.TrimSuffix(strings.SplitAfter(l.Text, "\n")[0], "\n")}
	}
	return l.parts
}
