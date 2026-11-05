package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"iter"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Filter replaces the secret values of a run, private key blocks, and tokens
// in text with Mark.
type Filter struct {
	mu sync.Mutex
	// values holds each value and its encoded forms.
	values map[string]bool
	// plain holds the lines of plain project text, without the white space
	// around them.
	plain map[string]bool
}

func NewFilter() *Filter {
	return &Filter{values: map[string]bool{}, plain: map[string]bool{}}
}

// Add adds a secret value and each of its Lines in the forms that the output
// can show. It skips a value shorter than 4 characters without the white
// space around it, and true and false.
func (f *Filter) Add(value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, exact := range append([]string{value}, f.lines(value)...) {
		if counts(strings.TrimSpace(exact)) {
			for _, s := range forms(exact) {
				f.values[s] = true
			}
		}
	}
}

// Lines returns the lines of a multi-line value that count on their own:
// each line that Add does not skip and that is not a line of plain project
// text.
func (f *Filter) Lines(value string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lines(value)
}

func (f *Filter) lines(value string) []string {
	if !strings.Contains(strings.TrimSpace(value), "\n") {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(value, "\n") {
		if v := strings.TrimSpace(l); counts(v) && !f.plain[v] {
			lines = append(lines, l)
		}
	}
	return lines
}

func counts(v string) bool {
	return utf8.RuneCountInString(v) >= 4 && v != "true" && v != "false"
}

// forms returns the forms of exact that the output can show: without the
// white space around it, in plain and JSON-escaped form, and as the output
// prints it, also JSON-escaped; and the base64 and URL-encoded forms of both
// the trimmed and the exact text.
func forms(exact string) []string {
	v := strings.TrimSpace(exact)
	var out []string
	for _, s := range []string{v, Printable(v), PrintableLines(v)} {
		j, _ := json.Marshal(s)
		out = append(out, s, string(j[1:len(j)-1]))
	}
	for _, s := range []string{v, exact} {
		out = append(out, base64.RawStdEncoding.EncodeToString([]byte(s)), url.QueryEscape(s), url.PathEscape(s))
	}
	return out
}

// Parts filters the text that parts make together, and returns it in the
// same parts. Each match becomes Mark. Overlapping and adjacent matches give
// one Mark. A newline stays, and a match inside a Mark of the text does not
// count. A Mark shows in the part where its match starts.
func (f *Filter) Parts(parts []string) []string {
	s := strings.Join(parts, "")
	f.mu.Lock()
	defer f.mu.Unlock()
	marked := match(s, maps.Keys(f.values))
	set := func(from, to int) {
		for i := from; i < to; i++ {
			marked[i] = true
		}
	}
	for _, p := range patterns {
		for _, m := range p.find(s) {
			set(m[0], m[1])
		}
	}
	keyBlocks(s, set)
	return split(s, marked, parts)
}

// Hide returns s with each of parts as Mark, like Filter.Parts: in the forms
// that Filter.Add knows, and in its Go-quoted form. It skips no part for its
// length.
func Hide(s string, parts []string) string {
	if len(parts) == 0 {
		return s
	}
	var values []string
	for _, p := range parts {
		values = append(values, p)
		values = append(values, forms(p)...)
		if q := strconv.Quote(p); q[1:len(q)-1] != p {
			values = append(values, q[1:len(q)-1])
		}
	}
	return split(s, match(s, slices.Values(values)), []string{s})[0]
}

// match marks the bytes of s that a value matches. A match inside a Mark of
// s does not count.
func match(s string, values iter.Seq[string]) []bool {
	marked := make([]bool, len(s))
	var marks [][2]int
	for i := 0; ; {
		j := strings.Index(s[i:], Mark)
		if j < 0 {
			break
		}
		marks = append(marks, [2]int{i + j, i + j + len(Mark)})
		i += j + len(Mark)
	}
	inMark := func(from, to int) bool {
		for _, m := range marks {
			if from >= m[0] && to <= m[1] {
				return true
			}
		}
		return false
	}
	for v := range values {
		if v == "" {
			continue
		}
		for i := 0; ; {
			j := strings.Index(s[i:], v)
			if j < 0 {
				break
			}
			if from, to := i+j, i+j+len(v); !inMark(from, to) {
				for k := from; k < to; k++ {
					marked[k] = true
				}
			}
			i += j + 1
		}
	}
	return marked
}

// split returns s, as parts make it, with each run of marked bytes as one
// Mark. A newline stays.
func split(s string, marked []bool, parts []string) []string {
	out := make([]string, len(parts))
	i := 0
	for k, p := range parts {
		var b strings.Builder
		for end := i + len(p); i < end; i++ {
			switch {
			case !marked[i] || s[i] == '\n':
				b.WriteByte(s[i])
			case i == 0 || !marked[i-1] || s[i-1] == '\n':
				b.WriteString(Mark)
			}
		}
		out[k] = b.String()
	}
	return out
}

// keyBlocks marks each private key block: from its header to its footer, or
// to the end of s. A line inside a block keeps its leading white space.
func keyBlocks(s string, set func(from, to int)) {
	inKey := false
	for ls := 0; ls < len(s); {
		le := strings.IndexByte(s[ls:], '\n')
		if le < 0 {
			le = len(s)
		} else {
			le += ls
		}
		pos := ls
		if inKey {
			start := ls + len(s[ls:le]) - len(strings.TrimLeft(s[ls:le], " \t"))
			if e := keyEnd.FindStringIndex(s[ls:le]); e != nil {
				set(start, ls+e[1])
				pos, inKey = ls+e[1], false
			} else {
				set(start, le)
				pos = le
			}
		}
		for pos < le {
			b := keyBegin.FindStringIndex(s[pos:le])
			if b == nil {
				break
			}
			from, after := pos+b[0], pos+b[1]
			e := keyEnd.FindStringIndex(s[after:le])
			if e == nil {
				set(from, le)
				inKey = true
				break
			}
			set(from, after+e[1])
			pos = after + e[1]
		}
		ls = le + 1
	}
}

// Unprintable reports whether r is a control, format, or line separator
// character other than tab, which could move the cursor, change the
// terminal, or show text in another order.
func Unprintable(r rune) bool {
	return r != '\t' && unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp)
}

// Printable replaces each Unprintable character in text from a host with "?".
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if Unprintable(r) {
			return '?'
		}
		return r
	}, s)
}

// PrintableLines is Printable for text with lines: it keeps each newline,
// and a \r\n line end becomes a newline.
func PrintableLines(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\n' && Unprintable(r) {
			return '?'
		}
		return r
	}, strings.ReplaceAll(s, "\r\n", "\n"))
}

// Plain adds the lines of plain project text. A line of a multi-line value
// that is also such a line does not count by itself. Call Plain before Add.
// It skips binary data, which has a NUL byte.
func (f *Filter) Plain(text []byte) {
	if bytes.IndexByte(text, 0) >= 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for line := range bytes.Lines(text) {
		f.plain[string(bytes.TrimSpace(line))] = true
	}
}
