package secret

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
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
}

func NewFilter() *Filter {
	return &Filter{values: map[string]bool{}}
}

// Add adds a secret value: the value and each of its lines, without the
// white space around them, in plain and JSON-escaped form, and as the output
// prints it, also JSON-escaped. It adds the base64 and URL-encoded forms of
// both the trimmed and the exact text. It skips text shorter than 4
// characters, and true and false.
func (f *Filter) Add(value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, exact := range append([]string{value}, strings.Split(value, "\n")...) {
		v := strings.TrimSpace(exact)
		if utf8.RuneCountInString(v) < 4 || v == "true" || v == "false" {
			continue
		}
		for _, s := range []string{v, Printable(v), PrintableLines(v)} {
			f.values[s] = true
			j, _ := json.Marshal(s)
			f.values[string(j[1:len(j)-1])] = true
		}
		for _, s := range []string{v, exact} {
			f.values[base64.RawStdEncoding.EncodeToString([]byte(s))] = true
			f.values[url.QueryEscape(s)] = true
			f.values[url.PathEscape(s)] = true
		}
	}
}

// Text returns s with each match replaced by Mark. Overlapping and adjacent
// matches give one Mark. A newline stays, and a match inside a Mark of s
// does not count.
func (f *Filter) Text(s string) string {
	return f.Parts([]string{s})[0]
}

// Parts filters the text that parts make together, and returns it in the
// same parts. A Mark shows in the part where its match starts.
func (f *Filter) Parts(parts []string) []string {
	s := strings.Join(parts, "")
	f.mu.Lock()
	defer f.mu.Unlock()
	marked := make([]bool, len(s))
	set := func(from, to int) {
		for i := from; i < to; i++ {
			marked[i] = true
		}
	}
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
	for v := range f.values {
		for i := 0; ; {
			j := strings.Index(s[i:], v)
			if j < 0 {
				break
			}
			if from, to := i+j, i+j+len(v); !inMark(from, to) {
				set(from, to)
			}
			i += j + 1
		}
	}
	for _, p := range patterns {
		for _, m := range p.find(s) {
			set(m[0], m[1])
		}
	}
	keyBlocks(s, set)
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

// PrintableLines is Printable for text with lines: it keeps each newline.
func PrintableLines(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\n' && Unprintable(r) {
			return '?'
		}
		return r
	}, s)
}
