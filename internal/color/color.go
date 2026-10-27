// Package color writes text with ANSI colors to a terminal.
package color

import (
	"fmt"
	"io"
	"strings"
)

// Style is an ANSI SGR code.
type Style string

const (
	Plain  Style = ""
	Bold   Style = "1"
	Red    Style = "31"
	Green  Style = "32"
	Yellow Style = "33"
	Cyan   Style = "36"
)

type Span struct {
	Style Style
	Text  string
}

// Text is text with styles. Its Write adds plain text.
type Text []Span

func (t *Text) Add(s Style, text string) {
	*t = append(*t, Span{s, text})
}

func (t *Text) Write(p []byte) (int, error) {
	t.Add(Plain, string(p))
	return len(p), nil
}

// String returns the text without styles.
func (t Text) String() string {
	var b strings.Builder
	for _, s := range t {
		b.WriteString(s.Text)
	}
	return b.String()
}

// Writer filters each write to a stream, and adds color when on. Every
// output stream of winch passes through one, so no secret reaches it.
type Writer struct {
	w      io.Writer
	filter func([]string) []string
	on     bool
}

// NewWriter returns a writer to w. filter returns its parts with the
// secrets masked.
func NewWriter(w io.Writer, filter func([]string) []string, on bool) *Writer {
	return &Writer{w: w, filter: filter, on: on}
}

func (w *Writer) Write(p []byte) (int, error) {
	if _, err := io.WriteString(w.w, w.filter([]string{string(p)})[0]); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Fprint writes t to w in one write. The filter sees all of t before the
// color codes go around each line of a styled span.
func Fprint(w *Writer, t Text) {
	parts := make([]string, len(t))
	for i, s := range t {
		parts[i] = s.Text
	}
	parts = w.filter(parts)
	if !w.on {
		fmt.Fprint(w.w, strings.Join(parts, ""))
		return
	}
	var b strings.Builder
	for i, s := range t {
		if s.Style == Plain {
			b.WriteString(parts[i])
			continue
		}
		for j, line := range strings.Split(parts[i], "\n") {
			if j > 0 {
				b.WriteByte('\n')
			}
			if line != "" {
				b.WriteString("\x1b[" + string(s.Style) + "m" + line + "\x1b[0m")
			}
		}
	}
	fmt.Fprint(w.w, b.String())
}
