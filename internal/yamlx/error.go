package yamlx

import (
	"fmt"
	"strings"
)

type Pos struct {
	File string
	Line int
	Col  int
}

// String gives only File for a position without a line, such as a
// command-line argument.
func (p Pos) String() string {
	if p.Line == 0 {
		return p.File
	}
	return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Col)
}

// Error is a problem in a project file. Its text is "file:line:col: message".
type Error struct {
	Pos Pos
	Msg string
}

func (e *Error) Error() string {
	return e.Pos.String() + ": " + e.Msg
}

func Errorf(pos Pos, format string, args ...any) *Error {
	return &Error{Pos: pos, Msg: fmt.Sprintf(format, args...)}
}

// FieldError is returned by a Validate method. The decoder places it at the
// value of Field, or at the struct when Field is empty.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string {
	return e.Field + ": " + e.Msg
}

// Suggest returns `; did you mean "x"?` for the option closest to name, or ""
// when no option is close.
func Suggest(name string, options []string) string {
	best, bestDist := "", len(name)/2+1
	for _, o := range options {
		if d := distance(name, o); d < bestDist {
			best, bestDist = o, d
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf("; did you mean %q?", best)
}

// distance is the edit distance of a and b, with a swap of two neighbors as
// one edit.
func distance(a, b string) int {
	ra, rb := []rune(strings.ToLower(a)), []rune(strings.ToLower(b))
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
