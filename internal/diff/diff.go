// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package diff is a copy of Go's internal/diff (see LICENSE). winch prints
// only the chunks, without the file header.
package diff

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// A pair is a pair of values tracked for both the x and y side of a diff.
// It is typically a pair of line indexes.
type pair struct{ x, y int }

// Diff returns an anchored diff of the two texts old and new
// in the “unified diff” format, without the file header. If old and new are identical,
// Diff returns a nil slice (no output).
//
// Unix diff implementations typically look for a diff with
// the smallest number of lines inserted and removed,
// which can in the worst case take time quadratic in the
// number of lines in the texts. As a result, many implementations
// either can be made to run for a long time or cut off the search
// after a predetermined amount of work.
//
// In contrast, this implementation looks for a diff with the
// smallest number of “unique” lines inserted and removed,
// where unique means a line that appears just once in both old and new.
// We call this an “anchored diff” because the unique lines anchor
// the chosen matching regions. An anchored diff is usually clearer
// than a standard diff, because the algorithm does not try to
// reuse unrelated blank lines or closing braces.
// The algorithm also guarantees to run in O(n log n) time
// instead of the standard O(n²) time.
//
// Some systems call this approach a “patience diff,” named for
// the “patience sorting” algorithm, itself named for a solitaire card game.
// We avoid that name for two reasons. First, the name has been used
// for a few different variants of the algorithm, so it is imprecise.
// Second, the name is frequently interpreted as meaning that you have
// to wait longer (to be patient) for the diff, meaning that it is a slower algorithm,
// when in fact the algorithm is faster than the standard one.
func Diff(old, new []byte) []byte {
	if bytes.Equal(old, new) {
		return nil
	}
	x := Lines(old)
	y := Lines(new)
	var out bytes.Buffer
	for _, h := range Hunks(x, y) {
		out.WriteString(h.Header())
		for _, op := range h.Ops {
			switch op.Kind {
			case ' ':
				out.WriteString(" " + x[op.X])
			case '-':
				out.WriteString("-" + x[op.X])
			default:
				out.WriteString("+" + y[op.Y])
			}
		}
	}
	return out.Bytes()
}

// Op is one line of a hunk: ' ' for a line of both texts, '-' for a line of
// x only, and '+' for a line of y only. X and Y are the indexes of the line.
type Op struct {
	Kind byte
	X, Y int
}

// Hunk is a chunk of a unified diff. X and Y are the start lines of the
// header, NX and NY its line counts.
type Hunk struct {
	X, Y, NX, NY int
	Ops          []Op
}

// Header is the line "@@ -x,nx +y,ny @@" of the hunk.
func (h Hunk) Header() string {
	return fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", h.X, h.NX, h.Y, h.NY)
}

// Hunks returns the chunks of the anchored diff of the lines x and y, with
// three lines of context.
func Hunks(x, y []string) []Hunk {
	var out []Hunk

	// Loop over matches to consider,
	// expanding each match to include surrounding lines,
	// and then printing diff chunks.
	// To avoid setup/teardown cases outside the loop,
	// tgs returns a leading {0,0} and trailing {len(x), len(y)} pair
	// in the sequence of matches.
	var (
		done  pair // printed up to x[:done.x] and y[:done.y]
		chunk pair // start lines of current chunk
		count pair // number of lines from each side in current chunk
		ops   []Op // lines for current chunk
	)
	for _, m := range tgs(x, y) {
		if m.x < done.x {
			// Already handled scanning forward from earlier match.
			continue
		}

		// Expand matching lines as far as possible,
		// establishing that x[start.x:end.x] == y[start.y:end.y].
		// Note that on the first (or last) iteration we may (or definitely do)
		// have an empty match: start.x==end.x and start.y==end.y.
		start := m
		for start.x > done.x && start.y > done.y && x[start.x-1] == y[start.y-1] {
			start.x--
			start.y--
		}
		end := m
		for end.x < len(x) && end.y < len(y) && x[end.x] == y[end.y] {
			end.x++
			end.y++
		}

		// Emit the mismatched lines before start into this chunk.
		// (No effect on first sentinel iteration, when start = {0,0}.)
		for i := done.x; i < start.x; i++ {
			ops = append(ops, Op{'-', i, -1})
			count.x++
		}
		for j := done.y; j < start.y; j++ {
			ops = append(ops, Op{'+', -1, j})
			count.y++
		}

		// If we're not at EOF and have too few common lines,
		// the chunk includes all the common lines and continues.
		const C = 3 // number of context lines
		if (end.x < len(x) || end.y < len(y)) &&
			(end.x-start.x < C || (len(ops) > 0 && end.x-start.x < 2*C)) {
			for i := start.x; i < end.x; i++ {
				ops = append(ops, Op{' ', i, start.y + i - start.x})
				count.x++
				count.y++
			}
			done = end
			continue
		}

		// End chunk with common lines for context.
		if len(ops) > 0 {
			n := end.x - start.x
			if n > C {
				n = C
			}
			for i := start.x; i < start.x+n; i++ {
				ops = append(ops, Op{' ', i, start.y + i - start.x})
				count.x++
				count.y++
			}
			done = pair{start.x + n, start.y + n}

			// Format and emit chunk.
			// Convert line numbers to 1-indexed.
			// Special case: empty file shows up as 0,0 not 1,0.
			if count.x > 0 {
				chunk.x++
			}
			if count.y > 0 {
				chunk.y++
			}
			out = append(out, Hunk{X: chunk.x, Y: chunk.y, NX: count.x, NY: count.y, Ops: ops})
			count.x = 0
			count.y = 0
			ops = nil
		}

		// If we reached EOF, we're done.
		if end.x >= len(x) && end.y >= len(y) {
			break
		}

		// Otherwise start a new chunk.
		chunk = pair{end.x - C, end.y - C}
		for i := chunk.x; i < end.x; i++ {
			ops = append(ops, Op{' ', i, chunk.y + i - chunk.x})
			count.x++
			count.y++
		}
		done = end
	}

	return out
}

// Lines returns the lines in the file x, including newlines.
// If the file does not end in a newline, one is supplied
// along with a warning about the missing newline.
func Lines(x []byte) []string {
	l := strings.SplitAfter(string(x), "\n")
	if l[len(l)-1] == "" {
		l = l[:len(l)-1]
	} else {
		// Treat last line as having a message about the missing newline attached,
		// using the same text as BSD/GNU diff (including the leading backslash).
		l[len(l)-1] += "\n\\ No newline at end of file\n"
	}
	return l
}

// tgs returns the pairs of indexes of the longest common subsequence
// of unique lines in x and y, where a unique line is one that appears
// once in x and once in y.
//
// The longest common subsequence algorithm is as described in
// Thomas G. Szymanski, “A Special Case of the Maximal Common
// Subsequence Problem,” Princeton TR #170 (January 1975),
// available at https://research.swtch.com/tgs170.pdf.
func tgs(x, y []string) []pair {
	// Count the number of times each string appears in a and b.
	// We only care about 0, 1, many, counted as 0, -1, -2
	// for the x side and 0, -4, -8 for the y side.
	// Using negative numbers now lets us distinguish positive line numbers later.
	m := make(map[string]int)
	for _, s := range x {
		if c := m[s]; c > -2 {
			m[s] = c - 1
		}
	}
	for _, s := range y {
		if c := m[s]; c > -8 {
			m[s] = c - 4
		}
	}

	// Now unique strings can be identified by m[s] = -1+-4.
	//
	// Gather the indexes of those strings in x and y, building:
	//	xi[i] = increasing indexes of unique strings in x.
	//	yi[i] = increasing indexes of unique strings in y.
	//	inv[i] = index j such that x[xi[i]] = y[yi[j]].
	var xi, yi, inv []int
	for i, s := range y {
		if m[s] == -1+-4 {
			m[s] = len(yi)
			yi = append(yi, i)
		}
	}
	for i, s := range x {
		if j, ok := m[s]; ok && j >= 0 {
			xi = append(xi, i)
			inv = append(inv, j)
		}
	}

	// Apply Algorithm A from Szymanski's paper.
	// In those terms, A = J = inv and B = [0, n).
	// We add sentinel pairs {0,0}, and {len(x),len(y)}
	// to the returned sequence, to help the processing loop.
	J := inv
	n := len(xi)
	T := make([]int, n)
	L := make([]int, n)
	for i := range T {
		T[i] = n + 1
	}
	for i := 0; i < n; i++ {
		k := sort.Search(n, func(k int) bool {
			return T[k] >= J[i]
		})
		T[k] = J[i]
		L[i] = k + 1
	}
	k := 0
	for _, v := range L {
		if k < v {
			k = v
		}
	}
	seq := make([]pair, 2+k)
	seq[1+k] = pair{len(x), len(y)} // sentinel at end
	lastj := n
	for i := n - 1; i >= 0; i-- {
		if L[i] == k && J[i] < lastj {
			seq[k] = pair{xi[i], yi[J[i]]}
			k--
		}
	}
	seq[0] = pair{0, 0} // sentinel at start
	return seq
}
