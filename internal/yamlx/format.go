package yamlx

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

var errLayout = errors.New("cannot format the file without a change to its values; change this line by hand, then run winch fmt again")

// layoutError is errLayout at a line, counted from 0.
type layoutError int

func (layoutError) Error() string { return errLayout.Error() }

// Format returns data with two-space indentation, list items indented under
// their key, and the keys of each step sorted by rank. steps are the paths of
// the step lists, such as "handlers.*" or "stages.*.steps". Format moves
// whole lines only, so comments, blank lines, and the text of each value
// stay. It fails when the result would not hold the same values.
func Format(file string, data []byte, steps []string, rank func(key string) int) ([]byte, error) {
	root, err := parseRoot(file, data)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return data, nil
	}
	text := string(data)
	n := strings.Count(text, "\n")
	crlf := n > 0 && strings.Count(text, "\r\n") == n
	if crlf {
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	in := strings.Split(text, "\n")
	lines, err := indent(in, root)
	if err == nil {
		lines, err = order(lines, steps, rank)
	}
	out := strings.Join(lines, "\n")
	if crlf {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	if err == nil && !sameFile(root, []byte(out)) {
		err = errLayout
	}
	if err != nil {
		line := firstDiff(in, lines)
		var le layoutError
		if errors.As(err, &le) {
			line = int(le)
		}
		return nil, &Error{Pos: Pos{File: file, Line: line + 1, Col: 1}, Msg: errLayout.Error()}
	}
	return []byte(out), nil
}

// firstDiff returns the first line where a and b differ.
func firstDiff(a, b []string) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}
	return 0
}

// start is a key of a block map or a "-" of a block list.
type start struct {
	col    int
	target int
	dash   bool
	// inline is true for a "-" whose item starts on the same line.
	inline bool
}

func (s start) delta() int { return s.target - s.col }

// layout is what Format knows about each line of a file.
type layout struct {
	lines  []string
	starts map[int][]start
	// fixed holds the shift of each line in a block scalar.
	fixed map[int]int
	// quoted holds the lines after the first of a quoted scalar.
	quoted map[int]bool
	// keep holds the lines of a block scalar that keeps its final blank
	// lines.
	keep map[int]bool
	err  error
}

func analyze(lines []string, root *yaml.Node) *layout {
	l := &layout{lines: lines, starts: map[int][]start{}, fixed: map[int]int{}, quoted: map[int]bool{}, keep: map[int]bool{}}
	if isBlock(root) {
		l.block(root, 0)
	}
	return l
}

func isBlock(n *yaml.Node) bool {
	return (n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) && n.Style&yaml.FlowStyle == 0
}

// col returns the byte offset of the 1-based character column c on line.
func (l *layout) col(line, c int) int {
	s := l.lines[line]
	i := 0
	for range c - 1 {
		if i >= len(s) {
			return len(s)
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return i
}

// block records the starts of a block map or list whose items belong at the
// column target.
func (l *layout) block(n *yaml.Node, target int) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			line := k.Line - 1
			s := start{col: l.col(line, k.Column), target: target}
			l.starts[line] = append(l.starts[line], s)
			l.value(n.Content[i+1], line, s)
		}
		return
	}
	for _, item := range n.Content {
		line, col, ok := l.dash(item)
		if !ok {
			l.err = layoutError(item.Line - 1)
			return
		}
		s := start{col: col, target: target, dash: true, inline: line == item.Line-1}
		l.starts[line] = append(l.starts[line], s)
		l.value(item, line, s)
	}
}

// dash finds the "-" of a list item.
func (l *layout) dash(item *yaml.Node) (int, int, bool) {
	line := item.Line - 1
	s := l.lines[line]
	for i := l.col(line, item.Column) - 1; i >= 0 && i < len(s); i-- {
		switch s[i] {
		case ' ':
			continue
		case '-':
			return line, i, true
		}
		return 0, 0, false
	}
	for line--; line >= 0; line-- {
		t := strings.TrimLeft(l.lines[line], " ")
		if t == "" || t[0] == '#' {
			continue
		}
		if rest := strings.TrimLeft(t[1:], " "); t[0] == '-' && (rest == "" || rest[0] == '#') {
			return line, len(l.lines[line]) - len(t), true
		}
		return 0, 0, false
	}
	return 0, 0, false
}

// value records the layout of the value of owner, a start on line.
func (l *layout) value(n *yaml.Node, line int, owner start) {
	switch {
	case isBlock(n):
		l.block(n, owner.target+2)
	case n.Kind != yaml.ScalarNode:
	case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		l.blockScalar(n, owner)
	case n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0:
		l.quotedScalar(n)
	}
}

// blockScalar records the shift of the lines of a block scalar: its content
// goes two columns under its owner. A scalar with an indentation indicator
// moves with its owner.
func (l *layout) blockScalar(n *yaml.Node, owner start) {
	head := n.Line - 1
	h := l.lines[head][l.col(head, n.Column):]
	i := strings.IndexAny(h, "|>")
	if i < 0 {
		l.err = layoutError(head)
		return
	}
	indicator := strings.Fields(h[i:] + " ")[0]
	explicit := strings.ContainsAny(indicator, "123456789")
	end := head + 1
	first := -1
	for ; end < len(l.lines); end++ {
		s := l.lines[end]
		t := strings.TrimLeft(s, " ")
		if t != "" && len(s)-len(t) <= owner.col {
			break
		}
		if t != "" && first < 0 {
			first = len(s) - len(t)
		}
	}
	d := owner.delta()
	if !explicit && first >= 0 {
		d = owner.target + 2 - first
	}
	for line := head + 1; line < end; line++ {
		l.fixed[line] = d
		l.keep[line] = strings.Contains(indicator, "+")
	}
}

// quotedScalar records the lines after the first of a quoted scalar.
func (l *layout) quotedScalar(n *yaml.Node) {
	line := n.Line - 1
	s := l.lines[line]
	i := l.col(line, n.Column)
	j := strings.IndexAny(s[i:], `"'`)
	if j < 0 {
		l.err = layoutError(line)
		return
	}
	q := s[i+j]
	pos := i + j + 1
	for line < len(l.lines) {
		s = l.lines[line]
		for ; pos < len(s); pos++ {
			switch {
			case q == '"' && s[pos] == '\\':
				pos++
			case s[pos] == q && q == '\'' && pos+1 < len(s) && s[pos+1] == '\'':
				pos++
			case s[pos] == q:
				return
			}
		}
		line++
		pos = 0
		if line < len(l.lines) {
			l.quoted[line] = true
		}
	}
}

// comment reports whether line is a comment line.
func (l *layout) comment(line int) bool {
	_, fixed := l.fixed[line]
	t := strings.TrimLeft(l.lines[line], " ")
	return !fixed && !l.quoted[line] && strings.HasPrefix(t, "#")
}

func shift(s string, d int) string {
	if d >= 0 {
		return strings.Repeat(" ", d) + s
	}
	t := strings.TrimLeft(s, " ")
	return s[min(-d, len(s)-len(t)):]
}

// indent moves each line to its column.
func indent(lines []string, root *yaml.Node) ([]string, error) {
	l := analyze(lines, root)
	if l.err != nil {
		return nil, l.err
	}
	// next holds the first start of the next line with starts.
	next := make([]*start, len(lines))
	var after *start
	for i := len(lines) - 1; i >= 0; i-- {
		next[i] = after
		if s := l.starts[i]; len(s) > 0 {
			after = &s[0]
		}
	}
	// open holds the starts that are still open, by column.
	var open []start
	cur := 0
	out := make([]string, len(lines))
	for i, s := range lines {
		if starts := l.starts[i]; len(starts) > 0 {
			line, ok := rebuild(s, starts)
			if !ok {
				return nil, layoutError(i)
			}
			out[i] = line
			for _, st := range starts {
				for len(open) > 0 && open[len(open)-1].col >= st.col {
					open = open[:len(open)-1]
				}
				open = append(open, st)
			}
			cur = starts[len(starts)-1].delta()
			continue
		}
		t := strings.TrimLeft(s, " ")
		if d, ok := l.fixed[i]; ok {
			if len(s) > 0 {
				s = shift(s, d)
			}
			out[i] = s
			continue
		}
		if t == "" {
			out[i] = s
			continue
		}
		d := cur
		if l.comment(i) {
			d = commentDelta(len(s)-len(t), next[i], open)
		}
		out[i] = shift(s, max(d, -(len(s)-len(t))))
	}
	return out, nil
}

// commentDelta returns the shift of a comment line at column col: that of
// the next start at the same column, else that of an open start at the same
// column, else that of the next start.
func commentDelta(col int, next *start, open []start) int {
	if next != nil && next.col == col {
		return next.delta()
	}
	for i := len(open) - 1; i >= 0; i-- {
		if open[i].col == col {
			return open[i].delta()
		}
	}
	if next != nil {
		return next.delta()
	}
	return 0
}

// rebuild puts each start of line s at its target column. It fails when
// other text comes before the first start.
func rebuild(s string, starts []start) (string, bool) {
	if strings.TrimLeft(s[:starts[0].col], " ") != "" {
		return "", false
	}
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", starts[0].target))
	for i, st := range starts {
		if i+1 < len(starts) {
			b.WriteString("- ")
			continue
		}
		rest := s[st.col:]
		if st.dash && st.inline {
			if t := strings.TrimLeft(rest[1:], " "); t != "" && t[0] != '#' {
				rest = "- " + t
			}
		}
		b.WriteString(rest)
	}
	return b.String(), true
}

// order puts the keys of each block step map in the step key order.
func order(lines []string, steps []string, rank func(string) int) ([]string, error) {
	if len(steps) == 0 {
		return lines, nil
	}
	root, err := parseRoot("", []byte(strings.Join(lines, "\n")))
	if err != nil || root == nil {
		return lines, errLayout
	}
	l := analyze(lines, root)
	if l.err != nil {
		return nil, l.err
	}
	var maps []*yaml.Node
	for _, p := range steps {
		for _, list := range find(root, strings.Split(p, ".")) {
			if !isBlock(list) || list.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range list.Content {
				if isBlock(item) && item.Kind == yaml.MappingNode {
					maps = append(maps, item)
				}
			}
		}
	}
	// Later steps first, so the line numbers of earlier steps stay.
	slices.SortFunc(maps, func(a, b *yaml.Node) int { return b.Line - a.Line })
	for _, m := range maps {
		if lines, err = l.orderStep(lines, m, rank); err != nil {
			return nil, err
		}
	}
	return lines, nil
}

// find returns the nodes at path. "*" is each value of a map or each item of
// a list.
func find(n *yaml.Node, path []string) []*yaml.Node {
	if len(path) == 0 {
		return []*yaml.Node{n}
	}
	var out []*yaml.Node
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if path[0] == "*" || n.Content[i].Value == path[0] {
				out = append(out, find(n.Content[i+1], path[1:])...)
			}
		}
	case yaml.SequenceNode:
		if path[0] == "*" {
			for _, item := range n.Content {
				out = append(out, find(item, path[1:])...)
			}
		}
	}
	return out
}

// orderStep sorts the keys of the step map m. Each key takes along the lines
// of its value and the comment lines right above it.
func (l *layout) orderStep(lines []string, m *yaml.Node, rank func(string) int) ([]string, error) {
	type chunk struct {
		rank  int
		lines []string
		// key is the index of the key line in lines.
		key int
	}
	var keys []int
	var ranks []int
	for i := 0; i+1 < len(m.Content); i += 2 {
		keys = append(keys, m.Content[i].Line-1)
		ranks = append(ranks, rank(m.Content[i].Value))
	}
	if slices.IsSorted(ranks) {
		return lines, nil
	}
	col := l.col(keys[0], m.Content[0].Column)
	begin := make([]int, len(keys))
	for i, k := range keys {
		begin[i] = k
		for i > 0 && begin[i]-1 > keys[i-1] && l.comment(begin[i]-1) && indentOf(lines[begin[i]-1]) == col {
			begin[i]--
		}
	}
	end := len(lines)
	for i := keys[len(keys)-1] + 1; i < len(lines); i++ {
		_, fixed := l.fixed[i]
		t := strings.TrimLeft(lines[i], " ")
		if !fixed && !l.quoted[i] && t != "" && t[0] != '#' && len(lines[i])-len(t) < col {
			end = i
			break
		}
	}
	for end-1 > keys[len(keys)-1] && !l.keep[end-1] && (strings.TrimSpace(lines[end-1]) == "" || l.comment(end-1)) {
		end--
	}
	chunks := make([]chunk, len(keys))
	for i := range keys {
		e := end
		if i+1 < len(keys) {
			e = begin[i+1]
		}
		chunks[i] = chunk{rank: ranks[i], lines: slices.Clone(lines[begin[i]:e]), key: keys[i] - begin[i]}
	}
	var head []string
	prefix := lines[keys[0]][:col]
	inline := strings.TrimLeft(prefix, " ") != ""
	if inline {
		chunks[0].lines[0] = strings.Repeat(" ", col) + chunks[0].lines[0][col:]
	}
	slices.SortStableFunc(chunks, func(a, b chunk) int { return a.rank - b.rank })
	if inline {
		dash := len(prefix) - len(strings.TrimLeft(prefix, " "))
		c := &chunks[0]
		for _, s := range c.lines[:c.key] {
			head = append(head, strings.Repeat(" ", dash)+strings.TrimLeft(s, " "))
		}
		c.lines = c.lines[c.key:]
		c.lines[0] = prefix + c.lines[0][col:]
	}
	out := slices.Clone(lines[:begin[0]])
	out = append(out, head...)
	for _, c := range chunks {
		out = append(out, c.lines...)
	}
	return append(out, lines[end:]...), nil
}

// sameFile reports whether b holds the values of the tree root, with the same
// tags, styles, anchors, and comments. The keys of a map can be in another
// order.
func sameFile(root *yaml.Node, b []byte) bool {
	var nb yaml.Node
	if yaml.Unmarshal(b, &nb) != nil || len(nb.Content) == 0 {
		return false
	}
	return sameNode(root, nb.Content[0]) && slices.Equal(comments(root), comments(nb.Content[0]))
}

func sameNode(a, b *yaml.Node) bool {
	if a.Kind != b.Kind || a.Tag != b.Tag || a.Style != b.Style || a.Anchor != b.Anchor || a.Value != b.Value || len(a.Content) != len(b.Content) {
		return false
	}
	if a.Kind == yaml.MappingNode {
		pa, pb := pairs(a), pairs(b)
		for i := range pa {
			if !sameNode(pa[i][0], pb[i][0]) || !sameNode(pa[i][1], pb[i][1]) {
				return false
			}
		}
		return true
	}
	for i := range a.Content {
		if !sameNode(a.Content[i], b.Content[i]) {
			return false
		}
	}
	return true
}

// pairs returns the key and value pairs of a map, sorted by key.
func pairs(n *yaml.Node) [][2]*yaml.Node {
	var p [][2]*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		p = append(p, [2]*yaml.Node{n.Content[i], n.Content[i+1]})
	}
	slices.SortStableFunc(p, func(a, b [2]*yaml.Node) int { return strings.Compare(a[0].Value, b[0].Value) })
	return p
}

// comments returns the comment lines of the tree n, sorted.
func comments(n *yaml.Node) []string {
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		for _, c := range []string{n.HeadComment, n.LineComment, n.FootComment} {
			for s := range strings.SplitSeq(c, "\n") {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	slices.Sort(out)
	return out
}

func indentOf(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}
