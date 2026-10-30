package project

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

// Keys decrypt the secrets of a project. Filter learns each secret value.
type Keys struct {
	Identity secret.Identity
	Filter   *secret.Filter
}

// Sealed is the value of a !secret scalar. The loader puts it into the node,
// so variable values hold it as a leaf.
type Sealed struct {
	// Text is the age file in base64.
	Text string
	// Plain is the value after Load decrypted it.
	Plain string
}

// sealedAt is a sealed value and its position.
type sealedAt struct {
	s   *Sealed
	pos yamlx.Pos
}

// seal checks each !secret scalar in n, a variable value, and puts a Sealed
// value into it. Another tag is an error with the message notHere, unless
// notHere is empty.
func (l *loader) seal(n *yamlx.Node, notHere string) []error {
	var errs []error
	walkTags(n, func(t *yamlx.Node) {
		switch {
		case t.Tag == "!secret":
		case notHere == "":
			return
		default:
			errs = append(errs, yamlx.Errorf(t.Pos, "%s", notHere))
			return
		}
		text, ok := t.Value.(string)
		if !ok {
			// An alias of a value that is sealed.
			return
		}
		if err := secret.CheckForm(text); err != nil {
			errs = append(errs, yamlx.Errorf(t.Pos, "!secret: %v", err))
			return
		}
		s := &Sealed{Text: text}
		t.Value = s
		l.sealed = append(l.sealed, sealedAt{s, t.Pos})
	})
	return errs
}

// walkTags calls f for each tagged scalar in n.
func walkTags(n *yamlx.Node, f func(*yamlx.Node)) {
	switch {
	case n.Tag != "":
		f(n)
	case n.Kind == yamlx.Map:
		for _, p := range n.Pairs {
			walkTags(p.Value, f)
		}
	case n.Kind == yamlx.List:
		for _, item := range n.Items {
			walkTags(item, f)
		}
	}
}

// staleSecrets returns a warning for each sealed value whose number of
// recipients is not n. age records only the number, not the keys.
func (l *loader) staleSecrets(n int) ([]*yamlx.Error, error) {
	var out []*yamlx.Error
	var errs []error
	for _, s := range l.sealed {
		got, err := secret.Stanzas(s.s.Text)
		if err != nil {
			errs = append(errs, yamlx.Errorf(s.pos, "!secret: %v", err))
			continue
		}
		if got != n {
			out = append(out, yamlx.Errorf(s.pos, "this secret is encrypted for %s; winch.yaml lists %d; run winch secret rekey", recipientCount(got), n))
		}
	}
	return out, errors.Join(errs...)
}

func recipientCount(n int) string {
	if n == 1 {
		return "1 recipient"
	}
	return fmt.Sprintf("%d recipients", n)
}

// unsealAll decrypts every sealed value with the identity of keys, and adds
// each plaintext to the filter.
func (l *loader) unsealAll(ctx context.Context, keys Keys) error {
	if len(l.sealed) == 0 {
		return nil
	}
	ids, err := keys.Identity.Read(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range l.sealed {
		plain, err := decrypt(s.s.Text, ids, keys.Identity)
		if err != nil {
			errs = append(errs, yamlx.Errorf(s.pos, "!secret: %v", err))
			continue
		}
		s.s.Plain = plain
		keys.Filter.Add(plain)
	}
	return errors.Join(errs...)
}

func decrypt(text string, ids []age.Identity, identity secret.Identity) (string, error) {
	plain, err := secret.Decrypt(text, ids)
	if errors.Is(err, secret.ErrNotRecipient) {
		return "", fmt.Errorf("the identity %s is not a recipient", identity)
	}
	return plain, err
}

// unseal returns a copy of v with each sealed value replaced: by its
// plaintext in the variant 0, by the placeholder of the variant 1 or 2.
func unseal(v any, n int) any {
	switch v := v.(type) {
	case *Sealed:
		if n == 0 {
			return v.Plain
		}
		return secret.Placeholder(n)
	case map[string]any:
		m := make(map[string]any, len(v))
		for k, x := range v {
			m[k] = unseal(x, n)
		}
		return m
	case []any:
		l := make([]any, len(v))
		for i, x := range v {
			l[i] = unseal(x, n)
		}
		return l
	}
	return v
}

func hasSealed(v any) bool {
	switch v := v.(type) {
	case *Sealed:
		return true
	case map[string]any:
		for _, x := range v {
			if hasSealed(x) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, hasSealed)
	}
	return false
}

// force returns alt, the value of a secret variable in the variant n, with
// each leaf that equals the real leaf replaced by the placeholder. Map keys
// stay.
func force(real, alt any, n int) any {
	switch r := real.(type) {
	case map[string]any:
		am, ok := alt.(map[string]any)
		if !ok {
			return alt
		}
		m := make(map[string]any, len(am))
		for k, x := range am {
			m[k] = force(r[k], x, n)
		}
		return m
	case []any:
		al, ok := alt.([]any)
		if !ok || len(al) != len(r) {
			return alt
		}
		l := make([]any, len(al))
		for i := range al {
			l[i] = force(r[i], al[i], n)
		}
		return l
	}
	if reflect.DeepEqual(real, alt) {
		return secret.Placeholder(n)
	}
	return alt
}

// maskError returns err, an error of the real values, with each part of its
// message that differs from the errors of the two placeholder variants as
// secret.Mark. A variant without an error masks the whole message.
func maskError(err error, alt [2]error) error {
	msg := err.Error()
	ye, ok := err.(*yamlx.Error)
	if ok {
		msg = ye.Msg
	}
	var am [2]string
	for i, a := range alt {
		am[i] = secret.Placeholder(i + 1)
		if ae, ok := a.(*yamlx.Error); ok {
			am[i] = ae.Msg
		} else if a != nil {
			am[i] = a.Error()
		}
	}
	if msg == am[0] && msg == am[1] {
		return err
	}
	shown, _ := secret.Mask(msg, am[0], am[1])
	if ok {
		return &yamlx.Error{Pos: ye.Pos, Msg: shown}
	}
	return errors.New(shown)
}

// Shown is how the output shows a step whose evaluation reads a secret.
type Shown struct {
	Main     string
	Then     string
	Validate string
	Unless   string
	// Lines are the lines of the content with their masks, or nil when the
	// content holds no secret.
	Lines []secret.Line
	// Hidden is true when the output shows no part of the content.
	Hidden bool
	// Public is the argument that holds a secret and goes into a file that
	// every user of the host can read, or "".
	Public string
}

// ShownMain is the main argument as the output shows it.
func (st Step) ShownMain() string {
	if st.Shown != nil {
		return st.Shown.Main
	}
	return st.Args.Main()
}

// ShownThen is the command of then as the output shows it.
func (st Step) ShownThen() string {
	if st.Shown != nil {
		return st.Shown.Then
	}
	return st.Then
}

// ShownValidate is the validate command as the output shows it.
func (st Step) ShownValidate() string {
	if st.Shown != nil {
		return st.Shown.Validate
	}
	if v, ok := st.Args.(module.WithValidate); ok {
		return v.ValidateCommand()
	}
	return ""
}

// ShownUnless is the unless command of a cmd as the output shows it.
func (st Step) ShownUnless() string {
	if st.Shown != nil {
		return st.Shown.Unless
	}
	if c, ok := st.Args.(*module.Cmd); ok {
		return c.UnlessCommand()
	}
	return ""
}

// Recipients returns the recipients in winch.yaml.
func Recipients(dir string) ([]age.Recipient, error) {
	cfg, err := loadConfig(dir)
	if err != nil {
		return nil, err
	}
	return recipients(cfg)
}

func recipients(cfg *Config) ([]age.Recipient, error) {
	if len(cfg.Recipients) == 0 {
		return nil, errors.New("winch.yaml has no recipients")
	}
	return secret.ParseRecipients(cfg.Recipients)
}

// AddRecipient adds key to recipients in winch.yaml when it is not in the
// list, and keeps the comments and the layout of the file. It reports whether
// it added key.
func AddRecipient(dir, key string) (bool, error) {
	path, err := filepath.EvalSymlinks(projectPath(dir, "winch.yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("%w; run winch in the project directory", notFound("winch.yaml"))
	}
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read winch.yaml: %w", err)
	}
	n, err := yamlx.Parse("winch.yaml", data)
	if err != nil {
		return false, err
	}
	var cfg Config
	if err := yamlx.Decode(n, &cfg); err != nil {
		return false, err
	}
	if slices.Contains(cfg.Recipients, key) {
		return false, nil
	}
	text := string(data)
	i := slices.IndexFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == "recipients" })
	if i < 0 {
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		indent := strings.Repeat(" ", n.Pairs[0].KeyPos.Col-1)
		text += indent + "recipients:\n" + indent + "  - " + key + "\n"
	} else if v := n.Pairs[i].Value; len(v.Items) > 0 {
		lines := strings.SplitAfter(text, "\n")
		last := v.Items[len(v.Items)-1].Pos
		line := lines[last.Line-1]
		if !strings.HasSuffix(line, "\n") {
			lines[last.Line-1] += "\n"
		}
		lines = slices.Insert(lines, last.Line, line[:last.Col-1]+key+"\n")
		text = strings.Join(lines, "")
	}
	// The edit assumes a block list of one-line items; a check of the result
	// catches every other layout.
	var after Config
	if n, err := yamlx.Parse("winch.yaml", []byte(text)); err != nil || yamlx.Decode(n, &after) != nil ||
		!slices.Equal(after.Recipients, append(cfg.Recipients, key)) {
		return false, errors.New("cannot add the public key to recipients in winch.yaml; add it by hand")
	}
	return true, replaceFile(path, []byte(text))
}

// Rekey encrypts every secret in winch.yaml, the inventories, and the recipes
// again for the recipients in winch.yaml. It writes no file when a secret
// fails. It returns the number of secrets and the files it rewrote.
func Rekey(ctx context.Context, dir string, identity secret.Identity) (int, []string, error) {
	cfg, err := loadConfig(dir)
	if err != nil {
		return 0, nil, err
	}
	recs, err := recipients(cfg)
	if err != nil {
		return 0, nil, err
	}
	invs, err := list(dir, "inventories")
	if err != nil {
		return 0, nil, err
	}
	recipes, err := recipeFiles(dir)
	if err != nil {
		return 0, nil, err
	}
	files := append(append([]string{"winch.yaml"}, invs...), recipes...)
	var ids []age.Identity
	// next keeps one value that two places hold the same after rekey.
	next := map[string]string{}
	// done holds the paths after links, so two links to one file write it
	// once.
	done := map[string]bool{}
	type rewrite struct {
		name, path string
		data       []byte
	}
	var out []rewrite
	count := 0
	var errs []error
	for _, file := range files {
		path, err := filepath.EvalSymlinks(projectPath(dir, file))
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil, notFound(file)
		}
		if err != nil {
			return 0, nil, err
		}
		if done[path] {
			continue
		}
		done[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, nil, err
		}
		n, err := yamlx.Parse(file, data)
		if err != nil {
			return 0, nil, err
		}
		var sealed []*yamlx.Node
		seen := map[*yamlx.Node]bool{}
		walkTags(n, func(t *yamlx.Node) {
			if t.Tag == "!secret" && !seen[t] {
				seen[t] = true
				sealed = append(sealed, t)
			}
		})
		if len(sealed) == 0 {
			continue
		}
		if ids == nil {
			if ids, err = identity.Read(ctx); err != nil {
				return 0, nil, err
			}
		}
		orig := strings.SplitAfter(string(data), "\n")
		lines := slices.Clone(orig)
		// shift is the change in length of each line by the earlier
		// replacements on it.
		shift := map[int]int{}
		for _, t := range sealed {
			text, _ := t.Value.(string)
			plain, err := decrypt(text, ids, identity)
			if err != nil {
				errs = append(errs, yamlx.Errorf(t.Pos, "!secret: %v", err))
				continue
			}
			if next[text] == "" {
				if next[text], err = secret.Encrypt(plain, recs); err != nil {
					return 0, nil, err
				}
			}
			l := t.Pos.Line - 1
			// The column counts characters and points at the tag or the
			// anchor before the text.
			at := 0
			for range t.Pos.Col - 1 {
				_, n := utf8.DecodeRuneInString(orig[l][at:])
				at += n
			}
			at += shift[l]
			i := strings.Index(lines[l][at:], text)
			if i < 0 {
				errs = append(errs, yamlx.Errorf(t.Pos, "!secret: the value is not on one line"))
				continue
			}
			i += at
			lines[l] = lines[l][:i] + next[text] + lines[l][i+len(text):]
			shift[l] += len(next[text]) - len(text)
			count++
		}
		out = append(out, rewrite{file, path, []byte(strings.Join(lines, ""))})
	}
	if err := errors.Join(errs...); err != nil {
		return 0, nil, err
	}
	slices.SortFunc(out, func(a, b rewrite) int { return strings.Compare(a.name, b.name) })
	var rewritten []string
	for _, r := range out {
		if err := replaceFile(r.path, r.data); err != nil {
			return 0, nil, err
		}
		rewritten = append(rewritten, r.name)
	}
	return count, rewritten, nil
}

// replaceFile writes data to path through a new file in the same directory,
// with the mode of path.
func replaceFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".winch-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// scanProject returns a warning for each private key or token in the
// project files that is not a !secret. It calls plain with the text of each
// file.
func scanProject(dir string, plain func([]byte)) ([]*yamlx.Error, error) {
	invs, err := list(dir, "inventories")
	if err != nil {
		return nil, err
	}
	pipelines, err := list(dir, "pipelines")
	if err != nil {
		return nil, err
	}
	recipes, err := recipeFiles(dir)
	if err != nil {
		return nil, err
	}
	files := slices.Concat([]string{"winch.yaml"}, invs, pipelines, recipes)
	for _, sub := range []string{"templates", "files"} {
		roots, err := filepath.Glob(filepath.Join(dir, "recipes", "*", sub))
		if err != nil {
			return nil, err
		}
		for _, root := range roots {
			err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
				if err != nil || !d.Type().IsRegular() {
					return err
				}
				rel, err := filepath.Rel(dir, path)
				if err != nil {
					return err
				}
				files = append(files, filepath.ToSlash(rel))
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	var out []*yamlx.Error
	seen := map[string]bool{}
	for _, file := range files {
		path, err := filepath.EvalSymlinks(projectPath(dir, file))
		if err != nil {
			return nil, err
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		plain(data)
		line, last, prev := 1, -1, 0
		for _, f := range secret.Scan(data) {
			line += bytes.Count(data[prev:f.Offset], []byte("\n"))
			if i := bytes.LastIndexByte(data[prev:f.Offset], '\n'); i >= 0 {
				last = prev + i
			}
			prev = f.Offset
			col := f.Offset - last
			out = append(out, yamlx.Errorf(yamlx.Pos{File: file, Line: line, Col: col}, "this looks like %s; use !secret", f.What))
		}
	}
	slices.SortStableFunc(out, func(a, b *yamlx.Error) int { return strings.Compare(a.Pos.File, b.Pos.File) })
	return out, nil
}

// WriteSecret encrypts plain for the recipients, and writes it as the value
// of the variable name into the vars of the group all in the inventory, or of
// host when host is not empty. inventory is the name of --inventory, or
// empty. It keeps the comments and the layout of the file, and returns the
// name of the inventory.
func WriteSecret(dir, inventory, host, name, plain string) (string, error) {
	cfg, err := loadConfig(dir)
	if err != nil {
		return "", err
	}
	recs, err := recipients(cfg)
	if err != nil {
		return "", err
	}
	// The reads of the parts that load are enough: a broken template in
	// another recipe does not block a new secret. The load errors show only
	// when the variable is not found, as they may hide its read.
	l, lErr := newLoader(dir, cfg)
	_, plErr := l.otherPipelines("")
	if read := l.readNames(); !read[name] {
		return "", errors.Join(errors.New(unknownVariable(name, read)), lErr, plErr)
	}
	inventory = cmp.Or(inventory, cfg.Inventory, l.layout.only())
	if inventory == "" {
		return "", errors.New("no inventory: use --inventory, or set inventory in winch.yaml")
	}
	inv, err := l.layout.inventory(inventory)
	if err != nil {
		return "", err
	}
	// A key in winch.yaml is the map at prefix.
	file, label := inv.file, inv.label("inventories")
	var prefix []string
	if inv.node != nil {
		file = "winch.yaml"
		if !inv.top {
			prefix = []string{"inventories", inv.name}
		}
	}
	path, err := filepath.EvalSymlinks(projectPath(dir, file))
	if errors.Is(err, fs.ErrNotExist) {
		return "", notFound(file)
	}
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", file, err)
	}
	n, err := yamlx.Parse(file, data)
	if err != nil {
		return "", err
	}
	keys := slices.Concat(prefix, []string{"groups", "all", "vars", name})
	where := "the group all"
	if host != "" {
		keys = slices.Concat(prefix, []string{"hosts", host, "vars", name})
		where = fmt.Sprintf("host %q", host)
		if find(n, keys[:len(prefix)+2]) == nil {
			return "", fmt.Errorf("host %q is not in %s", host, label)
		}
	}
	if find(n, keys) != nil {
		return "", fmt.Errorf("variable %q is already in the vars of %s in %s", name, where, label)
	}
	text, err := secret.Encrypt(plain, recs)
	if err != nil {
		return "", err
	}
	out := insert(string(data), n, keys, "!secret "+text)
	// insert assumes block maps; a check of the result catches every other
	// layout.
	after, err := yamlx.Parse(file, []byte(out))
	if err != nil || !reflect.DeepEqual(yamlx.Value(after), withValue(yamlx.Value(n), keys, text)) {
		return "", fmt.Errorf("cannot write vars.%s into %s; add it by hand", name, label)
	}
	return label, replaceFile(path, []byte(out))
}

// find returns the pair at the path of keys in n, or nil.
func find(n *yamlx.Node, keys []string) *yamlx.Pair {
	for i, key := range keys {
		if n.Kind != yamlx.Map {
			return nil
		}
		j := slices.IndexFunc(n.Pairs, func(p yamlx.Pair) bool { return p.Key == key })
		if j < 0 {
			return nil
		}
		if i == len(keys)-1 {
			return &n.Pairs[j]
		}
		n = n.Pairs[j].Value
	}
	return nil
}

// insert returns text, whose tree is root, with the map entries for keys and
// leaf as the value of the last key. It returns text when a map on the path
// is not a block map.
func insert(text string, root *yamlx.Node, keys []string, leaf string) string {
	lines := strings.SplitAfter(text, "\n")
	n := root
	for i := range keys {
		var at, col int
		rest := keys[i:]
		p := find(n, rest[:1])
		switch {
		case p != nil && p.Value.Kind == yamlx.Map && len(p.Value.Pairs) > 0:
			n = p.Value
			continue
		case p != nil && p.Value.Kind == yamlx.Null:
			at, col = p.KeyPos.Line, p.KeyPos.Col+2
			rest = rest[1:]
		case p != nil:
			return text
		case len(n.Pairs) == 0:
			at, col = len(lines), 1
		default:
			at, col = blockEnd(lines, n.Pairs[0].KeyPos), n.Pairs[0].KeyPos.Col
		}
		var b strings.Builder
		b.WriteString(strings.Join(lines[:at], ""))
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}
		for j, k := range rest {
			b.WriteString(strings.Repeat(" ", col-1+2*j) + k + ":")
			if j == len(rest)-1 {
				b.WriteString(" " + leaf)
			}
			b.WriteString("\n")
		}
		b.WriteString(strings.Join(lines[at:], ""))
		return b.String()
	}
	return text
}

// blockEnd returns the index of the line after the block map whose first key
// is at first: the line after its last line that is indented at least as far
// as the key.
func blockEnd(lines []string, first yamlx.Pos) int {
	end := first.Line
	for i := first.Line; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		rest := strings.TrimLeft(line, " ")
		if rest == "" {
			continue
		}
		if len(line)-len(rest) < first.Col-1 {
			break
		}
		end = i + 1
	}
	return end
}

// withValue returns a copy of v, a map, with leaf at the path of keys.
func withValue(v any, keys []string, leaf any) map[string]any {
	m, _ := v.(map[string]any)
	m = maps.Clone(m)
	if m == nil {
		m = map[string]any{}
	}
	if len(keys) == 1 {
		m[keys[0]] = leaf
	} else {
		m[keys[0]] = withValue(m[keys[0]], keys[1:], leaf)
	}
	return m
}
