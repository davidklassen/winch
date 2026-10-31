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
	// Why is a line that an error of the age key ends with, or "".
	Why string
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
// recipients is not n, the length of recipients in file. age records only the
// number, not the keys.
func (l *loader) staleSecrets(file string, n int) ([]*yamlx.Error, error) {
	var out []*yamlx.Error
	var errs []error
	for _, s := range l.sealed {
		got, err := secret.Stanzas(s.s.Text)
		if err != nil {
			errs = append(errs, yamlx.Errorf(s.pos, "!secret: %v", err))
			continue
		}
		if got != n {
			out = append(out, yamlx.Errorf(s.pos, "this secret is encrypted for %s; %s lists %d; a member who can read it must run winch secret rekey", publicKeyCount(got), file, n))
		}
	}
	return out, errors.Join(errs...)
}

func publicKeyCount(n int) string {
	if n == 1 {
		return "1 public key"
	}
	return fmt.Sprintf("%d public keys", n)
}

// unsealAll decrypts every sealed value with the age key of keys, and adds
// each plaintext to the filter. recipients are the public keys in the project
// file.
func (l *loader) unsealAll(ctx context.Context, keys Keys, recipients []string) error {
	if len(l.sealed) == 0 {
		return nil
	}
	ids, err := keys.Identity.Read(ctx)
	if err != nil {
		return withWhy(err, keys.Why)
	}
	k := &keyring{identity: keys.Identity, ids: ids, recipients: recipients, why: keys.Why}
	var errs []error
	for _, s := range l.sealed {
		plain, ok, err := k.decrypt(s.s.Text, s.pos)
		if !ok {
			errs = append(errs, err)
			continue
		}
		s.s.Plain = plain
		keys.Filter.Add(plain)
	}
	return errors.Join(errs...)
}

func withWhy(err error, why string) error {
	if why == "" {
		return err
	}
	return errors.Join(err, errors.New(why))
}

// keyring decrypts secrets with an age key. It reports only the first
// secret that the key cannot read.
type keyring struct {
	identity   secret.Identity
	ids        []age.Identity
	recipients []string
	why        string
	reported   bool
}

// decrypt returns the plaintext of text, the secret at pos. When ok is false,
// err is the error to report, or nil for a key error that was reported.
func (k *keyring) decrypt(text string, pos yamlx.Pos) (plain string, ok bool, err error) {
	plain, err = secret.Decrypt(text, k.ids)
	switch {
	case errors.Is(err, secret.ErrNotRecipient):
		if k.reported {
			return "", false, nil
		}
		k.reported = true
		return "", false, withWhy(k.cannotRead(pos), k.why)
	case err != nil:
		return "", false, yamlx.Errorf(pos, "!secret: %v", err)
	}
	return plain, true, nil
}

// cannotRead returns the error at pos, the first secret that the age key
// cannot read. The fix depends on whether its public key is in recipients.
func (k *keyring) cannotRead(pos yamlx.Pos) error {
	for _, key := range secret.PublicKeys(k.ids) {
		if slices.Contains(k.recipients, key) {
			return yamlx.Errorf(pos, "the secrets are not encrypted for the age key %s yet; a member who can read them must run winch secret rekey", k.identity)
		}
	}
	set := "WINCH_AGE_KEY to an age key"
	if k.identity.Cmd != "" {
		set = "WINCH_AGE_IDENTITY_CMD to a command that prints an age key"
	}
	return yamlx.Errorf(pos, "the age key %s is not in recipients; set %s in recipients, or run winch secret init and ask a member to run winch secret rekey", k.identity, set)
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

// sealedFields adds to fields each field that holds a secret in a map element
// of the list or map v. It returns false when a secret is in another place.
func sealedFields(v any, fields map[string]bool) bool {
	var elems []any
	switch v := v.(type) {
	case []any:
		elems = v
	case map[string]any:
		elems = slices.Collect(maps.Values(v))
	default:
		return false
	}
	for _, e := range elems {
		if !hasSealed(e) {
			continue
		}
		m, ok := e.(map[string]any)
		if !ok {
			return false
		}
		for k, x := range m {
			if hasSealed(x) {
				fields[k] = true
			}
		}
	}
	return true
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
	// every user of the host can read, or "": a repo source or a certbot
	// renewal file.
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

// Recipients returns the recipients in the project file.
func Recipients(dir string) ([]age.Recipient, error) {
	cfg, err := loadConfig(dir)
	if err != nil {
		return nil, err
	}
	return recipients(cfg)
}

func recipients(cfg *Config) ([]age.Recipient, error) {
	if len(cfg.Recipients) == 0 {
		return nil, fmt.Errorf("%s has no recipients; run winch secret init", cfg.file)
	}
	return secret.ParseRecipients(cfg.Recipients)
}

// RecipientEdit is the project file with a new key in recipients.
type RecipientEdit struct {
	// File is winch.yaml or winch.yml.
	File string
	path string
	text []byte
}

// AddRecipient returns the edit that adds key to recipients in the project
// file, or nil when key is in the list. The edit keeps the comments and the
// layout of the file.
func AddRecipient(dir, key string) (*RecipientEdit, error) {
	file, err := projectFile(dir)
	if err != nil {
		return nil, err
	}
	path, err := filepath.EvalSymlinks(projectPath(dir, file))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w; run winch in the project directory", notFound(file))
	}
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	n, err := yamlx.Parse(file, data)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yamlx.Decode(n, &cfg); err != nil {
		return nil, err
	}
	if slices.Contains(cfg.Recipients, key) {
		return nil, nil
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
	if n, err := yamlx.Parse(file, []byte(text)); err != nil || yamlx.Decode(n, &after) != nil ||
		!slices.Equal(after.Recipients, append(cfg.Recipients, key)) {
		return nil, fmt.Errorf("cannot add the public key to recipients in %s; add it by hand", file)
	}
	return &RecipientEdit{File: file, path: path, text: []byte(text)}, nil
}

func (e *RecipientEdit) Write() error {
	return replaceFile(e.path, e.text)
}

// secretFiles returns the files that can hold a secret: the project file,
// the inventories, and the recipes.
func secretFiles(dir string, cfg *Config) ([]string, error) {
	invs, err := list(dir, "inventories")
	if err != nil {
		return nil, err
	}
	recipes, err := recipeFiles(dir)
	if err != nil {
		return nil, err
	}
	return slices.Concat([]string{cfg.file}, invs, recipes), nil
}

func HasSecrets(dir string) (bool, error) {
	cfg, err := loadConfig(dir)
	if err != nil {
		return false, err
	}
	files, err := secretFiles(dir, cfg)
	if err != nil {
		return false, err
	}
	for _, file := range files {
		n, err := parse(dir, file)
		if err != nil {
			return false, err
		}
		found := false
		walkTags(n, func(t *yamlx.Node) { found = found || t.Tag == "!secret" })
		if found {
			return true, nil
		}
	}
	return false, nil
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
	files, err := secretFiles(dir, cfg)
	if err != nil {
		return 0, nil, err
	}
	var k *keyring
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
		if k == nil {
			ids, err := identity.Read(ctx)
			if err != nil {
				return 0, nil, err
			}
			k = &keyring{identity: identity, ids: ids, recipients: cfg.Recipients}
		}
		orig := strings.SplitAfter(string(data), "\n")
		lines := slices.Clone(orig)
		// shift is the change in length of each line by the earlier
		// replacements on it.
		shift := map[int]int{}
		for _, t := range sealed {
			text, _ := t.Value.(string)
			plain, ok, err := k.decrypt(text, t.Pos)
			if !ok {
				errs = append(errs, err)
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
func scanProject(dir, project string, plain func([]byte)) ([]*yamlx.Error, error) {
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
	files := slices.Concat([]string{project}, invs, pipelines, recipes)
	kinds := map[string]string{project: "project"}
	for _, f := range invs {
		kinds[f] = "inventory"
	}
	for _, f := range recipes {
		kinds[f] = "recipe"
	}
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
				kinds[filepath.ToSlash(rel)] = sub
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
		found := secret.Scan(data)
		if len(found) == 0 {
			continue
		}
		var vars map[int]bool
		fix := "put it in a variable with !secret, and read the variable here"
		switch kinds[file] {
		case "templates":
			fix = "put it in a variable with !secret, and read it with .vars"
		case "files":
			fix = "put it in a variable with !secret, move the file to templates/, and use template in place of source to read it with .vars"
		case "inventory":
			fix = "move it into vars with !secret"
			fallthrough
		case "project", "recipe":
			if n, err := yamlx.Parse(file, data); err == nil {
				vars = varLines(n, kinds[file], strings.SplitAfter(string(data), "\n"))
			}
		}
		line, last, prev := 1, -1, 0
		for _, f := range found {
			line += bytes.Count(data[prev:f.Offset], []byte("\n"))
			if i := bytes.LastIndexByte(data[prev:f.Offset], '\n'); i >= 0 {
				last = prev + i
			}
			prev = f.Offset
			col := f.Offset - last
			at := fix
			if vars[line] {
				at = "use !secret"
			}
			out = append(out, yamlx.Errorf(yamlx.Pos{File: file, Line: line, Col: col}, "this looks like %s; %s", f.What, at))
		}
	}
	slices.SortStableFunc(out, func(a, b *yamlx.Error) int { return strings.Compare(a.Pos.File, b.Pos.File) })
	return out, nil
}

// varLines returns the lines of the variable values in n, the tree of lines,
// a file of kind "project", "inventory", or "recipe". A !secret can stand on
// these lines.
func varLines(n *yamlx.Node, kind string, lines []string) map[int]bool {
	out := map[int]bool{}
	defaults := func(n *yamlx.Node) {
		p := find(n, []string{"vars"})
		if p == nil || p.Value.Kind != yamlx.Map || len(p.Value.Pairs) == 0 {
			return
		}
		for i := p.KeyPos.Line; i <= blockEnd(lines, p.Value.Pairs[0].KeyPos); i++ {
			out[i] = true
		}
	}
	inventory := func(n *yamlx.Node) {
		for _, key := range []string{"hosts", "groups"} {
			if p := find(n, []string{key}); p != nil {
				for _, e := range p.Value.Pairs {
					defaults(e.Value)
				}
			}
		}
	}
	switch kind {
	case "inventory":
		inventory(n)
	case "recipe":
		defaults(n)
	case "project":
		defaults(n)
		inventory(n)
		if p := find(n, []string{"inventories"}); p != nil {
			for _, e := range p.Value.Pairs {
				inventory(e.Value)
			}
		}
		if p := find(n, []string{"recipes"}); p != nil {
			for _, e := range p.Value.Pairs {
				defaults(e.Value)
			}
		}
	}
	return out
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
	// A layout error can hide the inventory to write into.
	if _, err := readLayout(dir, cfg); err != nil {
		return "", err
	}
	// The reads of the parts that load are enough: a broken template in
	// another recipe does not block a new secret. The load errors show only
	// when the variable is not found, as they may hide its read.
	l, lErr := newLoader(dir, cfg)
	_, plErr := l.otherPipelines("")
	if read := l.readNames(); !read[name] {
		return "", errors.Join(fmt.Errorf("nothing reads vars.%s%s", name, yamlx.Suggest(name, slices.Sorted(maps.Keys(read)))), lErr, plErr)
	}
	inventory = cmp.Or(inventory, cfg.Inventory, l.layout.only())
	if inventory == "" {
		return "", l.noInventory()
	}
	inv, err := l.layout.inventory(inventory)
	if err != nil {
		return "", err
	}
	// A key in winch.yaml is the map at prefix.
	file, label := inv.file, inv.label("inventories")
	var prefix []string
	if inv.node != nil {
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
		where = "host " + host
		if find(n, keys[:len(prefix)+2]) == nil {
			return "", fmt.Errorf("host %s is not in %s", host, label)
		}
	}
	if find(n, keys) != nil {
		return "", fmt.Errorf("vars.%s is already in the vars of %s in %s", name, where, label)
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
