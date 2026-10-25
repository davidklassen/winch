package project

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

// Keys decrypt the secrets of a project. Filter learns each secret value.
type Keys struct {
	// Identity is the path of the age identity file.
	Identity string
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

// unsealAll decrypts every sealed value with the identity of keys, and adds
// each plaintext to the filter.
func (l *loader) unsealAll(keys Keys) error {
	if len(l.sealed) == 0 {
		return nil
	}
	ids, err := secret.ReadIdentities(keys.Identity)
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

func decrypt(text string, ids []age.Identity, identity string) (string, error) {
	plain, err := secret.Decrypt(text, ids)
	if errors.Is(err, secret.ErrNotRecipient) {
		return "", fmt.Errorf("the identity in %s is not a recipient", identity)
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
	Main string
	Then string
	// Lines are the lines of the content with their masks, or nil when the
	// content holds no secret.
	Lines []secret.Line
	// Hidden is true when the output shows no part of the content.
	Hidden bool
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

// inventories returns the inventory files of the project: the files in
// inventories/, and the default inventory of winch.yaml.
func inventories(dir string, cfg *Config) ([]string, error) {
	files, err := list(dir, "inventories")
	if err != nil {
		return nil, err
	}
	if cfg.Inventory != "" && !slices.Contains(files, filepath.ToSlash(filepath.Clean(cfg.Inventory))) {
		files = append(files, filepath.ToSlash(filepath.Clean(cfg.Inventory)))
	}
	return files, nil
}

// Rekey encrypts every secret in winch.yaml, the inventories, and the recipes
// again for the recipients in winch.yaml. It writes no file when a secret
// fails. It returns the number of secrets and of files.
func Rekey(dir, identity string) (int, int, error) {
	cfg, err := loadConfig(dir)
	if err != nil {
		return 0, 0, err
	}
	recs, err := recipients(cfg)
	if err != nil {
		return 0, 0, err
	}
	invs, err := inventories(dir, cfg)
	if err != nil {
		return 0, 0, err
	}
	recipes, err := filepath.Glob(filepath.Join(dir, "recipes", "*", "recipe.yaml"))
	if err != nil {
		return 0, 0, err
	}
	files := append([]string{"winch.yaml"}, invs...)
	for _, r := range recipes {
		rel, err := filepath.Rel(dir, r)
		if err != nil {
			return 0, 0, err
		}
		files = append(files, filepath.ToSlash(rel))
	}
	var ids []age.Identity
	// next keeps one value that two places hold the same after rekey.
	next := map[string]string{}
	out := map[string][]byte{}
	count := 0
	var errs []error
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return 0, 0, err
		}
		n, err := yamlx.Parse(file, data)
		if err != nil {
			return 0, 0, err
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
			if ids, err = secret.ReadIdentities(identity); err != nil {
				return 0, 0, err
			}
		}
		lines := strings.SplitAfter(string(data), "\n")
		for _, t := range sealed {
			text, _ := t.Value.(string)
			plain, err := decrypt(text, ids, identity)
			if err != nil {
				errs = append(errs, yamlx.Errorf(t.Pos, "!secret: %v", err))
				continue
			}
			if next[text] == "" {
				if next[text], err = secret.Encrypt(plain, recs); err != nil {
					return 0, 0, err
				}
			}
			line := lines[t.Pos.Line-1]
			i := strings.Index(line, text)
			if i < 0 {
				errs = append(errs, yamlx.Errorf(t.Pos, "!secret: the value is not on one line"))
				continue
			}
			lines[t.Pos.Line-1] = line[:i] + next[text] + line[i+len(text):]
			count++
		}
		out[file] = []byte(strings.Join(lines, ""))
	}
	if err := errors.Join(errs...); err != nil {
		return 0, 0, err
	}
	for _, file := range slices.Sorted(maps.Keys(out)) {
		if err := replaceFile(filepath.Join(dir, file), out[file]); err != nil {
			return 0, 0, err
		}
	}
	return count, len(out), nil
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
// project files that is not a !secret.
func scanProject(dir string, cfg *Config) ([]*yamlx.Error, error) {
	invs, err := inventories(dir, cfg)
	if err != nil {
		return nil, err
	}
	pipelines, err := list(dir, "pipelines")
	if err != nil {
		return nil, err
	}
	files := []string{filepath.Join(dir, "winch.yaml")}
	for _, y := range append(invs, pipelines...) {
		files = append(files, filepath.Join(dir, y))
	}
	recipes, err := filepath.Glob(filepath.Join(dir, "recipes", "*", "recipe.yaml"))
	if err != nil {
		return nil, err
	}
	files = append(files, recipes...)
	for _, sub := range []string{"templates", "files"} {
		roots, err := filepath.Glob(filepath.Join(dir, "recipes", "*", sub))
		if err != nil {
			return nil, err
		}
		for _, root := range roots {
			err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.Type().IsRegular() {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	var out []*yamlx.Error
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(dir, path)
		line, last, prev := 1, -1, 0
		for _, f := range secret.Scan(data) {
			line += bytes.Count(data[prev:f.Offset], []byte("\n"))
			if i := bytes.LastIndexByte(data[prev:f.Offset], '\n'); i >= 0 {
				last = prev + i
			}
			prev = f.Offset
			col := f.Offset - last
			out = append(out, yamlx.Errorf(yamlx.Pos{File: filepath.ToSlash(rel), Line: line, Col: col}, "this looks like %s; use !secret", f.What))
		}
	}
	slices.SortStableFunc(out, func(a, b *yamlx.Error) int { return strings.Compare(a.Pos.File, b.Pos.File) })
	return out, nil
}
