package module

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Repo struct {
	Name       string        `yaml:"name,required" json:"name" line:"file name in /etc/apt" doc:"File name in /etc/apt, of the source file and of the key file."`
	URL        string        `yaml:"url,required" json:"url" line:"without a user or a password" doc:"Without a user or a password."`
	Suite      string        `yaml:"suite,required" json:"suite" line:"such as trixie" doc:"Such as trixie. A flat suite ends in /."`
	Components yamlx.Strings `yaml:"components" json:"components,omitempty" line:"such as main" doc:"Such as main. They are required, except for a flat suite, which has none."`
	Key        string        `yaml:"key" json:"-" line:"key file in the recipe's files/" doc:"Key file in the recipe's files/ directory: an ASCII-armored OpenPGP public key. Download the vendor's key once and keep it in the project. A step has at most one of key and key_content."`
	KeyPos     yamlx.Pos     `json:"-"`
	KeyContent *string       `yaml:"key_content" json:"-" line:"key text, in place of key" doc:"Key text, in place of key: an ASCII-armored OpenPGP public key. A step has at most one of key and key_content."`
	// KeyContentPos is the position of key_content.
	KeyContentPos yamlx.Pos `json:"-"`
	// KeyData is key_content, or the content of the key file in the recipe's
	// files.
	KeyData []byte `json:"key_data,omitempty"`
	// Removed are the paths that earlier steps of the host remove. The
	// controller sets them.
	Removed []string `json:"removed,omitempty"`

	// Check sets these for Apply.
	writes  []repoFile
	refresh bool
}

// repoFile is a file that Apply writes, with what Check found at its path.
type repoFile struct {
	path    string
	content []byte
	// old is the content of the file, and fi its info, or nil when there is
	// no file.
	old []byte
	fi  fs.FileInfo
}

const (
	sourcesDir = "/etc/apt/sources.list.d"
	keyringDir = "/etc/apt/keyrings"
)

func (r *Repo) Main() string { return r.Name }

var sourceNameRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)

// hasSpace reports whether s has white space or a control character.
func hasSpace(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

const spaceMsg = "has white space or a control character"

func (r *Repo) Validate() error {
	if !sourceNameRe.MatchString(r.Name) {
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf(`%q is not a source name; a name has letters, digits, _, -, and ., and does not start with .`, r.Name)}
	}
	if hasSpace(r.URL) {
		return &yamlx.FieldError{Field: "url", Msg: spaceMsg}
	}
	u, err := parseHTTPURL(r.URL)
	switch {
	case err != nil:
		return err
	case u.User != nil:
		return &yamlx.FieldError{Field: "url", Msg: fmt.Sprintf("holds a user name or password, and the source file is world-readable; put them in /etc/apt/auth.conf.d/%s.conf with mode 0600", r.Name)}
	}
	if r.Suite == "" {
		return &yamlx.FieldError{Field: "suite", Msg: "is empty"}
	}
	if hasSpace(r.Suite) {
		return &yamlx.FieldError{Field: "suite", Msg: spaceMsg}
	}
	for i, c := range r.Components {
		switch {
		case c == "":
			return &yamlx.FieldError{Field: "components", Msg: fmt.Sprintf("element %d is empty", i+1)}
		case hasSpace(c):
			return &yamlx.FieldError{Field: "components", Msg: fmt.Sprintf("element %d %s", i+1, spaceMsg)}
		}
	}
	flat := strings.HasSuffix(r.Suite, "/")
	switch {
	case flat && len(r.Components) > 0:
		return &yamlx.FieldError{Field: "components", Msg: `a flat suite, which ends in "/", has no components`}
	case !flat && len(r.Components) == 0:
		return &yamlx.FieldError{Field: "suite", Msg: `needs components, such as [main]; only a flat suite, which ends in "/", has none`}
	}
	if r.KeyPos.Line > 0 && r.KeyContent != nil {
		return &yamlx.FieldError{At: "key_content", Msg: "a repo step has at most one of key and key_content"}
	}
	return CheckRelative("key", r.Key)
}

// SetKey sets the key data to data, the content of the key file name. data
// must be ASCII-armored OpenPGP public keys, and at least one key must be able
// to sign at now. It returns a warning for each key that cannot sign, each key
// that stops signing within 30 days, and each key that apt rejects for its
// algorithm or hash.
func (r *Repo) SetKey(name string, data []byte, now time.Time) ([]string, error) {
	keys, err := parsePGPKeys(data)
	if errors.Is(err, errNotArmored) {
		return nil, fmt.Errorf("%s %w", name, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var dead, warnings []string
	for _, k := range keys {
		var weak []string
		if k.weak != "" {
			weak = append(weak, fmt.Sprintf("the key %s %s", k.fingerprint, k.weak))
		}
		for _, s := range k.subkeys {
			if s.weak != "" {
				weak = append(weak, fmt.Sprintf("the signing subkey %s of the key %s %s", s.fingerprint, k.fingerprint, s.weak))
			}
		}
		signer, until, ok := lastSigner(k)
		switch {
		case !ok && len(weak) > 0:
			dead = append(dead, strings.Join(weak, "; "))
		case !ok:
			msg := fmt.Sprintf("the key %s has no key or subkey that can sign", k.fingerprint)
			dead = append(dead, msg)
			warnings = append(warnings, name+": "+msg)
		case until.IsZero():
		case !now.Before(until):
			msg := fmt.Sprintf("%s expired on %s", signer, until.Format(time.DateOnly))
			dead = append(dead, msg)
			warnings = append(warnings, name+": "+msg)
		case until.Sub(now) < 30*24*time.Hour:
			warnings = append(warnings, fmt.Sprintf("%s: %s expires on %s", name, signer, until.Format(time.DateOnly)))
		}
		for _, w := range weak {
			warnings = append(warnings, name+": "+w)
		}
	}
	if len(dead) == len(keys) {
		return nil, fmt.Errorf("%s: %s", name, strings.Join(dead, "; "))
	}
	r.KeyData = data
	return warnings, nil
}

// lastSigner returns the part of k that can sign longest, for a message, and
// when it stops, or zero for never. The primary key's expiry ends every
// subkey. A weak primary key also ends its subkeys, because it makes their
// binding signatures. ok is false when no part of k that apt accepts can sign.
func lastSigner(k pgpKey) (signer string, until time.Time, ok bool) {
	if k.weak != "" {
		return "", time.Time{}, false
	}
	var last *pgpSubkey
	if !k.signs {
		for i, s := range k.subkeys {
			if s.weak != "" {
				continue
			}
			if last == nil || !last.expires.IsZero() && (s.expires.IsZero() || s.expires.After(last.expires)) {
				last = &k.subkeys[i]
			}
		}
		if last == nil {
			return "", time.Time{}, false
		}
		until = last.expires
	}
	if !k.expires.IsZero() && (until.IsZero() || k.expires.Before(until)) {
		last, until = nil, k.expires
	}
	if last != nil {
		return fmt.Sprintf("the signing subkey %s of the key %s", last.fingerprint, k.fingerprint), until, true
	}
	return "the key " + k.fingerprint, until, true
}

// Source names the step's source: two steps with the same Source write the same
// apt entry.
func (r *Repo) Source() string { return uriKey(r.URL) + " " + r.Suite }

func (r *Repo) sourcePath() string { return sourcesDir + "/" + r.Name + ".sources" }
func (r *Repo) keyPath() string    { return keyringDir + "/" + r.Name + ".asc" }

// source returns the content of the source file.
func (r *Repo) source() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "Types: deb\nURIs: %s\nSuites: %s\n", r.URL, r.Suite)
	if len(r.Components) > 0 {
		fmt.Fprintf(&b, "Components: %s\n", strings.Join(r.Components, " "))
	}
	if r.KeyData != nil {
		fmt.Fprintf(&b, "Signed-By: %s\n", r.keyPath())
	}
	return []byte(b.String())
}

func (r *Repo) Check(_ context.Context, st *State, _ Say) (Result, error) {
	if err := r.checkOthers(); err != nil {
		return Result{}, err
	}
	var changes []string
	if r.KeyData != nil {
		f, lines, err := checkRepoFile(r.keyPath(), r.KeyData)
		if err != nil {
			return Result{}, err
		}
		if f.fi == nil || string(f.old) != string(f.content) {
			kl, err := keyFileChanges(r.keyPath(), f.old, r.KeyData)
			if err != nil {
				return Result{}, err
			}
			lines = append(lines, kl...)
			r.refresh = true
		}
		changes = append(changes, lines...)
		if len(lines) > 0 {
			r.writes = append(r.writes, f)
		}
	}
	f, lines, err := checkRepoFile(r.sourcePath(), r.source())
	if err != nil {
		return Result{}, err
	}
	if err := r.checkOwnFile(f.old); err != nil {
		return Result{}, err
	}
	action := Modify
	switch {
	case f.fi == nil:
		action = Create
		r.refresh = true
	case string(f.old) != string(f.content):
		lines = append(sourceChanges(r.sourcePath(), f.old, f.content), lines...)
		r.refresh = true
	}
	changes = append(changes, lines...)
	if len(lines) > 0 {
		r.writes = append(r.writes, f)
	}
	if len(changes) == 0 {
		return Result{Status: OK}, nil
	}
	if r.refresh {
		changes = append(changes, "refresh the index of source "+r.Name)
		st.IndexFresh, st.Refreshed = false, false
	}
	return Result{Status: Change, Action: action, Changes: changes}, nil
}

// keyFileChanges describes how the key file p changes from old, nil when there
// is no file, to new.
func keyFileChanges(p string, old, new []byte) ([]string, error) {
	newKeys, err := parsePGPKeys(new)
	if err != nil {
		return nil, fmt.Errorf("the key: %w", err)
	}
	var lines []string
	var oldKeys []pgpKey
	if old != nil {
		oldKeys, err = parsePGPKeys(old)
		if err != nil {
			lines = append(lines, "replace "+p+": "+err.Error())
		}
	}
	for _, o := range oldKeys {
		if !slices.ContainsFunc(newKeys, func(k pgpKey) bool { return k.fingerprint == o.fingerprint }) {
			lines = append(lines, "remove key "+keyText(o))
		}
	}
	for _, k := range newKeys {
		i := slices.IndexFunc(oldKeys, func(o pgpKey) bool { return o.fingerprint == k.fingerprint })
		switch {
		case i < 0:
			lines = append(lines, "add key "+keyText(k))
		case oldKeys[i].data != k.data:
			lines = append(lines, "update key "+k.fingerprint+" (same key, new content)")
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "rewrite "+p)
	}
	return lines, nil
}

func keyText(k pgpKey) string {
	if k.userID == "" {
		return k.fingerprint
	}
	return k.fingerprint + " " + secret.Printable(k.userID)
}

// checkOthers fails when another sources file of apt lists the source.
func (r *Repo) checkOthers() error {
	files := []string{"/etc/apt/sources.list"}
	entries, err := os.ReadDir(sourcesDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if n == r.Name+".sources" || !sourceNameRe.MatchString(n) || !strings.HasSuffix(n, ".list") && !strings.HasSuffix(n, ".sources") {
			continue
		}
		files = append(files, path.Join(sourcesDir, n))
	}
	for _, f := range files {
		if r.removed(f) {
			continue
		}
		fi, err := os.Stat(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		for _, s := range parseSources(f, data) {
			if s.has(r.URL, r.Suite) {
				return fmt.Errorf("the source %s %s is also in %s; remove it there", r.URL, r.Suite, f)
			}
		}
	}
	return nil
}

// checkRepoFile reads the file at p, which must hold content, owned by root
// with mode 0644. The lines are the missing parents and the new file, or the
// owner and mode changes. A file that must change fails with the immutable or
// append-only flag.
func checkRepoFile(p string, content []byte) (repoFile, []string, error) {
	f := repoFile{path: p, content: content}
	dir, missing, err := openParent(p)
	if err != nil {
		return f, nil, err
	}
	defer dir.Close()
	fi, ok, err := lstat(dir, path.Base(p), missing)
	if err != nil {
		return f, nil, err
	}
	if !ok {
		return f, append(parentChanges(missing), "create file "+p+" ("+attrLine("root", "root", 0o644)+")"), nil
	}
	if !fi.Mode().IsRegular() {
		return f, nil, fmt.Errorf("%s is %s, not a file", p, kind(fi))
	}
	file, err := openSame(dir, path.Base(p), fi)
	if err != nil {
		return f, nil, err
	}
	defer file.Close()
	if f.old, err = io.ReadAll(io.LimitReader(file, maxDiff+1)); err != nil {
		return f, nil, err
	}
	// Apply puts the old content back when the refresh fails.
	if len(f.old) > maxDiff {
		return f, nil, fmt.Errorf("%s is larger than 1 MiB", p)
	}
	f.fi = fi
	lines, err := prefixed(p, fi, "root", "root", 0o644)
	if err != nil || len(lines) == 0 && string(f.old) == string(content) {
		return f, lines, err
	}
	return f, lines, noFlags(dir, path.Base(p), fi, p)
}

// sourceFields are the fields of a source file that winch writes.
var sourceFields = []string{"Types", "URIs", "Suites", "Components", "Signed-By"}

// sourceChanges describes how the source file p changes from old to new, per
// field when old is one stanza of the fields that winch writes.
func sourceChanges(p string, old, new []byte) []string {
	o, n := stanzas(string(old)), stanzas(string(new))[0]
	if len(o) != 1 {
		return []string{"rewrite " + p}
	}
	for k := range o[0] {
		if !slices.ContainsFunc(sourceFields, func(f string) bool { return strings.EqualFold(f, k) }) {
			return []string{"rewrite " + p}
		}
	}
	var lines []string
	for _, field := range sourceFields {
		k := strings.ToLower(field)
		a, b := strings.Join(strings.Fields(o[0][k]), " "), strings.Join(strings.Fields(n[k]), " ")
		if a == b {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: %s %s → %s", p, field, orNone(a), orNone(b)))
	}
	if len(lines) == 0 {
		return []string{"rewrite " + p}
	}
	return lines
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// Apply writes the files that Check found different and refreshes the index
// of the source. When the refresh fails, it puts the old files back.
func (r *Repo) Apply(ctx context.Context, say Say) error {
	for i, f := range r.writes {
		if err := writeRoot(f.path, f.content, 0, 0, 0o644); err != nil {
			return undo(r.writes[:i], err)
		}
	}
	if !r.refresh {
		return nil
	}
	if err := waitIndexLock(ctx, say.Progress); err != nil {
		return undo(r.writes, err)
	}
	if err := r.update(ctx); err != nil {
		return undo(r.writes, fmt.Errorf("refresh the index of source %s: %w; the old files are back", r.Name, err))
	}
	return nil
}

// update refreshes the index of this source only.
func (r *Repo) update(ctx context.Context) error {
	_, err := aptGet(ctx, "update", "-q", "--error-on=any",
		"-o", "Dir::Etc::SourceList="+r.sourcePath(), "-o", "Dir::Etc::SourceParts=-",
		"-o", "APT::Get::List-Cleanup=0", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=")
	return err
}

// undo puts the files back as Check found them, the last first.
func undo(files []repoFile, err error) error {
	errs := []error{err}
	for i := len(files) - 1; i >= 0; i-- {
		errs = append(errs, files[i].restore())
	}
	return errors.Join(errs...)
}

// restore puts the file back as Check found it.
func (f repoFile) restore() error {
	if f.fi == nil {
		err := os.Remove(f.path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	st := f.fi.Sys().(*syscall.Stat_t)
	return writeRoot(f.path, f.old, int(st.Uid), int(st.Gid), uint32(st.Mode)&0o7777)
}

// writeRoot writes content to the file p through a rename, and creates its
// missing parents.
func writeRoot(p string, content []byte, uid, gid int, mode uint32) error {
	dir, missing, err := openParent(p)
	if err != nil {
		return err
	}
	defer dir.Close()
	if len(missing) > 0 {
		sub, err := mkdirs(dir, missing)
		if err != nil {
			return err
		}
		defer sub.Close()
		dir = sub
	}
	err = writeFile(dir, path.Base(p), bytes.NewReader(content), uid, gid, mode, func(tmp string) error {
		return dir.Rename(tmp, path.Base(p))
	})
	return pathError("write", p, err)
}

// removed reports whether an earlier step removes p or a parent of p.
func (r *Repo) removed(p string) bool {
	for _, d := range r.Removed {
		if p == d || strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

// checkOwnFile fails when old, the content of the source file, holds more
// than one entry or an entry that is not deb. One deb entry is the step's
// source, perhaps with an old URI or suite.
func (r *Repo) checkOwnFile(old []byte) error {
	if r.removed(r.sourcePath()) {
		return nil
	}
	var entries, keys []string
	for _, st := range stanzas(string(old)) {
		for _, t := range strings.Fields(st["types"]) {
			for _, u := range strings.Fields(st["uris"]) {
				for _, s := range strings.Fields(st["suites"]) {
					if k := t + " " + uriKey(u) + " " + s; !slices.Contains(keys, k) {
						keys = append(keys, k)
						entries = append(entries, t+" "+u+" "+s)
					}
				}
			}
		}
	}
	if len(keys) == 1 && strings.HasPrefix(keys[0], "deb ") {
		return nil
	}
	for i, k := range keys {
		if k != "deb "+r.Source() {
			return r.otherEntry(entries[i])
		}
	}
	return nil
}

func (r *Repo) otherEntry(e string) error {
	return fmt.Errorf("%s holds %s, which is not this step's source; move it to another file", r.sourcePath(), e)
}
