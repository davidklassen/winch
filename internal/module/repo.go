package module

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Repo struct {
	Name       string        `yaml:"name,required" json:"name"`
	URL        string        `yaml:"url,required" json:"url"`
	Suite      string        `yaml:"suite,required" json:"suite"`
	Components yamlx.Strings `yaml:"components" json:"components,omitempty"`
	Key        string        `yaml:"key" json:"-"`
	KeyPos     yamlx.Pos     `json:"-"`
	// KeyData is the content of the key file in the recipe's files.
	KeyData []byte `json:"key_data,omitempty"`

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
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf(`%q is not a source name; a name has letters, digits, "_", "-", and ".", and does not start with "."`, r.Name)}
	}
	if hasSpace(r.URL) {
		return &yamlx.FieldError{Field: "url", Msg: spaceMsg}
	}
	u, err := url.Parse(r.URL)
	switch {
	case err != nil || u.Scheme != "http" && u.Scheme != "https":
		return &yamlx.FieldError{Field: "url", Msg: "must start with http:// or https://"}
	case u.Host == "":
		return &yamlx.FieldError{Field: "url", Msg: "has no host"}
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
		if c == "" || hasSpace(c) {
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
	return checkRelative("key", r.Key)
}

// SetKey sets the key data to data, the content of the key file name. data
// must be ASCII-armored OpenPGP public keys, and at least one primary key
// must not have expired at now. It returns a warning for each expired key
// and each key that expires within 30 days.
func (r *Repo) SetKey(name string, data []byte, now time.Time) ([]string, error) {
	keys, err := parsePGPKeys(data)
	if errors.Is(err, errNotArmored) {
		return nil, fmt.Errorf("%s %w", name, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var expired, warnings []string
	for _, k := range keys {
		switch {
		case k.expires.IsZero():
		case !now.Before(k.expires):
			msg := fmt.Sprintf("the key %s expired on %s", k.fingerprint, k.expires.Format(time.DateOnly))
			expired = append(expired, msg)
			warnings = append(warnings, name+": "+msg)
		case k.expires.Sub(now) < 30*24*time.Hour:
			warnings = append(warnings, fmt.Sprintf("%s: the key %s expires on %s", name, k.fingerprint, k.expires.Format(time.DateOnly)))
		}
	}
	if len(expired) == len(keys) {
		return nil, fmt.Errorf("%s: %s", name, strings.Join(expired, "; "))
	}
	r.KeyData = data
	return warnings, nil
}

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

func (r *Repo) Check(_ context.Context, st *State, _ func(string)) (Result, error) {
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
		st.IndexFresh = false
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
	return k.fingerprint + " " + k.userID
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
		data, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
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
// owner and mode changes.
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
	return f, lines, err
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
func (r *Repo) Apply(ctx context.Context, note func(string)) error {
	for i, f := range r.writes {
		if err := writeRoot(f.path, f.content, 0, 0, 0o644); err != nil {
			return undo(r.writes[:i], err)
		}
	}
	if !r.refresh {
		return nil
	}
	if err := waitIndexLock(ctx, note); err != nil {
		return undo(r.writes, err)
	}
	_, err := run(ctx, aptEnv, "apt-get", "update", "-q", "--error-on=any",
		"-o", "Dir::Etc::SourceList="+r.sourcePath(), "-o", "Dir::Etc::SourceParts=-",
		"-o", "APT::Get::List-Cleanup=0", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=")
	if err != nil {
		return undo(r.writes, fmt.Errorf("refresh the index of source %s: %w; the old files are back", r.Name, err))
	}
	return nil
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
	return writeRoot(f.path, f.old, st.Uid, st.Gid, uint32(st.Mode)&0o7777)
}

// writeRoot writes content to the file p through a rename, and creates its
// missing parents.
func writeRoot(p string, content []byte, uid, gid, mode uint32) error {
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
	return writeFile(dir, path.Base(p), content, uid, gid, mode, func(tmp string) error {
		return dir.Rename(tmp, path.Base(p))
	})
}
