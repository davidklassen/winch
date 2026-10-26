package module

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
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
	Key        string        `yaml:"key" json:"key,omitempty"`

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
	if hasSpace(r.Key) {
		return &yamlx.FieldError{Field: "key", Msg: spaceMsg}
	}
	if r.Key != "" && !strings.HasPrefix(r.Key, "https://") {
		return &yamlx.FieldError{Field: "key", Msg: "must start with https://, so the network cannot choose the key"}
	}
	return nil
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
	if r.Key != "" {
		fmt.Fprintf(&b, "Signed-By: %s\n", r.keyPath())
	}
	return []byte(b.String())
}

func (r *Repo) Check(ctx context.Context, st *State, _ func(string)) (Result, error) {
	if err := r.checkOthers(); err != nil {
		return Result{}, err
	}
	var changes []string
	if r.Key != "" {
		data, err := fetchKey(ctx, keyClient(), r.Key)
		if err != nil {
			return Result{}, fmt.Errorf("fetch the key %s: %w", r.Key, err)
		}
		newKey, err := parsePGPKey(data)
		if errors.Is(err, errNotArmored) {
			return Result{}, fmt.Errorf("%s %w", r.Key, err)
		}
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", r.Key, err)
		}
		f, lines, err := checkRepoFile(r.keyPath(), data)
		if err != nil {
			return Result{}, err
		}
		if f.fi == nil || string(f.old) != string(f.content) {
			if f.fi != nil {
				old, err := parsePGPKey(f.old)
				if err != nil {
					lines = append(lines, "replace "+r.keyPath()+": "+err.Error())
				} else {
					lines = append(lines, "remove key "+keyText(old))
				}
			}
			lines = append(lines, "add key "+keyText(newKey))
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

func keyText(k pgpKey) string {
	if k.userID == "" {
		return k.fingerprint
	}
	return k.fingerprint + " " + k.userID
}

// keyClient returns the HTTP client of a key fetch: no proxy, and https also
// after a redirect.
func keyClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("a redirect to %s, which is not https", req.URL)
			}
			if len(via) >= 10 {
				return errors.New("more than 10 redirects")
			}
			return nil
		},
	}
}

// fetchKey fetches the key with client.
func fetchKey(ctx context.Context, client *http.Client, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "winch")
	resp, err := client.Do(req)
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // the read gives the result
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDiff+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDiff {
		return nil, errors.New("larger than 1 MiB")
	}
	return data, nil
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
