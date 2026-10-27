package module

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/davidklassen/winch/internal/yamlx"
)

type File struct {
	Path        string    `yaml:"path,required" json:"path"`
	Content     *string   `yaml:"content" json:"-"`
	Template    string    `yaml:"template" json:"-"`
	TemplatePos yamlx.Pos `json:"-"`
	Source      string    `yaml:"source" json:"-"`
	SourcePos   yamlx.Pos `json:"-"`
	// Data is the content for the host, from content, template, or source.
	// Without omitempty, JSON keeps nil apart from empty content.
	Data       []byte         `json:"data"`
	DataSHA256 string         `json:"data_sha256,omitempty"`
	Owner      yamlx.NameOrID `yaml:"owner" json:"owner,omitempty"`
	Group      yamlx.NameOrID `yaml:"group" json:"group,omitempty"`
	Mode       string         `yaml:"mode" json:"mode,omitempty"`
	Validation *string        `yaml:"validate" json:"validate,omitempty"`
	Absent     bool           `yaml:"absent" json:"absent,omitempty"`
	Replace    bool           `yaml:"replace" json:"replace,omitempty"`
}

func (f *File) Main() string { return f.Path }

func (f *File) Validate() error {
	if err := checkPath(f.Path); err != nil {
		return err
	}
	sources := []arg{{"content", f.Content != nil}, {"template", f.Template != ""}, {"source", f.Source != ""}}
	if f.Absent {
		return absentTakesNone(append(sources, arg{"owner", f.Owner != ""}, arg{"group", f.Group != ""}, arg{"mode", f.Mode != ""}, arg{"validate", f.Validation != nil}, arg{"replace", f.Replace})...)
	}
	if err := checkCommand("validate", f.Validation); err != nil {
		return err
	}
	set := 0
	for _, a := range sources {
		if a.set {
			set++
		}
		if a.set && set > 1 {
			return &yamlx.FieldError{Field: a.name, Msg: "a file has only one of content, template, and source"}
		}
	}
	if set == 0 {
		return &yamlx.FieldError{Field: "content", Msg: "a file needs content, template, or source, or absent: true"}
	}
	if err := checkRelative("template", f.Template); err != nil {
		return err
	}
	if err := checkRelative("source", f.Source); err != nil {
		return err
	}
	if err := checkOwner("owner", f.Owner); err != nil {
		return err
	}
	if err := checkOwner("group", f.Group); err != nil {
		return err
	}
	return checkMode(f.Mode, "0644")
}

func checkCommand(field string, c *string) error {
	if c != nil && *c == "" {
		return &yamlx.FieldError{Field: field, Msg: "must not be empty"}
	}
	return nil
}

var numberRe = regexp.MustCompile(`^[0-9]+$`)

// checkOwner checks an owner or a group: the characters of a name, and the
// range of a value of only digits. chown takes the ID 4294967295 as "no
// change".
func checkOwner(field string, v yamlx.NameOrID) error {
	if strings.ContainsAny(string(v), ":/") || strings.ContainsFunc(string(v), unicode.IsSpace) || strings.HasPrefix(string(v), "-") {
		return &yamlx.FieldError{Field: field, Msg: fmt.Sprintf(`%q is not a name; a name has no ":", "/", or white space, and does not start with "-"`, v)}
	}
	if !numberRe.MatchString(string(v)) {
		return nil
	}
	return checkID(field, yamlx.ID(v))
}

var modeRe = regexp.MustCompile(`^[0-7]{3,4}$`)

func checkMode(mode, example string) error {
	if mode != "" && !modeRe.MatchString(mode) {
		return &yamlx.FieldError{Field: "mode", Msg: fmt.Sprintf("must be an octal mode such as %q", example)}
	}
	return nil
}

func checkRelative(field, p string) error {
	if p != "" && (!fs.ValidPath(p) || p == ".") {
		return &yamlx.FieldError{Field: field, Msg: `must be a clean relative path, such as "a/b.conf"`}
	}
	return nil
}

func checkPath(p string) error {
	if p == "/" {
		return &yamlx.FieldError{Field: "path", Msg: "must not be /"}
	}
	return checkAbs("path", p)
}

// checkAbs checks that p is a clean absolute path without ".." and without
// control characters.
func checkAbs(field, p string) error {
	switch {
	case strings.ContainsFunc(p, unicode.IsControl):
		return &yamlx.FieldError{Field: field, Msg: "has a control character"}
	case !path.IsAbs(p):
		return &yamlx.FieldError{Field: field, Msg: "must be an absolute path"}
	case slices.Contains(strings.Split(p, "/"), ".."):
		return &yamlx.FieldError{Field: field, Msg: `".." is not allowed; write the path without it`}
	case path.Clean(p) != p:
		return &yamlx.FieldError{Field: field, Msg: fmt.Sprintf("must be a clean path, such as %q", path.Clean(p))}
	}
	return nil
}

type arg struct {
	name string
	set  bool
}

func absentTakesNone(args ...arg) error {
	return takesNone("absent: true", args...)
}

// takesNone fails for the first of args that is set: what takes none of them.
func takesNone(what string, args ...arg) error {
	for _, a := range args {
		if a.set {
			return &yamlx.FieldError{Field: a.name, Msg: what + " takes no " + a.name}
		}
	}
	return nil
}

func (f *File) WithoutContent() Module {
	c := *f
	if f.Data != nil {
		c.DataSHA256 = sha(f.Data)
		c.Data = nil
	}
	return &c
}

// OthersRead reports whether the mode, or the default mode, lets others read
// the file.
func (f *File) OthersRead() bool {
	_, _, mode, err := attrs("", "", f.Mode, "0644")
	return err == nil && mode&0o004 != 0
}

func (f *File) Text() ([]byte, string) {
	return f.Data, notText(f.Data)
}

const maxDiff = 1 << 20

// attrs returns the owner, group, and mode with their defaults.
func attrs(owner, group yamlx.NameOrID, mode, defaultMode string) (string, string, uint32, error) {
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = "root"
	}
	if mode == "" {
		mode = defaultMode
	}
	n, err := strconv.ParseUint(mode, 8, 32)
	return string(owner), string(group), uint32(n), err
}

// ids returns the IDs of a user and a group that must exist.
func ids(owner, group string) (uid, gid uint32, err error) {
	uid, ok, err := lookupUser(owner)
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, fmt.Errorf("user %q does not exist", owner)
	}
	gid, ok, err = lookupGroup(group)
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, fmt.Errorf("group %q does not exist", group)
	}
	return uid, gid, nil
}

func (f *File) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	dir, missing, err := openParent(f.Path)
	if _, ok := errors.AsType[*noPathError](err); ok && f.Absent {
		return Result{Status: OK}, nil
	}
	if err != nil {
		return Result{}, err
	}
	defer dir.Close()
	name := path.Base(f.Path)
	fi, exists, err := lstat(dir, name, missing)
	if err != nil {
		return Result{}, err
	}
	if f.Absent {
		switch {
		case !exists:
			return Result{Status: OK}, nil
		case !fi.Mode().IsRegular():
			return Result{}, fmt.Errorf("%s is %s, not a file", f.Path, kind(fi))
		}
		if err := noFlags(dir, name, fi, f.Path); err != nil {
			return Result{}, err
		}
		return Result{Status: Change, Action: Remove}, nil
	}
	owner, group, mode, err := attrs(f.Owner, f.Group, f.Mode, "0644")
	if err != nil {
		return Result{}, err
	}
	switch {
	case !exists:
		changes := append(parentChanges(missing), attrLine(owner, group, mode)+userNote(owner, group))
		return Result{Status: Change, Action: Create, Changes: changes, Old: new("")}, nil
	case fi.Mode()&fs.ModeSymlink != 0:
		target, _ := dir.Readlink(name)
		changes := []string{"replace the symbolic link to " + target, attrLine(owner, group, mode) + userNote(owner, group)}
		return Result{Status: Change, Action: Modify, Changes: changes, Old: new("")}, nil
	case fi.IsDir():
		line, err := checkReplace(dir, name, f.Path, fi, f.Replace)
		if err != nil {
			return Result{}, err
		}
		changes := []string{line, attrLine(owner, group, mode) + userNote(owner, group)}
		return Result{Status: Change, Action: Modify, Changes: changes, Old: new("")}, nil
	case !fi.Mode().IsRegular():
		return Result{}, fmt.Errorf("%s is %s, not a file", f.Path, kind(fi))
	}
	r, err := openSame(dir, name, fi)
	if err != nil {
		return Result{}, err
	}
	defer r.Close()
	res := Result{Status: OK}
	sum, err := fileSHA(r)
	if err != nil {
		return Result{}, err
	}
	if sum != f.sum() {
		res.Status, res.Action = Change, Modify
		old, err := readHead(r)
		if err != nil {
			return Result{}, fmt.Errorf("read %s: %w", f.Path, err)
		}
		if res.OldReason = notText(old); res.OldReason == "" {
			res.Old = new(string(old))
		}
	}
	changes, err := attrChanges(fi, owner, group, mode)
	if err != nil {
		return Result{}, err
	}
	if len(changes) > 0 {
		res.Status, res.Action = Change, Modify
		res.Changes = append(res.Changes, changes...)
	}
	if res.Status == Change {
		if err := noFlags(dir, name, fi, f.Path); err != nil {
			return Result{}, err
		}
	}
	return res, nil
}

// attrChanges describes how the owner, group, and mode of fi differ from the
// wanted ones.
func attrChanges(fi fs.FileInfo, owner, group string, mode uint32) ([]string, error) {
	st := fi.Sys().(*syscall.Stat_t)
	ownerLine, err := ownerChange("owner", owner, st.Uid, lookupUser, userName)
	if err != nil {
		return nil, err
	}
	groupLine, err := ownerChange("group", group, st.Gid, lookupGroup, groupName)
	if err != nil {
		return nil, err
	}
	var changes []string
	for _, c := range []string{ownerLine, groupLine} {
		if c != "" {
			changes = append(changes, c)
		}
	}
	if cur := uint32(st.Mode) & 0o7777; cur != mode {
		changes = append(changes, fmt.Sprintf("mode %04o → %04o", cur, mode))
	}
	return changes, nil
}

func (f *File) Apply(ctx context.Context, _ func(string)) error {
	name := path.Base(f.Path)
	if f.Absent {
		dir, err := openDir(f.Path)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Remove(name)
	}
	owner, group, mode, err := attrs(f.Owner, f.Group, f.Mode, "0644")
	if err != nil {
		return err
	}
	uid, gid, err := ids(owner, group)
	if err != nil {
		return err
	}
	dir, missing, err := openParent(f.Path)
	if err != nil {
		return err
	}
	defer dir.Close()
	fi, exists, err := lstat(dir, name, missing)
	if err != nil {
		return err
	}
	if exists && fi.Mode().IsRegular() {
		r, err := openSame(dir, name, fi)
		if err != nil {
			return err
		}
		defer r.Close()
		sum, err := fileSHA(r)
		if err != nil {
			return err
		}
		if sum == f.sum() {
			return setAttrs(r, uid, gid, mode)
		}
	}
	if f.Data == nil {
		return ErrNeedContent
	}
	if exists && fi.IsDir() {
		if err := noMount(dir, name, fi, f.Path); err != nil {
			return err
		}
	}
	sub, err := mkdirs(dir, missing)
	if err != nil {
		return err
	}
	defer sub.Close()
	return writeFile(sub, name, f.Data, uid, gid, mode, func(tmp string) error {
		return put(ctx, dir, missing, sub, tmp, name, f.Validation)
	})
}

func (f *File) sum() string {
	if f.Data != nil {
		return sha(f.Data)
	}
	return f.DataSHA256
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func fileSHA(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readHead reads r from the start, up to one byte more than a diff takes.
func readHead(r io.ReadSeeker) ([]byte, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(r, maxDiff+1))
}

const tooLarge = "larger than 1 MiB"

// notText returns the reason the plan shows no diff of data, or "" for text.
func notText(data []byte) string {
	switch {
	case len(data) > maxDiff:
		return tooLarge
	case bytes.IndexByte(data, 0) >= 0:
		return "binary"
	case !utf8.Valid(data):
		return "not UTF-8"
	}
	return ""
}

func kind(fi fs.FileInfo) string {
	switch m := fi.Mode(); {
	case m.IsDir():
		return "a directory"
	case m&fs.ModeSymlink != 0:
		return "a symbolic link"
	case m.IsRegular():
		return "a file"
	case m&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeCharDevice != 0:
		return "a character device"
	case m&fs.ModeDevice != 0:
		return "a block device"
	}
	return "a special file"
}

// noPathError is a parent of a path that is not a directory or a link to a
// missing target, so the path cannot exist. Kind is the kind of the last part,
// when that part exists and is not a directory.
type noPathError struct{ msg, kind string }

func (e *noPathError) Error() string { return e.msg }

var errLinkLevels = errors.New("too many levels of symbolic links")

// openParent opens the parent directory of p. When parents are missing, it
// opens the deepest one that exists and also returns the missing ones, from
// the top.
func openParent(p string) (*os.Root, []string, error) {
	return openPath(path.Dir(p), p)
}

// openPath opens the directory d for the step on path p, as openParent does.
// It follows a symbolic link only in a directory that only root can write.
// Each part opens relative to the directory before it, so a user cannot swap
// in a link while the helper works.
func openPath(d, p string) (*os.Root, []string, error) {
	dir, err := os.OpenRoot("/")
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*os.Root, []string, error) {
		dir.Close()
		return nil, nil, err
	}
	todo := parts(d)
	// The last tail parts of todo come from p, the others from link targets.
	tail := len(todo)
	link := ""
	for links := 0; len(todo) > 0; {
		name, full := todo[0], path.Join(dir.Name(), todo[0])
		switch name {
		case "", ".":
			todo = todo[1:]
			continue
		case "..":
			todo = append(parts(path.Dir(dir.Name())), todo[1:]...)
			next, err := os.OpenRoot("/")
			if err != nil {
				return fail(err)
			}
			dir.Close()
			dir = next
			continue
		}
		fi, err := dir.Lstat(name)
		switch {
		case errors.Is(err, fs.ErrNotExist) && len(todo) > tail:
			return fail(&noPathError{msg: link + " is a symbolic link to a missing target"})
		case errors.Is(err, fs.ErrNotExist):
			missing := make([]string, len(todo))
			for i := len(missing) - 1; i >= 0; i-- {
				missing[i], d = d, path.Dir(d)
			}
			return dir, missing, nil
		case err != nil:
			return fail(err)
		case fi.Mode()&fs.ModeSymlink != 0:
			safe, err := onlyRoot(dir)
			if err != nil {
				return fail(err)
			}
			if !safe {
				return fail(fmt.Errorf("%s is a symbolic link in %s, which a user other than root can write", full, dir.Name()))
			}
			if links++; links > 40 {
				return fail(fmt.Errorf("%s: %w", p, errLinkLevels))
			}
			target, err := dir.Readlink(name)
			if err != nil {
				return fail(err)
			}
			tail = min(tail, len(todo)-1)
			todo = append(strings.Split(target, "/"), todo[1:]...)
			link = full
			if path.IsAbs(target) {
				next, err := os.OpenRoot("/")
				if err != nil {
					return fail(err)
				}
				dir.Close()
				dir = next
			}
		case !fi.IsDir():
			e := &noPathError{msg: fmt.Sprintf("%s is %s, not a directory", full, kind(fi))}
			if !slices.ContainsFunc(todo[1:], func(s string) bool { return s != "" && s != "." }) {
				e.kind = kind(fi)
			}
			return fail(e)
		default:
			next, err := openRoot(dir, name, fi)
			if err != nil {
				return fail(err)
			}
			dir.Close()
			dir = next
			todo = todo[1:]
		}
	}
	return dir, nil, nil
}

func parts(p string) []string {
	if p == "/" {
		return nil
	}
	return strings.Split(p[1:], "/")
}

// onlyRoot reports whether no user other than root owns or can write dir.
func onlyRoot(dir *os.Root) (bool, error) {
	fi, err := dir.Stat(".")
	if err != nil {
		return false, err
	}
	return fi.Sys().(*syscall.Stat_t).Uid == 0 && fi.Mode()&0o022 == 0, nil
}

// openDir opens the parent directory of p, which must exist.
func openDir(p string) (*os.Root, error) {
	dir, missing, err := openParent(p)
	if err == nil && len(missing) > 0 {
		dir.Close()
		return nil, fmt.Errorf("%s does not exist", missing[0])
	}
	return dir, err
}

// lstat reports that name does not exist when its parents are missing.
func lstat(dir *os.Root, name string, missing []string) (fs.FileInfo, bool, error) {
	if len(missing) > 0 {
		return nil, false, nil
	}
	fi, err := dir.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	return fi, err == nil, err
}

// mkdirs creates the missing directories below dir with the default owner and
// mode, and opens the last one.
func mkdirs(dir *os.Root, missing []string) (*os.Root, error) {
	cur, err := dir.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	for _, m := range missing {
		next, err := mkdir(cur, path.Base(m), 0, 0, 0o755)
		cur.Close()
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// mkdir creates the directory name in dir with the owner, group, and mode,
// and opens it.
func mkdir(dir *os.Root, name string, uid, gid, mode uint32) (*os.Root, error) {
	if err := dir.Mkdir(name, 0o700); err != nil {
		return nil, err
	}
	fi, err := dir.Lstat(name)
	if err != nil {
		return nil, err
	}
	sub, err := openRoot(dir, name, fi)
	if err != nil {
		return nil, err
	}
	if err := setRootAttrs(sub, uid, gid, mode); err != nil {
		sub.Close()
		return nil, err
	}
	return sub, nil
}

func setRootAttrs(r *os.Root, uid, gid, mode uint32) error {
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return setAttrs(f, uid, gid, mode)
}

// openSame opens name in dir and checks that it is still the file that fi
// describes. Root follows a link that a user swaps in after the Lstat.
func openSame(dir *os.Root, name string, fi fs.FileInfo) (*os.File, error) {
	f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	got, err := f.Stat()
	if err == nil && !os.SameFile(fi, got) {
		err = fmt.Errorf("%s changed while winch worked on it", path.Join(dir.Name(), name))
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// openRoot opens the directory name in dir and checks that it is still the
// one that fi describes.
func openRoot(dir *os.Root, name string, fi fs.FileInfo) (*os.Root, error) {
	r, err := dir.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	got, err := r.Stat(".")
	if err == nil && !os.SameFile(fi, got) {
		err = fmt.Errorf("%s changed while winch worked on it", path.Join(dir.Name(), name))
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func setAttrs(f *os.File, uid, gid, mode uint32) error {
	if err := f.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	return f.Chmod(fileMode(mode))
}

func attrLine(owner, group string, mode uint32) string {
	return fmt.Sprintf("owner %s, group %s, mode %04o", owner, group, mode)
}

func parentChanges(missing []string) []string {
	var changes []string
	for _, d := range missing {
		changes = append(changes, ParentChange(d))
	}
	return changes
}

// ParentChange is the change of a step that creates the missing parent
// directory dir.
func ParentChange(dir string) string {
	return "create directory " + dir + " (" + attrLine("root", "root", 0o755) + ")"
}

// writeFile writes content to a temporary file in dir, and calls put to move
// it to name.
func writeFile(dir *os.Root, name string, content []byte, uid, gid, mode uint32, put func(tmp string) error) error {
	tmpName := ".winch-" + rand.Text()
	tmp, err := dir.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer dir.Remove(tmpName)
	_, err = tmp.Write(content)
	if err == nil {
		err = tmp.Chown(int(uid), int(gid))
	}
	if err == nil {
		err = tmp.Chmod(fileMode(mode))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return put(tmpName)
}

// fileMode converts a numeric mode such as 04755 to a Go file mode.
func fileMode(m uint32) fs.FileMode {
	out := fs.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		out |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		out |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		out |= fs.ModeSticky
	}
	return out
}

// lookupUser returns the ID of a user name, or the ID that a value of only
// digits gives.
func lookupUser(name string) (uint32, bool, error) {
	if id, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(id), true, nil
	}
	u, err := user.Lookup(name)
	if _, ok := errors.AsType[user.UnknownUserError](err); ok {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(id), true, err
}

func lookupGroup(name string) (uint32, bool, error) {
	if id, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(id), true, nil
	}
	g, err := user.LookupGroup(name)
	if _, ok := errors.AsType[user.UnknownGroupError](err); ok {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	id, err := strconv.ParseUint(g.Gid, 10, 32)
	return uint32(id), true, err
}

// ownerChange describes a change of owner or group, or returns "".
func ownerChange(what, want string, cur uint32, lookup func(string) (uint32, bool, error), name func(uint32) string) (string, error) {
	id, ok, err := lookup(want)
	if err != nil {
		return "", err
	}
	if ok && id == cur {
		return "", nil
	}
	line := fmt.Sprintf("%s %s → %s", what, name(cur), want)
	if !ok {
		line += " (does not exist yet)"
	}
	return line, nil
}

func userName(id uint32) string {
	s := strconv.FormatUint(uint64(id), 10)
	if u, err := user.LookupId(s); err == nil {
		return u.Username
	}
	return s
}

func groupName(id uint32) string {
	s := strconv.FormatUint(uint64(id), 10)
	if g, err := user.LookupGroupId(s); err == nil {
		return g.Name
	}
	return s
}

// userNote marks an owner or group that does not exist yet. An earlier step
// can create it.
func userNote(owner, group string) string {
	note := ""
	if _, ok, err := lookupUser(owner); err == nil && !ok {
		note += fmt.Sprintf("; user %q does not exist yet", owner)
	}
	if _, ok, err := lookupGroup(group); err == nil && !ok {
		note += fmt.Sprintf("; group %q does not exist yet", group)
	}
	return note
}
