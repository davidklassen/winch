package module

import (
	"bytes"
	"context"
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
	"syscall"
	"unicode/utf8"

	"github.com/davidklassen/winch/internal/yamlx"
)

type File struct {
	Path          string  `yaml:"path,required" json:"path"`
	Content       *string `yaml:"content" json:"content,omitempty"`
	ContentSHA256 string  `json:"content_sha256,omitempty"`
	Owner         string  `yaml:"owner" json:"owner,omitempty"`
	Group         string  `yaml:"group" json:"group,omitempty"`
	Mode          string  `yaml:"mode" json:"mode,omitempty"`
	Absent        bool    `yaml:"absent" json:"absent,omitempty"`
}

func (f *File) Main() string { return f.Path }

func (f *File) Validate() error {
	if err := checkPath(f.Path); err != nil {
		return err
	}
	if f.Absent {
		return absentTakesNone(arg{"content", f.Content != nil}, arg{"owner", f.Owner != ""}, arg{"group", f.Group != ""}, arg{"mode", f.Mode != ""})
	}
	if f.Content == nil {
		return &yamlx.FieldError{Field: "content", Msg: "a file needs content, or absent: true"}
	}
	return checkMode(f.Mode, "0644")
}

var modeRe = regexp.MustCompile(`^[0-7]{3,4}$`)

func checkMode(mode, example string) error {
	if mode != "" && !modeRe.MatchString(mode) {
		return &yamlx.FieldError{Field: "mode", Msg: fmt.Sprintf("must be an octal mode such as %q", example)}
	}
	return nil
}

func checkPath(p string) error {
	switch {
	case !path.IsAbs(p):
		return &yamlx.FieldError{Field: "path", Msg: "must be an absolute path"}
	case path.Clean(p) != p:
		return &yamlx.FieldError{Field: "path", Msg: fmt.Sprintf("must be a clean path, such as %q", path.Clean(p))}
	case p == "/":
		return &yamlx.FieldError{Field: "path", Msg: "must not be /"}
	}
	return nil
}

type arg struct {
	name string
	set  bool
}

func absentTakesNone(args ...arg) error {
	for _, a := range args {
		if a.set {
			return &yamlx.FieldError{Field: a.name, Msg: "absent: true takes no " + a.name}
		}
	}
	return nil
}

func (f *File) WithoutContent() Module {
	c := *f
	if f.Content != nil {
		c.ContentSHA256 = sha(*f.Content)
		c.Content = nil
	}
	return &c
}

func (f *File) Text() *string { return f.Content }

const maxDiff = 1 << 20

// attrs returns the owner, group, and mode with their defaults.
func attrs(owner, group, mode, defaultMode string) (string, string, uint32, error) {
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
	return owner, group, uint32(n), err
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

func (f *File) Check(ctx context.Context, _ *State) (Result, error) {
	fi, err := os.Lstat(f.Path)
	if errors.Is(err, syscall.ENOTDIR) {
		if f.Absent {
			return Result{Status: OK}, nil
		}
		_, err = missingParents(f.Path)
		return Result{}, err
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, err
	}
	exists := err == nil
	if f.Absent {
		switch {
		case !exists:
			return Result{Status: OK}, nil
		case !fi.Mode().IsRegular():
			return Result{}, fmt.Errorf("%s is %s, not a file", f.Path, kind(fi))
		}
		return Result{Status: Change, Action: Remove}, nil
	}
	owner, group, mode, err := attrs(f.Owner, f.Group, f.Mode, "0644")
	if err != nil {
		return Result{}, err
	}
	switch {
	case !exists:
		changes, err := parentChanges(f.Path)
		if err != nil {
			return Result{}, err
		}
		changes = append(changes, attrLine(owner, group, mode)+userNote(owner, group))
		return Result{Status: Change, Action: Create, Changes: changes, Old: new("")}, nil
	case fi.Mode()&fs.ModeSymlink != 0:
		target, _ := os.Readlink(f.Path)
		changes := []string{"replace the symbolic link to " + target, attrLine(owner, group, mode) + userNote(owner, group)}
		return Result{Status: Change, Action: Modify, Changes: changes, Old: new("")}, nil
	case !fi.Mode().IsRegular():
		return Result{}, fmt.Errorf("%s is %s, not a file", f.Path, kind(fi))
	}
	res := Result{Status: OK}
	sum, err := fileSHA(f.Path)
	if err != nil {
		return Result{}, err
	}
	if sum != f.sum() {
		res.Status, res.Action = Change, Modify
		if old, ok := readText(f.Path, fi.Size()); ok {
			res.Old = &old
		} else {
			res.Changes = append(res.Changes, "content (binary or larger than 1 MiB)")
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

func (f *File) Apply(ctx context.Context) error {
	if f.Absent {
		return os.Remove(f.Path)
	}
	owner, group, mode, err := attrs(f.Owner, f.Group, f.Mode, "0644")
	if err != nil {
		return err
	}
	uid, gid, err := ids(owner, group)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(f.Path)
	if err == nil && fi.Mode().IsRegular() {
		sum, err := fileSHA(f.Path)
		if err != nil {
			return err
		}
		if sum == f.sum() {
			return setAttrs(f.Path, uid, gid, mode)
		}
	}
	if f.Content == nil {
		return ErrNeedContent
	}
	if err := mkParents(f.Path); err != nil {
		return err
	}
	return writeFile(f.Path, *f.Content, uid, gid, mode)
}

func (f *File) sum() string {
	if f.Content != nil {
		return sha(*f.Content)
	}
	return f.ContentSHA256
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func fileSHA(path string) (string, error) {
	r, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readText(path string, size int64) (string, bool) {
	if size > maxDiff {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return "", false
	}
	return string(data), true
}

func kind(fi fs.FileInfo) string {
	switch m := fi.Mode(); {
	case m.IsDir():
		return "a directory"
	case m&fs.ModeSymlink != 0:
		return "a symbolic link"
	case m.IsRegular():
		return "a file"
	}
	return "a special file"
}

// missingParents returns the parent directories of path that do not exist,
// deepest first. A parent that is not a directory is an error.
func missingParents(p string) ([]string, error) {
	var out []string
	for dir := path.Dir(p); dir != "/"; dir = path.Dir(dir) {
		fi, err := os.Stat(dir)
		if err == nil {
			if !fi.IsDir() {
				return nil, fmt.Errorf("%s is %s, not a directory", dir, kind(fi))
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if _, err := os.Lstat(dir); err == nil {
			return nil, fmt.Errorf("%s is a symbolic link to a missing target", dir)
		}
		out = append(out, dir)
	}
	return out, nil
}

// mkParents creates the missing parents of p with the default owner and mode.
func mkParents(p string) error {
	parents, err := missingParents(p)
	if err != nil {
		return err
	}
	for _, d := range slices.Backward(parents) {
		if err := mkdir(d, 0, 0, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func mkdir(dir string, uid, gid, mode uint32) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	return setAttrs(dir, uid, gid, mode)
}

func setAttrs(p string, uid, gid, mode uint32) error {
	if err := os.Chown(p, int(uid), int(gid)); err != nil {
		return err
	}
	return os.Chmod(p, fileMode(mode))
}

func attrLine(owner, group string, mode uint32) string {
	return fmt.Sprintf("owner %s, group %s, mode %04o", owner, group, mode)
}

// parentChanges describes the missing parents of p in the order apply
// creates them.
func parentChanges(p string) ([]string, error) {
	parents, err := missingParents(p)
	if err != nil {
		return nil, err
	}
	var changes []string
	for _, d := range slices.Backward(parents) {
		changes = append(changes, "create directory "+d+" ("+attrLine("root", "root", 0o755)+")")
	}
	return changes, nil
}

func writeFile(p, content string, uid, gid, mode uint32) error {
	tmp, err := os.CreateTemp(path.Dir(p), ".winch-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(content)
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
	return os.Rename(tmp.Name(), p)
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

func lookupUser(name string) (uint32, bool, error) {
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
