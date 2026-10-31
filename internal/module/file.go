package module

import (
	"bytes"
	"cmp"
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
	Path        string    `yaml:"path,required" json:"path" line:"absolute" doc:"Absolute. The step creates missing parent directories, owned by root with mode 0755."`
	Content     *string   `yaml:"content" json:"-" line:"literal text" doc:"Literal text. A step without content, template, source, copy_from, or stock sets only the owner, group, and mode that it gives, with no defaults, of a file that exists. When that file is missing, the plan says does not exist yet. Apply fails when it is still missing."`
	Template    string    `yaml:"template" json:"-" line:"file in the recipe's templates/" doc:"File in the recipe's templates/ directory. Its output is the content."`
	TemplatePos yamlx.Pos `json:"-"`
	Source      string    `yaml:"source" json:"-" line:"file in the recipe's files/" doc:"File in the recipe's files/ directory. Its bytes are the content."`
	SourcePos   yamlx.Pos `json:"-"`
	CopyFrom    string    `yaml:"copy_from" json:"copy_from,omitempty" line:"file on the host" doc:"File on the host. Its bytes are the content, and its permission bits are the default mode. The default owner and group stay root: the owner of the source does not carry over."`
	Stock       bool      `yaml:"stock" json:"stock,omitempty" line:"content that the package ships" doc:"Content that the package ships for path, from the installed version. The package also gives the default owner, group, and mode."`
	// Data is the content for the host, from content, template, or source.
	// Without omitempty, JSON keeps nil apart from empty content.
	Data       []byte `json:"data"`
	DataSHA256 string `json:"data_sha256,omitempty"`
	// Listens are the lines of the content of sshd's config that set the
	// ports, for a step without its content.
	Listens    []string       `json:"listens,omitempty"`
	Owner      yamlx.NameOrID `yaml:"owner" json:"owner,omitempty" doc:"A user name or a numeric ID. A step without content has no default." default:"root"`
	Group      yamlx.NameOrID `yaml:"group" json:"group,omitempty" doc:"A group name or a numeric ID. A step without content has no default." default:"root"`
	Mode       string         `yaml:"mode" json:"mode,omitempty" line:"octal, in quotes" doc:"Octal, in quotes: \"0640\". Without quotes, YAML reads it as a number. With stock, the package gives the default. With copy_from, the source gives it. A step without content has no default." default:"0644"`
	Validation *string        `yaml:"validate" json:"validate,omitempty" line:"check command for the new file" doc:"Check command for the new file. The command names the real path, or checks the whole config: nginx -t. winch puts the new file in place and runs the command. When the command fails, the old file comes back and the step fails."`
	Absent     bool           `yaml:"absent" json:"absent,omitempty" doc:"Remove the file. A path of another kind fails the check."`
	Replace    bool           `yaml:"replace" json:"replace,omitempty" line:"remove another kind of thing at path first" doc:"Remove another kind of thing at path first, such as a directory. Without it, such a thing fails the check."`
}

func (f *File) Main() string { return f.Path }

func (f *File) ValidateCommand() string {
	if f.Validation == nil {
		return ""
	}
	return *f.Validation
}

func (f *File) Validate() error {
	if err := checkPath(f.Path); err != nil {
		return err
	}
	sources := []arg{{"content", f.Content != nil}, {"template", f.Template != ""}, {"source", f.Source != ""}, {"copy_from", f.CopyFrom != ""}, {"stock", f.Stock}}
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
			return &yamlx.FieldError{Field: a.name, Msg: "a file has only one of content, template, source, copy_from, and stock"}
		}
	}
	if set == 0 {
		if f.Owner == "" && f.Group == "" && f.Mode == "" {
			return &yamlx.FieldError{Field: "content", Msg: "a file needs content, template, source, copy_from, or stock, one of owner, group, and mode, or absent: true"}
		}
		if err := takesNone("a file without content", arg{"validate", f.Validation != nil}, arg{"replace", f.Replace}); err != nil {
			return err
		}
	}
	if err := CheckRelative("template", f.Template); err != nil {
		return err
	}
	if err := CheckRelative("source", f.Source); err != nil {
		return err
	}
	if f.CopyFrom != "" {
		if err := checkAbs("copy_from", f.CopyFrom); err != nil {
			return err
		}
		if f.CopyFrom == f.Path {
			return &yamlx.FieldError{Field: "copy_from", Msg: "is the path of the step itself"}
		}
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

func checkOwner(field string, v yamlx.NameOrID) error {
	if v == "" {
		return nil
	}
	if numberRe.MatchString(string(v)) {
		return checkID(field, yamlx.ID(v))
	}
	what := "user"
	if field == "group" {
		what = "group"
	}
	return checkAccountName(field, what, string(v))
}

var modeRe = regexp.MustCompile(`^[0-7]{3,4}$`)

func checkMode(mode, example string) error {
	if mode != "" && !modeRe.MatchString(mode) {
		return &yamlx.FieldError{Field: "mode", Msg: fmt.Sprintf("must be an octal mode such as %q", example)}
	}
	return nil
}

func CheckRelative(field, p string) error {
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
		if SSHDConfig(f.Path) {
			c.Listens = listens(string(f.Data))
		}
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
func ids(owner, group string) (uid, gid int, err error) {
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
	if !f.hasContent() {
		return f.checkAttrs(dir, name, fi, exists)
	}
	hc, err := f.hostContent(ctx)
	if err != nil {
		return Result{}, err
	}
	if hc != nil {
		defer hc.close()
	}
	owner, group, mode, known, err := f.wanted(hc)
	if err != nil {
		return Result{}, err
	}
	want := attrLine(owner, group, mode) + userNote(owner, group)
	// A source on the host shows no diff, only the line that names it.
	var content []string
	var srcSum string
	old := new("")
	if hc != nil {
		content, old, srcSum = []string{hc.line}, nil, hc.sum
		switch {
		case !known && f.CopyFrom != "":
			want = fmt.Sprintf("owner %s, group %s, mode from %s", owner, group, hc.from) + userNote(owner, group)
		case !known:
			want = "owner, group, and mode from " + hc.from
		}
	}
	switch {
	case !exists:
		changes := slices.Concat(parentChanges(missing), content, []string{want})
		return Result{Status: Change, Action: Create, Changes: changes, Old: old, SourceSHA256: srcSum, Validates: f.Validation != nil}, nil
	case fi.Mode()&fs.ModeSymlink != 0:
		target, _ := dir.Readlink(name)
		changes := slices.Concat([]string{"replace the symbolic link to " + target}, content, []string{want})
		return Result{Status: Change, Action: Modify, Changes: changes, Old: old, SourceSHA256: srcSum, Validates: f.Validation != nil}, nil
	case fi.IsDir():
		line, err := checkReplace(dir, name, f.Path, fi, f.Replace)
		if err != nil {
			return Result{}, err
		}
		changes := slices.Concat([]string{line}, content, []string{want})
		return Result{Status: Change, Action: Modify, Changes: changes, Old: old, SourceSHA256: srcSum, Validates: f.Validation != nil}, nil
	case !fi.Mode().IsRegular():
		return Result{}, fmt.Errorf("%s is %s, not a file", f.Path, kind(fi))
	}
	r, err := openSame(dir, name, fi)
	if err != nil {
		return Result{}, err
	}
	defer r.Close()
	res := Result{Status: OK, SourceSHA256: srcSum}
	sum, err := fileSHA(r)
	if err != nil {
		return Result{}, err
	}
	wantSum := f.sum()
	if hc != nil {
		wantSum = hc.sum
	}
	if sum != wantSum {
		res.Status, res.Action, res.Changes, res.Validates = Change, Modify, content, f.Validation != nil
		if hc == nil {
			old, err := readHead(r)
			if err != nil {
				return Result{}, fmt.Errorf("read %s: %w", f.Path, err)
			}
			if res.OldReason = notText(old); res.OldReason == "" {
				res.Old = new(string(old))
			}
		}
	}
	changes := []string{want}
	if known {
		if changes, err = attrChanges(fi, owner, group, mode); err != nil {
			return Result{}, err
		}
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

// hasContent reports whether the step on the host sets the content.
func (f *File) hasContent() bool {
	return f.Data != nil || f.DataSHA256 != "" || f.fromHost()
}

// fromHost reports whether the content comes from the host: copy_from or
// stock.
func (f *File) fromHost() bool {
	return f.CopyFrom != "" || f.Stock
}

// hostContent reads the source of copy_from or stock, or returns nil for
// content from the controller.
func (f *File) hostContent(ctx context.Context) (*hostContent, error) {
	switch {
	case f.Stock:
		return stockSource(ctx, f.Path)
	case f.CopyFrom != "":
		return copySource(f.CopyFrom)
	}
	return nil, nil
}

// wanted returns the owner, group, and mode with their defaults: those of hc
// when it is not nil, else root and 0644. known is false when a default comes
// from a source that does not exist yet.
func (f *File) wanted(hc *hostContent) (owner, group string, mode uint32, known bool, err error) {
	if hc == nil {
		owner, group, mode, err = attrs(f.Owner, f.Group, f.Mode, "0644")
		return owner, group, mode, true, err
	}
	known = hc.missing == nil || f.Mode != "" && (f.CopyFrom != "" || (f.Owner != "" && f.Group != ""))
	owner, group, mode, err = attrs(cmp.Or(f.Owner, yamlx.NameOrID(hc.owner)), cmp.Or(f.Group, yamlx.NameOrID(hc.group)), f.Mode, fmt.Sprintf("%04o", hc.mode))
	return owner, group, mode, known, err
}

// checkAttrs checks a step without content: only the owner, group, and mode
// it gives.
func (f *File) checkAttrs(dir *os.Root, name string, fi fs.FileInfo, exists bool) (Result, error) {
	switch {
	case !exists:
		return Result{Status: Change, Action: Modify, Changes: []string{f.Path + " does not exist yet"}}, nil
	case !fi.Mode().IsRegular():
		return Result{}, fmt.Errorf("%s is %s, not a file", f.Path, kind(fi))
	}
	owner, group, mode, err := f.attrsOr(fi)
	if err != nil {
		return Result{}, err
	}
	changes, err := attrChanges(fi, owner, group, mode)
	if err != nil || len(changes) == 0 {
		return Result{Status: OK}, err
	}
	if err := noFlags(dir, name, fi, f.Path); err != nil {
		return Result{}, err
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

// attrsOr returns the owner, group, and mode that the step gives, and those
// of fi for the ones it does not give.
func (f *File) attrsOr(fi fs.FileInfo) (string, string, uint32, error) {
	st := fi.Sys().(*syscall.Stat_t)
	owner := cmp.Or(string(f.Owner), strconv.FormatUint(uint64(st.Uid), 10))
	group := cmp.Or(string(f.Group), strconv.FormatUint(uint64(st.Gid), 10))
	if f.Mode == "" {
		return owner, group, uint32(st.Mode) & 0o7777, nil
	}
	n, err := strconv.ParseUint(f.Mode, 8, 32)
	return owner, group, uint32(n), err
}

func (f *File) applyAttrs(name string) error {
	dir, missing, err := openParent(f.Path)
	if err != nil {
		return err
	}
	defer dir.Close()
	fi, exists, err := lstat(dir, name, missing)
	switch {
	case err != nil:
		return err
	case !exists:
		return fmt.Errorf("%s does not exist; a file step without content does not create it", f.Path)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s is %s, not a file", f.Path, kind(fi))
	}
	r, err := openSame(dir, name, fi)
	if err != nil {
		return err
	}
	defer r.Close()
	owner, group, mode, err := f.attrsOr(fi)
	if err != nil {
		return err
	}
	uid, gid, err := ids(owner, group)
	if err != nil {
		return err
	}
	return setAttrs(r, uid, gid, mode)
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
	if !f.hasContent() {
		return f.applyAttrs(name)
	}
	hc, err := f.hostContent(ctx)
	if err != nil {
		return err
	}
	wantSum := f.sum()
	if hc != nil {
		defer hc.close()
		if hc.missing != nil {
			return hc.missing
		}
		wantSum = hc.sum
	}
	owner, group, mode, _, err := f.wanted(hc)
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
		if sum == wantSum {
			return setAttrs(r, uid, gid, mode)
		}
	}
	var content io.Reader
	switch {
	case hc != nil:
		if content, err = hc.reader(); err != nil {
			return err
		}
	case f.Data == nil:
		return ErrNeedContent
	default:
		content = bytes.NewReader(f.Data)
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
	return writeFile(sub, name, content, uid, gid, mode, func(tmp string) error {
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
			if err := linkAllowed(dir, name); err != nil {
				return fail(err)
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

// linkAllowed fails for the symbolic link name in dir when a user other than
// root owns or can write dir: winch does not follow it.
func linkAllowed(dir *os.Root, name string) error {
	safe, err := onlyRoot(dir)
	if err == nil && !safe {
		err = fmt.Errorf("%s is a symbolic link in %s, which a user other than root can write", path.Join(dir.Name(), name), dir.Name())
	}
	return err
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
func mkdir(dir *os.Root, name string, uid, gid int, mode uint32) (*os.Root, error) {
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

func setRootAttrs(r *os.Root, uid, gid int, mode uint32) error {
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

// setAttrs changes nothing when f is already right: the kernel refuses even
// such a change on an immutable or append-only file.
func setAttrs(f *os.File, uid, gid int, mode uint32) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) == uid && int(st.Gid) == gid && uint32(st.Mode)&0o7777 == mode {
		return nil
	}
	if err := f.Chown(uid, gid); err != nil {
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
func writeFile(dir *os.Root, name string, content io.Reader, uid, gid int, mode uint32, put func(tmp string) error) error {
	tmpName := ".winch-" + rand.Text()
	tmp, err := dir.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer dir.Remove(tmpName)
	_, err = io.Copy(tmp, content)
	if err == nil {
		err = tmp.Chown(uid, gid)
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
func lookupUser(name string) (int, bool, error) {
	if numberRe.MatchString(name) {
		id, err := parseID("UID", name, strconv.IntSize)
		return id, true, err
	}
	u, err := user.Lookup(name)
	if _, ok := errors.AsType[user.UnknownUserError](err); ok {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	id, err := parseID("UID", u.Uid, strconv.IntSize)
	return id, true, err
}

func lookupGroup(name string) (int, bool, error) {
	if numberRe.MatchString(name) {
		id, err := parseID("GID", name, strconv.IntSize)
		return id, true, err
	}
	g, err := user.LookupGroup(name)
	if _, ok := errors.AsType[user.UnknownGroupError](err); ok {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	id, err := parseID("GID", g.Gid, strconv.IntSize)
	return id, true, err
}

// ownerChange describes a change of owner or group, or returns "".
func ownerChange(what, want string, cur uint32, lookup func(string) (int, bool, error), name func(uint32) string) (string, error) {
	id, ok, err := lookup(want)
	if err != nil {
		return "", err
	}
	if ok && id == int(cur) {
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
