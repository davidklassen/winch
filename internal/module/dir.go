package module

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Dir struct {
	Path         string         `yaml:"path,required" json:"path" doc:"The absolute path of the directory. The step follows a symbolic link to a directory."`
	Owner        yamlx.NameOrID `yaml:"owner" json:"owner,omitempty" doc:"The owner of the directory, a user name or a numeric ID." default:"root"`
	Group        yamlx.NameOrID `yaml:"group" json:"group,omitempty" doc:"The group of the directory, a group name or a numeric ID." default:"root"`
	Mode         string         `yaml:"mode" json:"mode,omitempty" doc:"The mode of the directory, in octal, such as 0750. Quote it, or YAML reads it as a number." default:"0755"`
	ModePos      yamlx.Pos      `json:"-"`
	Recurse      bool           `yaml:"recurse" json:"recurse,omitempty" doc:"Set owner and group on every entry of the tree. The mode stays the mode of the directory alone."`
	Absent       bool           `yaml:"absent" json:"absent,omitempty" doc:"Remove the directory with its content."`
	Replace      bool           `yaml:"replace" json:"replace,omitempty" doc:"Remove another kind of thing at path first, such as a file or a link."`
	Purge        bool           `yaml:"purge" json:"purge,omitempty" doc:"Remove each direct entry that no package owns and no step for the host writes."`
	KeepPatterns []string       `yaml:"keep" json:"keep_patterns,omitempty" doc:"Glob patterns of names that purge keeps, such as *.db. Needs purge."`
	// Keep are the paths below Path that steps for the host write. The
	// controller sets them.
	Keep []string `json:"keep,omitempty"`

	// removed are the paths that purge removes. Check sets them.
	removed []string
}

func (d *Dir) Main() string { return d.Path }

func (d *Dir) Validate() error {
	if err := checkPath(d.Path); err != nil {
		return err
	}
	if d.Absent {
		return absentTakesNone(arg{"owner", d.Owner != ""}, arg{"group", d.Group != ""}, arg{"mode", d.Mode != ""}, arg{"recurse", d.Recurse}, arg{"replace", d.Replace}, arg{"purge", d.Purge}, arg{"keep", d.KeepPatterns != nil})
	}
	if d.KeepPatterns != nil && !d.Purge {
		return &yamlx.FieldError{Field: "keep", Msg: "keep needs purge: true"}
	}
	for _, pattern := range d.KeepPatterns {
		if pattern == "" {
			return &yamlx.FieldError{Field: "keep", Msg: "a pattern must not be empty"}
		}
		if strings.Contains(pattern, "/") {
			return &yamlx.FieldError{Field: "keep", Msg: fmt.Sprintf("pattern %q has a /; keep matches names in the directory", pattern)}
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return &yamlx.FieldError{Field: "keep", Msg: fmt.Sprintf("invalid glob pattern %q: %s", pattern, err)}
		}
	}
	if err := checkOwner("owner", d.Owner); err != nil {
		return err
	}
	if err := checkOwner("group", d.Group); err != nil {
		return err
	}
	return checkMode(d.Mode, "0755")
}

// ModeWarning returns a warning for a mode with a read bit and no execute
// bit in the same class, or "".
func (d *Dir) ModeWarning() string {
	m, err := strconv.ParseUint(d.Mode, 8, 32)
	if err != nil {
		return ""
	}
	fixed := m
	var classes []string
	for i, class := range []string{"owner", "group", "others"} {
		shift := 6 - 3*i
		if m&(4<<shift) != 0 && m&(1<<shift) == 0 {
			classes = append(classes, class)
			fixed |= 1 << shift
		}
	}
	var who string
	switch len(classes) {
	case 0:
		return ""
	case 1:
		who = classes[0]
	case 2:
		who = classes[0] + " and " + classes[1]
	case 3:
		who = "owner, group, and others"
	}
	return fmt.Sprintf("%s can read the directory but not enter it; use \"%04o\"", who, fixed)
}

func (d *Dir) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	dir, missing, err := openParent(d.Path)
	if _, ok := errors.AsType[*noPathError](err); ok && d.Absent {
		return Result{Status: OK}, nil
	}
	if err != nil {
		return Result{}, err
	}
	defer dir.Close()
	name := path.Base(d.Path)
	fi, exists, err := lstat(dir, name, missing)
	if err != nil {
		return Result{}, err
	}
	if d.Absent {
		if !exists {
			return Result{Status: OK}, nil
		}
		if !fi.IsDir() {
			return Result{}, fmt.Errorf("%s is %s, not a directory", d.Path, kind(fi))
		}
		t, err := walkTree(dir, name, d.Path, fi)
		if err != nil {
			return Result{}, err
		}
		return Result{Status: Change, Action: Remove, Changes: []string{"remove its content: " + t.counts()}}, nil
	}
	owner, group, mode, err := attrs(d.Owner, d.Group, d.Mode, "0755")
	if err != nil {
		return Result{}, err
	}
	want := attrLine(owner, group, mode) + userNote(owner, group)
	link := ""
	at, atName := dir, name
	if exists && fi.Mode()&fs.ModeSymlink != 0 && !d.Replace {
		if link, err = dir.Readlink(name); err != nil {
			return Result{}, err
		}
		behind, err := openLinked(d.Path)
		if err != nil {
			return Result{}, err
		}
		defer behind.Close()
		if fi, err = behind.Stat("."); err != nil {
			return Result{}, err
		}
		at, atName = behind, "."
	}
	switch {
	case !exists:
		return Result{Status: Change, Action: Create, Changes: append(parentChanges(missing), want)}, nil
	case fi.Mode()&fs.ModeSymlink != 0:
		target, _ := dir.Readlink(name)
		return Result{Status: Change, Action: Modify, Changes: []string{"replace the symbolic link to " + target, want}}, nil
	case fi.Mode().IsRegular():
		line, err := checkReplace(dir, name, d.Path, fi, d.Replace)
		if err != nil {
			return Result{}, err
		}
		return Result{Status: Change, Action: Modify, Changes: []string{line, want}}, nil
	case !fi.IsDir():
		return Result{}, fmt.Errorf("%s is %s, not a directory", d.Path, kind(fi))
	}
	changes, err := attrChanges(fi, owner, group, mode)
	if err != nil {
		return Result{}, err
	}
	if len(changes) > 0 {
		if err := noFlags(at, atName, fi, d.Path); err != nil {
			return Result{}, err
		}
	}
	if d.Purge {
		r, err := openRoot(at, atName, fi)
		if err != nil {
			return Result{}, err
		}
		rs, err := d.removals(r)
		r.Close()
		if err != nil {
			return Result{}, err
		}
		if len(rs) > 0 {
			if err := noFlags(at, atName, fi, d.Path); err != nil {
				return Result{}, err
			}
		}
		for _, rm := range rs {
			changes = append(changes, rm.line)
			d.removed = append(d.removed, path.Join(d.Path, rm.name))
		}
	}
	if d.Recurse {
		uid, gid, err := wantIDs(owner, group)
		if err != nil {
			return Result{}, err
		}
		t, err := countEntries(at, atName, fi, d.Path, uid, gid)
		if err != nil {
			return Result{}, err
		}
		if t.files+t.dirs > 0 {
			changes = append(changes, "owner and group of its content: "+t.counts())
		}
	}
	if len(changes) == 0 {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes, Link: link}, nil
}

// wantIDs returns the IDs of owner and group, or -1 for one that does not
// exist yet: every entry differs from it.
func wantIDs(owner, group string) (int64, int64, error) {
	uid, gid := int64(-1), int64(-1)
	u, ok, err := lookupUser(owner)
	if err != nil {
		return 0, 0, err
	}
	if ok {
		uid = int64(u)
	}
	g, ok, err := lookupGroup(group)
	if err != nil {
		return 0, 0, err
	}
	if ok {
		gid = int64(g)
	}
	return uid, gid, nil
}

// walkOwners calls fn for each entry in the directory fi at name in dir, at
// any depth, whose owner or group is not uid or gid. fn gets the directory of
// the entry, its name there, and its path below the walked directory. The
// walk opens each directory by one name and checks that it is the one it
// listed, so it never follows a symbolic link. It skips a mount point with
// its content, and an entry that goes away.
func walkOwners(dir *os.Root, name string, fi fs.FileInfo, uid, gid int64, fn func(sub *os.Root, name, rel string, info fs.FileInfo) error) error {
	top, err := openRoot(dir, name, fi)
	if err != nil {
		return err
	}
	defer top.Close()
	f, err := top.Open(".")
	if err != nil {
		return err
	}
	target, mounts, err := mountsAt(f)
	f.Close()
	if err != nil {
		return err
	}
	skip := map[string]bool{}
	for _, mp := range mounts {
		skip[strings.TrimPrefix(mp, target+"/")] = true
	}
	var walk func(sub *os.Root, prefix string) error
	walk = func(sub *os.Root, prefix string) error {
		d, err := sub.Open(".")
		if err != nil {
			return err
		}
		names, err := d.Readdirnames(-1)
		d.Close()
		if err != nil {
			return err
		}
		slices.Sort(names)
		for _, n := range names {
			rel := path.Join(prefix, n)
			if skip[rel] {
				continue
			}
			info, err := sub.Lstat(n)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			st := info.Sys().(*syscall.Stat_t)
			if int64(st.Uid) != uid || int64(st.Gid) != gid {
				if err := fn(sub, n, rel, info); err != nil {
					return err
				}
			}
			if !info.IsDir() {
				continue
			}
			next, err := openRoot(sub, n, info)
			if err != nil {
				return err
			}
			err = walk(next, rel)
			next.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	return walk(top, "")
}

// chownContent sets the owner and group of every entry in the directory fi at
// name in dir when the step recurses.
func (d *Dir) chownContent(dir *os.Root, name string, fi fs.FileInfo, uid, gid uint32) error {
	if !d.Recurse {
		return nil
	}
	return walkOwners(dir, name, fi, int64(uid), int64(gid), func(sub *os.Root, name, _ string, _ fs.FileInfo) error {
		return sub.Lchown(name, int(uid), int(gid))
	})
}

func (d *Dir) Apply(ctx context.Context, _ func(string)) error {
	name := path.Base(d.Path)
	if d.Absent {
		dir, err := openDir(d.Path)
		if err != nil {
			return err
		}
		defer dir.Close()
		fi, exists, err := lstat(dir, name, nil)
		if err != nil || !exists {
			return err
		}
		if err := noMount(dir, name, fi, d.Path); err != nil {
			return err
		}
		return dir.RemoveAll(name)
	}
	owner, group, mode, err := attrs(d.Owner, d.Group, d.Mode, "0755")
	if err != nil {
		return err
	}
	uid, gid, err := ids(owner, group)
	if err != nil {
		return err
	}
	dir, missing, err := openParent(d.Path)
	if err != nil {
		return err
	}
	defer dir.Close()
	sub, err := mkdirs(dir, missing)
	if err != nil {
		return err
	}
	defer sub.Close()
	fi, exists, err := lstat(sub, name, nil)
	if err != nil {
		return err
	}
	switch {
	case !exists:
	case fi.Mode()&fs.ModeSymlink != 0 && !d.Replace:
		behind, err := openLinked(d.Path)
		if err != nil {
			return err
		}
		defer behind.Close()
		f, err := behind.Open(".")
		if err != nil {
			return err
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if err := setAttrs(f, uid, gid, mode); err != nil {
			return err
		}
		if d.Purge {
			if err := d.purge(behind); err != nil {
				return err
			}
		}
		return d.chownContent(behind, ".", fi, uid, gid)
	case d.Replace && (fi.Mode()&fs.ModeSymlink != 0 || fi.Mode().IsRegular()):
		if err := sub.Remove(name); err != nil {
			return err
		}
	}
	if err := sub.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	fi, err = sub.Lstat(name)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is %s, not a directory", d.Path, kind(fi))
	}
	f, err := openSame(sub, name, fi)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := setAttrs(f, uid, gid, mode); err != nil {
		return err
	}
	if d.Purge {
		r, err := openRoot(sub, name, fi)
		if err != nil {
			return err
		}
		err = d.purge(r)
		r.Close()
		if err != nil {
			return err
		}
	}
	return d.chownContent(sub, name, fi, uid, gid)
}

// openLinked opens the directory behind the symbolic link at p.
func openLinked(p string) (*os.Root, error) {
	dir, missing, err := openPath(p, p)
	if errors.Is(err, errLinkLevels) {
		return nil, fmt.Errorf("%s is a symbolic link with %w; add replace: true to remove it", p, errLinkLevels)
	}
	if e, ok := errors.AsType[*noPathError](err); ok {
		return nil, fmt.Errorf("%s is a symbolic link to %s; add replace: true to remove it", p, cmp.Or(e.kind, "a missing target"))
	}
	if err == nil && len(missing) > 0 {
		dir.Close()
		return nil, fmt.Errorf("%s does not exist", missing[0])
	}
	return dir, err
}

// noMount fails when name in dir, or anything below it, is a mount point.
// RemoveAll would remove the files on the mounted file system. p is the path
// of name in the step, which can differ from the real path behind links.
func noMount(dir *os.Root, name string, fi fs.FileInfo, p string) error {
	f, err := openSame(dir, name, fi)
	if err != nil {
		return err
	}
	defer f.Close()
	target, mounts, err := mountsAt(f)
	if err != nil || len(mounts) == 0 {
		return err
	}
	return fmt.Errorf("%s is a mount point", p+mounts[0][len(target):])
}

// mountsAt returns the real path of f and the mount points at it or below it.
func mountsAt(f *os.File) (string, []string, error) {
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", nil, err
	}
	var mounts []string
	for line := range strings.Lines(string(data)) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mp := mountEscapes.Replace(fields[4])
		if mp == target || strings.HasPrefix(mp, target+"/") {
			mounts = append(mounts, mp)
		}
	}
	return target, mounts, nil
}

var mountEscapes = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
