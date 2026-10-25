package module

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Dir struct {
	Path   string         `yaml:"path,required" json:"path"`
	Owner  yamlx.NameOrID `yaml:"owner" json:"owner,omitempty"`
	Group  yamlx.NameOrID `yaml:"group" json:"group,omitempty"`
	Mode   string         `yaml:"mode" json:"mode,omitempty"`
	Absent bool           `yaml:"absent" json:"absent,omitempty"`
}

func (d *Dir) Main() string { return d.Path }

func (d *Dir) Validate() error {
	if err := checkPath(d.Path); err != nil {
		return err
	}
	if d.Absent {
		return absentTakesNone(arg{"owner", d.Owner != ""}, arg{"group", d.Group != ""}, arg{"mode", d.Mode != ""})
	}
	if err := checkID("owner", d.Owner); err != nil {
		return err
	}
	if err := checkID("group", d.Group); err != nil {
		return err
	}
	return checkMode(d.Mode, "0755")
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
	if exists && !fi.IsDir() {
		return Result{}, fmt.Errorf("%s is %s, not a directory", d.Path, kind(fi))
	}
	if d.Absent {
		if !exists {
			return Result{Status: OK}, nil
		}
		if err := noMount(dir, name, fi, d.Path); err != nil {
			return Result{}, err
		}
		res := Result{Status: Change, Action: Remove}
		empty, err := isEmpty(dir, name, fi)
		if err != nil {
			return Result{}, err
		}
		if !empty {
			res.Changes = []string{"remove its content"}
		}
		return res, nil
	}
	owner, group, mode, err := attrs(d.Owner, d.Group, d.Mode, "0755")
	if err != nil {
		return Result{}, err
	}
	if !exists {
		changes := append(parentChanges(missing), attrLine(owner, group, mode)+userNote(owner, group))
		return Result{Status: Change, Action: Create, Changes: changes}, nil
	}
	changes, err := attrChanges(fi, owner, group, mode)
	if err != nil || len(changes) == 0 {
		return Result{Status: OK}, err
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
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
	if err := sub.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	fi, err := sub.Lstat(name)
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
	return setAttrs(f, uid, gid, mode)
}

func isEmpty(dir *os.Root, name string, fi fs.FileInfo) (bool, error) {
	f, err := openSame(dir, name, fi)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, err
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
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		return err
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	for line := range strings.Lines(string(data)) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mp := mountEscapes.Replace(fields[4])
		if mp == target || strings.HasPrefix(mp, target+"/") {
			return fmt.Errorf("%s is a mount point", p+mp[len(target):])
		}
	}
	return nil
}

var mountEscapes = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
