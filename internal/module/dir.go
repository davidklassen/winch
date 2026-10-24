package module

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

type Dir struct {
	Path   string `yaml:"path,required" json:"path"`
	Owner  string `yaml:"owner" json:"owner,omitempty"`
	Group  string `yaml:"group" json:"group,omitempty"`
	Mode   string `yaml:"mode" json:"mode,omitempty"`
	Absent bool   `yaml:"absent" json:"absent,omitempty"`
}

func (d *Dir) Main() string { return d.Path }

func (d *Dir) Validate() error {
	if err := checkPath(d.Path); err != nil {
		return err
	}
	if d.Absent {
		return absentTakesNone(arg{"owner", d.Owner != ""}, arg{"group", d.Group != ""}, arg{"mode", d.Mode != ""})
	}
	if err := checkNames(d.Owner, d.Group); err != nil {
		return err
	}
	return checkMode(d.Mode, "0755")
}

func (d *Dir) Check(ctx context.Context, _ *State) (Result, error) {
	fi, err := os.Lstat(d.Path)
	if errors.Is(err, syscall.ENOTDIR) {
		if d.Absent {
			return Result{Status: OK}, nil
		}
		_, err = missingParents(d.Path)
		return Result{}, err
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, err
	}
	exists := err == nil
	if exists && !fi.IsDir() {
		return Result{}, fmt.Errorf("%s is %s, not a directory", d.Path, kind(fi))
	}
	if d.Absent {
		if !exists {
			return Result{Status: OK}, nil
		}
		res := Result{Status: Change, Action: Remove}
		empty, err := isEmpty(d.Path)
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
		changes, err := parentChanges(d.Path)
		if err != nil {
			return Result{}, err
		}
		changes = append(changes, attrLine(owner, group, mode)+userNote(owner, group))
		return Result{Status: Change, Action: Create, Changes: changes}, nil
	}
	changes, err := attrChanges(fi, owner, group, mode)
	if err != nil || len(changes) == 0 {
		return Result{Status: OK}, err
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (d *Dir) Apply(ctx context.Context) error {
	if d.Absent {
		return os.RemoveAll(d.Path)
	}
	owner, group, mode, err := attrs(d.Owner, d.Group, d.Mode, "0755")
	if err != nil {
		return err
	}
	uid, gid, err := ids(owner, group)
	if err != nil {
		return err
	}
	if err := mkParents(d.Path); err != nil {
		return err
	}
	if err := os.Mkdir(d.Path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return setAttrs(d.Path, uid, gid, mode)
}

func isEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
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
