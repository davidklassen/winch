package module

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"syscall"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Link struct {
	Path   string  `yaml:"path,required" json:"path"`
	Target *string `yaml:"target" json:"target,omitempty"`
	Absent bool    `yaml:"absent" json:"absent,omitempty"`
}

func (l *Link) Main() string { return l.Path }

func (l *Link) Validate() error {
	if err := checkPath(l.Path); err != nil {
		return err
	}
	switch {
	case l.Absent:
		return absentTakesNone(arg{"target", l.Target != nil})
	case l.Target == nil:
		return &yamlx.FieldError{Field: "target", Msg: "a link needs a target, or absent: true"}
	case *l.Target == "":
		return &yamlx.FieldError{Field: "target", Msg: "must not be empty"}
	}
	return nil
}

func (l *Link) Check(ctx context.Context, _ *State) (Result, error) {
	fi, err := os.Lstat(l.Path)
	if errors.Is(err, syscall.ENOTDIR) {
		if l.Absent {
			return Result{Status: OK}, nil
		}
		_, err = missingParents(l.Path)
		return Result{}, err
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, err
	}
	exists := err == nil
	if exists && fi.Mode()&fs.ModeSymlink == 0 {
		return Result{}, fmt.Errorf("%s is %s, not a symbolic link", l.Path, kind(fi))
	}
	switch {
	case l.Absent && !exists:
		return Result{Status: OK}, nil
	case l.Absent:
		return Result{Status: Change, Action: Remove}, nil
	case !exists:
		changes, err := parentChanges(l.Path)
		if err != nil {
			return Result{}, err
		}
		return Result{Status: Change, Action: Create, Changes: append(changes, "target "+*l.Target)}, nil
	}
	cur, err := os.Readlink(l.Path)
	if err != nil {
		return Result{}, err
	}
	if cur == *l.Target {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: []string{"target " + cur + " → " + *l.Target}}, nil
}

func (l *Link) Apply(ctx context.Context) error {
	if l.Absent {
		return os.Remove(l.Path)
	}
	if err := mkParents(l.Path); err != nil {
		return err
	}
	// A new link replaces the old one in one rename.
	tmp := path.Join(path.Dir(l.Path), ".winch-"+rand.Text())
	if err := os.Symlink(*l.Target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, l.Path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
