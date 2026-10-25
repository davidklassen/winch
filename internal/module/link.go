package module

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

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
	case dotDotAfterPart(*l.Target):
		return &yamlx.FieldError{Field: "target", Msg: `".." after another part is not allowed; write the target without it`}
	case path.Clean(*l.Target) != *l.Target:
		return &yamlx.FieldError{Field: "target", Msg: fmt.Sprintf("must be a clean path, such as %q", path.Clean(*l.Target))}
	}
	return nil
}

// dotDotAfterPart reports a ".." that follows a name. The host resolves
// "a/.." through "a", so when "a" is a link, the clean form names
// another place.
func dotDotAfterPart(target string) bool {
	named := false
	for part := range strings.SplitSeq(target, "/") {
		switch part {
		case "", ".":
		case "..":
			if named {
				return true
			}
		default:
			named = true
		}
	}
	return false
}

func (l *Link) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	dir, missing, err := openParent(l.Path)
	if _, ok := errors.AsType[*noPathError](err); ok && l.Absent {
		return Result{Status: OK}, nil
	}
	if err != nil {
		return Result{}, err
	}
	defer dir.Close()
	name := path.Base(l.Path)
	fi, exists, err := lstat(dir, name, missing)
	if err != nil {
		return Result{}, err
	}
	if exists && fi.Mode()&fs.ModeSymlink == 0 {
		return Result{}, fmt.Errorf("%s is %s, not a symbolic link", l.Path, kind(fi))
	}
	switch {
	case l.Absent && !exists:
		return Result{Status: OK}, nil
	case l.Absent:
		return Result{Status: Change, Action: Remove}, nil
	case !exists:
		return Result{Status: Change, Action: Create, Changes: append(parentChanges(missing), "target "+*l.Target)}, nil
	}
	cur, err := dir.Readlink(name)
	if err != nil {
		return Result{}, err
	}
	if cur == *l.Target {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: []string{"target " + cur + " → " + *l.Target}}, nil
}

func (l *Link) Apply(ctx context.Context, _ func(string)) error {
	name := path.Base(l.Path)
	if l.Absent {
		dir, err := openDir(l.Path)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Remove(name)
	}
	dir, missing, err := openParent(l.Path)
	if err != nil {
		return err
	}
	defer dir.Close()
	sub, err := mkdirs(dir, missing)
	if err != nil {
		return err
	}
	defer sub.Close()
	// A new link replaces the old one in one rename.
	tmp := ".winch-" + rand.Text()
	if err := sub.Symlink(*l.Target, tmp); err != nil {
		return err
	}
	if err := sub.Rename(tmp, name); err != nil {
		sub.Remove(tmp)
		return err
	}
	return nil
}
