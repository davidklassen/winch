package module

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"unicode"

	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Link struct {
	Path       string  `yaml:"path,required" json:"path" line:"absolute" doc:"Absolute. The step creates missing parent directories, owned by root with mode 0755."`
	Target     *string `yaml:"target" json:"target,omitempty" line:"relative or absolute; need not exist" doc:"Relative or absolute; need not exist."`
	Validation *string `yaml:"validate" json:"validate,omitempty" line:"check command, as for file" doc:"Check command, as for file."`
	Absent     bool    `yaml:"absent" json:"absent,omitempty" doc:"Remove the link. A path of another kind fails the check."`
	Replace    bool    `yaml:"replace" json:"replace,omitempty" line:"remove another kind of thing at path first" doc:"Remove another kind of thing at path first, such as a file or a directory. Without it, such a thing fails the check."`
}

func (l *Link) Main() string { return l.Path }

func (l *Link) ValidateCommand() string {
	if l.Validation == nil {
		return ""
	}
	return *l.Validation
}

func (l *Link) Validate() error {
	if err := checkPath(l.Path); err != nil {
		return err
	}
	switch {
	case l.Absent:
		return absentTakesNone(arg{"target", l.Target != nil}, arg{"validate", l.Validation != nil}, arg{"replace", l.Replace})
	case l.Target == nil:
		return &yamlx.FieldError{Field: "target", Msg: "a link needs a target, or absent: true"}
	case *l.Target == "":
		return &yamlx.FieldError{Field: "target", Msg: "must not be empty"}
	case strings.ContainsFunc(*l.Target, unicode.IsControl):
		return &yamlx.FieldError{Field: "target", Msg: "has a control character"}
	case dotDotAfterPart(*l.Target):
		return &yamlx.FieldError{Field: "target", Msg: `".." after another part is not allowed; write the target without it`}
	case path.Clean(*l.Target) != *l.Target:
		return &yamlx.FieldError{Field: "target", Msg: fmt.Sprintf("must be a clean path, such as %q", path.Clean(*l.Target))}
	}
	return checkCommand("validate", l.Validation)
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

func (l *Link) Check(ctx context.Context, _ *State, _ Say) (Result, error) {
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
		if l.Absent || !fi.IsDir() && !fi.Mode().IsRegular() {
			return Result{}, fmt.Errorf("%s is %s, not a symbolic link", l.Path, kind(fi))
		}
		line, err := checkReplace(dir, name, l.Path, fi, l.Replace)
		if err != nil {
			return Result{}, err
		}
		return Result{Status: Change, Action: Modify, Changes: []string{line, "target " + *l.Target}, Validates: l.Validation != nil}, nil
	}
	switch {
	case l.Absent && !exists:
		return Result{Status: OK}, nil
	case l.Absent:
		return Result{Status: Change, Action: Remove}, nil
	case !exists:
		return Result{Status: Change, Action: Create, Changes: append(parentChanges(missing), "target "+*l.Target), Validates: l.Validation != nil}, nil
	}
	cur, err := dir.Readlink(name)
	if err != nil {
		return Result{}, err
	}
	if cur == *l.Target {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: []string{"target " + secret.Printable(cur) + " → " + *l.Target}, Validates: l.Validation != nil}, nil
}

func (l *Link) Apply(ctx context.Context, _ Say) error {
	name := path.Base(l.Path)
	if l.Absent {
		dir, err := openDir(l.Path)
		if err != nil {
			return err
		}
		defer dir.Close()
		return pathError("remove", l.Path, dir.Remove(name))
	}
	dir, missing, err := openParent(l.Path)
	if err != nil {
		return err
	}
	defer dir.Close()
	fi, exists, err := lstat(dir, name, missing)
	if err != nil {
		return err
	}
	if exists && fi.IsDir() {
		if err := noMount(dir, name, fi, l.Path); err != nil {
			return err
		}
	}
	sub, err := mkdirs(dir, missing)
	if err != nil {
		return err
	}
	defer sub.Close()
	// A new link replaces the old one in one rename.
	tmp := ".winch-" + rand.Text()
	if err := sub.Symlink(*l.Target, tmp); err != nil {
		return pathError("create link", l.Path, err)
	}
	defer sub.Remove(tmp)
	return pathError("create link", l.Path, put(ctx, dir, missing, sub, tmp, name, l.Validation))
}
