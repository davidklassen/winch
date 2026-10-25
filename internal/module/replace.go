package module

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// tree is a file, or a directory with its content, at the path of a step of
// another kind.
type tree struct {
	dir         bool
	files, dirs int
}

// check returns the plan line that removes t, or the error of a step without
// replace: true.
func (t tree) check(p string, replace bool) (string, error) {
	if !replace {
		return "", fmt.Errorf("%s is %s; add replace: true to remove it", p, t)
	}
	if !t.dir {
		return "remove file " + p, nil
	}
	return fmt.Sprintf("remove directory %s: %s, %s", p, count(t.files, "file", "files"), count(t.dirs, "directory", "directories")), nil
}

func (t tree) String() string {
	if !t.dir {
		return "a file"
	}
	var parts []string
	if t.files > 0 {
		parts = append(parts, count(t.files, "file", "files"))
	}
	if t.dirs > 0 {
		parts = append(parts, count(t.dirs, "directory", "directories"))
	}
	if len(parts) == 0 {
		return "an empty directory"
	}
	return "a directory with " + strings.Join(parts, " and ")
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// checkReplace checks the file or directory fi at name in dir, which a step
// of another kind replaces, and returns the plan line that removes it. p is
// the path of name in the step.
func checkReplace(dir *os.Root, name, p string, fi fs.FileInfo, replace bool) (string, error) {
	if err := noMount(dir, name, fi, p); err != nil {
		return "", err
	}
	t := tree{dir: fi.IsDir()}
	if t.dir {
		sub, err := openRoot(dir, name, fi)
		if err != nil {
			return "", err
		}
		defer sub.Close()
		err = fs.WalkDir(sub.FS(), ".", func(name string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case name == ".":
			case d.IsDir():
				t.dirs++
			default:
				t.files++
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	return t.check(p, replace)
}
