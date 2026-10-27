package module

import (
	"fmt"
	"io/fs"
	"os"
	"path"
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
	return "remove directory " + p + ": " + t.counts(), nil
}

func (t tree) counts() string {
	return count(t.files, "file", "files") + ", " + count(t.dirs, "directory", "directories")
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
	t, err := walkTree(dir, name, p, fi)
	if err != nil {
		return "", err
	}
	return t.check(p, replace)
}

// walkTree counts the file or directory fi at name in dir with its content.
// It fails on a mount point or a flag that stops the removal. p is the path
// of name in the step.
func walkTree(dir *os.Root, name, p string, fi fs.FileInfo) (tree, error) {
	if err := noMount(dir, name, fi, p); err != nil {
		return tree{}, err
	}
	if err := noFlags(dir, name, fi, p); err != nil || !fi.IsDir() {
		return tree{}, err
	}
	return countEntries(dir, name, fi, p, -1, -1)
}

// countEntries counts the entries that walkOwners visits, and fails on a
// flag that stops a change of one.
func countEntries(dir *os.Root, name string, fi fs.FileInfo, p string, uid, gid int64) (tree, error) {
	t := tree{dir: true}
	err := walkOwners(dir, name, fi, uid, gid, func(sub *os.Root, name, rel string, info fs.FileInfo) error {
		if info.IsDir() {
			t.dirs++
		} else {
			t.files++
		}
		return noFlags(sub, name, info, path.Join(p, rel))
	})
	return t, err
}

// noFlags fails when the file or directory fi at name in dir has the immutable
// or append-only flag. Apply cannot change or remove it.
func noFlags(dir *os.Root, name string, fi fs.FileInfo, p string) error {
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return nil
	}
	f, err := openSame(dir, name, fi)
	if err != nil {
		return err
	}
	defer f.Close()
	flags, err := inodeFlags(f)
	switch {
	case err != nil:
		return fmt.Errorf("read the flags of %s: %w", p, err)
	case flags&fsImmutableFl != 0:
		return fmt.Errorf("%s is immutable; chattr -i changes it", p)
	case flags&fsAppendFl != 0:
		return fmt.Errorf("%s is append-only; chattr -a changes it", p)
	}
	return nil
}

// The inode flags of chattr +a and +i.
const (
	fsImmutableFl = 0x10
	fsAppendFl    = 0x20
)
