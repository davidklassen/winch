package module

import (
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
)

// removal is an entry of a directory that purge removes, with its plan line.
type removal struct {
	name, line string
}

// removals returns the entries of dir, the directory of the step, that
// purge removes, in name order. It fails on an entry that holds a mount point
// or a flag that stops the removal. It never follows a symbolic link.
func (d *Dir) removals(dir *os.Root) ([]removal, error) {
	f, err := dir.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	want := map[string]bool{}
	for _, n := range names {
		want[path.Join(d.Path, n)] = true
	}
	owned, err := dpkgOwners(os.DirFS(dpkgInfo), want)
	if err != nil {
		return nil, err
	}
	var out []removal
	for _, n := range names {
		fi, err := dir.Lstat(n)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if keeps(d.Path, n, fi.Mode()&fs.ModeSymlink != 0, d.Keep, owned) {
			continue
		}
		p := path.Join(d.Path, n)
		line := "remove " + strings.TrimPrefix(kind(fi), "a ") + " " + p
		if fi.IsDir() || fi.Mode().IsRegular() {
			if line, err = checkReplace(dir, n, p, fi, true); err != nil {
				return nil, err
			}
		}
		out = append(out, removal{n, line})
	}
	return out, nil
}

// purge removes the entries of dir that removals returns.
func (d *Dir) purge(dir *os.Root) error {
	rs, err := d.removals(dir)
	if err != nil {
		return err
	}
	for _, r := range rs {
		if err := dir.RemoveAll(r.name); err != nil {
			return err
		}
	}
	return nil
}

// keeps reports whether purge keeps the entry name of the directory dir: a
// package owns it, it is a path in keep or a parent of one, or it is an
// enable link of a unit.
func keeps(dir, name string, link bool, keep []string, owned map[string]string) bool {
	p := path.Join(dir, name)
	if _, ok := owned[p]; ok {
		return true
	}
	if slices.ContainsFunc(keep, func(k string) bool { return k == p || strings.HasPrefix(k, p+"/") }) {
		return true
	}
	return enableLink(dir, name, link)
}

// enableLink reports whether the entry name of dir is what systemctl enable,
// mask, or an alias makes: a link in the unit directory, a directory of
// links such as multi-user.target.wants, or a link in such a directory.
func enableLink(dir, name string, link bool) bool {
	links := func(n string) bool {
		return strings.HasSuffix(n, ".wants") || strings.HasSuffix(n, ".requires") || strings.HasSuffix(n, ".upholds")
	}
	switch {
	case dir == unitDir:
		return link || links(name)
	case path.Dir(dir) == unitDir && links(path.Base(dir)):
		return link
	}
	return false
}
