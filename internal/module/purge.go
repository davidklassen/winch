package module

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
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
		if d.keeps(n, fi.Mode()&fs.ModeSymlink != 0, owned) {
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

func (d *Dir) keeps(name string, link bool, owned map[string]string) bool {
	for _, pattern := range d.KeepPatterns {
		if match, _ := path.Match(pattern, name); match {
			return true
		}
	}
	return keeps(d.Path, name, link, d.Keep, owned)
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

// sshdSafe fails when rs, the removals of the purge, hold a file that sshd
// needs.
func (d *Dir) sshdSafe(ctx context.Context, rs []removal) error {
	needed, err := sshdFiles(ctx)
	if err != nil || len(needed) == 0 {
		return err
	}
	dir, err := filepath.EvalSymlinks(d.Path)
	if err != nil {
		return err
	}
	removed := make([]string, len(rs))
	for i, r := range rs {
		removed[i] = filepath.Join(dir, r.name)
	}
	return sshdLoss(d.Path, removed, needed)
}

// sshdFiles returns the files without which sshd does not start: its main
// config and its host keys.
func sshdFiles(ctx context.Context) ([]string, error) {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		return nil, nil
	}
	out, err := run(ctx, nil, "/usr/sbin/sshd", "-T")
	if err != nil {
		return nil, fmt.Errorf("find the files that sshd needs: %w", err)
	}
	files := []string{"/etc/ssh/sshd_config"}
	for line := range strings.Lines(out) {
		if key, value, _ := strings.Cut(strings.TrimSpace(line), " "); key == "hostkey" {
			files = append(files, value)
		}
	}
	return sshdNeeded(files), nil
}

// sshdNeeded returns each file of files that exists twice: as given, and
// with every symbolic link resolved. A purge that removes a link on either
// path loses the file.
func sshdNeeded(files []string) []string {
	var out []string
	for _, f := range files {
		if resolved, err := filepath.EvalSymlinks(f); err == nil {
			out = append(out, f, resolved)
		}
	}
	return out
}

// sshdLoss fails when removed, the paths that a purge of dir removes, holds a
// path of needed, the files that sshd needs. It names the removed entries, as
// keep takes them.
func sshdLoss(dir string, removed, needed []string) error {
	var lost []string
	for _, r := range removed {
		if slices.ContainsFunc(needed, func(n string) bool { return n == r || strings.HasPrefix(n, r+"/") }) {
			lost = append(lost, filepath.Base(r))
		}
	}
	if len(lost) == 0 {
		return nil
	}
	slices.Sort(lost)
	return fmt.Errorf("purge of %s would remove files that sshd needs: %s; add these names to keep, or purge a narrower directory", dir, strings.Join(slices.Compact(lost), ", "))
}
