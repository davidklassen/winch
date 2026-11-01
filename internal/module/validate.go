package module

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
)

// put renames tmp to name in dir. A directory at name, which a rename cannot
// replace, moves aside first and is removed after. With a validate command,
// it keeps the old entry at name as a hard link, runs the command, and puts
// the old state back when the command fails: the old entry, or no entry and
// none of the missing parents that it created below top.
func put(ctx context.Context, top *os.Root, missing []string, dir *os.Root, tmp, name string, validate *string) error {
	fi, err := dir.Lstat(name)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	isDir := exists && fi.IsDir()
	if validate == nil && !isDir {
		return dir.Rename(tmp, name)
	}
	backup := ".winch-old-" + rand.Text()
	if exists {
		keep := dir.Link
		if isDir {
			keep = dir.Rename
		}
		if err := keep(name, backup); err != nil {
			return err
		}
	}
	if err := dir.Rename(tmp, name); err != nil {
		if isDir {
			return errors.Join(err, dir.Rename(backup, name))
		}
		dir.Remove(backup)
		return err
	}
	var verr error
	if validate != nil {
		verr = Shell(ctx, *validate)
	}
	if verr == nil {
		if exists {
			if err := dir.RemoveAll(backup); err != nil {
				return fmt.Errorf("remove the old %s, kept as %s: %w", name, backup, err)
			}
		}
		return nil
	}
	failed := fmt.Errorf("validate failed: %w", verr)
	if exists {
		if isDir {
			if err := dir.Remove(name); err != nil {
				return errors.Join(failed, fmt.Errorf("put back the old %s, kept as %s: %w", name, backup, err))
			}
		}
		// A failed restore keeps the backup: it is the only copy of the old
		// entry.
		if err := dir.Rename(backup, name); err != nil {
			return errors.Join(failed, fmt.Errorf("put back the old %s, kept as %s: %w", name, backup, err))
		}
		return fmt.Errorf("validate failed, and the old file is back: %w", verr)
	}
	if err := dir.Remove(name); err != nil {
		return errors.Join(failed, err)
	}
	errs := []error{fmt.Errorf("validate failed, and the new file is removed: %w", verr)}
	// The missing parents, relative to top, from the deepest.
	rel := ""
	var parents []string
	for _, m := range missing {
		rel = path.Join(rel, path.Base(m))
		parents = append(parents, rel)
	}
	for i := len(parents) - 1; i >= 0; i-- {
		errs = append(errs, top.Remove(parents[i]))
	}
	return errors.Join(errs...)
}
