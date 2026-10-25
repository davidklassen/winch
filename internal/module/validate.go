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

// put renames tmp to name in dir. With a validate command, it keeps the old
// entry at name as a hard link, runs the command, and puts the old state back
// when the command fails: the old entry, or no entry and none of the missing
// parents that it created below top.
func put(ctx context.Context, top *os.Root, missing []string, dir *os.Root, tmp, name string, validate *string) error {
	if validate == nil {
		return dir.Rename(tmp, name)
	}
	_, err := dir.Lstat(name)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	backup := ".winch-old-" + rand.Text()
	if exists {
		if err := dir.Link(name, backup); err != nil {
			return fmt.Errorf("keep the old %s: %w", name, err)
		}
	}
	if err := dir.Rename(tmp, name); err != nil {
		dir.Remove(backup)
		return err
	}
	verr := Shell(ctx, *validate)
	if verr == nil {
		if exists {
			dir.Remove(backup)
		}
		return nil
	}
	if exists {
		// A failed restore keeps the backup: it is the only copy of the old
		// entry.
		if err := dir.Rename(backup, name); err != nil {
			return errors.Join(fmt.Errorf("validate: %w", verr), fmt.Errorf("put back the old %s, kept as %s: %w", name, backup, err))
		}
		return fmt.Errorf("validate: %w", verr)
	}
	errs := []error{fmt.Errorf("validate: %w", verr), dir.Remove(name)}
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
