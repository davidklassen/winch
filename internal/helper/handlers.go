package helper

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// handlers is the file of the pending handlers of a project: one
// <recipe>.<handler> per line.
type handlers struct {
	dir     string
	project string
}

func (h handlers) read() ([]string, error) {
	f, err := os.OpenInRoot(h.dir, h.project)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the pending handlers: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the pending handlers: %w", err)
	}
	return strings.Fields(string(data)), nil
}

func (h handlers) add(names []string) error {
	if len(names) == 0 {
		return nil
	}
	cur, err := h.read()
	if err != nil {
		return err
	}
	added := false
	for _, n := range names {
		if !slices.Contains(cur, n) {
			cur = append(cur, n)
			added = true
		}
	}
	if !added {
		return nil
	}
	return h.write(cur)
}

func (h handlers) remove(name string) error {
	cur, err := h.read()
	if err != nil {
		return err
	}
	out := slices.DeleteFunc(cur, func(n string) bool { return n == name })
	if len(out) == len(cur) {
		return nil
	}
	return h.write(out)
}

// write replaces the file in one rename, after the data is on disk.
func (h handlers) write(names []string) error {
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", h.dir, err)
	}
	root, err := os.OpenRoot(h.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n + "\n")
	}
	tmp := ".winch-" + rand.Text()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("record the pending handlers: %w", err)
	}
	defer root.Remove(tmp)
	_, err = f.WriteString(b.String())
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, h.project)
	}
	if err == nil {
		err = syncDir(root)
	}
	if err != nil {
		return fmt.Errorf("record the pending handlers: %w", err)
	}
	return nil
}

// syncDir makes a rename in dir survive a crash.
func syncDir(dir *os.Root) error {
	d, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
