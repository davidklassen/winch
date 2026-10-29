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

// records is a file of records of a project, one per line: the pending
// handlers as <recipe>.<handler>, the pending then records as JSON, or the
// unpacks as <sha256>:<owner>:<group> <unpack directory>.
type records struct {
	dir     string
	project string
	// what names the records in errors.
	what string
}

// read returns the lines of the file, also empty ones, so that the index of a
// line gives its line number.
func (h records) read() ([]string, error) {
	f, err := os.OpenInRoot(h.dir, h.project)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the %s: %w", h.what, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the %s: %w", h.what, err)
	}
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return []string{}, nil
	}
	return strings.Split(text, "\n"), nil
}

// add returns the names that the file did not have.
func (h records) add(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	cur, err := h.read()
	if err != nil {
		return nil, err
	}
	var added []string
	for _, n := range names {
		if !slices.Contains(cur, n) {
			cur = append(cur, n)
			added = append(added, n)
		}
	}
	if len(added) == 0 {
		return nil, nil
	}
	return added, h.write(cur)
}

func (h records) remove(names ...string) error {
	cur, err := h.read()
	if err != nil {
		return err
	}
	out := slices.DeleteFunc(cur, func(n string) bool { return slices.Contains(names, n) })
	if len(out) == len(cur) {
		return nil
	}
	return h.write(out)
}

// write replaces the file in one rename, after the data is on disk.
func (h records) write(names []string) error {
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
		return fmt.Errorf("record the %s: %w", h.what, err)
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
		return fmt.Errorf("record the %s: %w", h.what, err)
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

// recorded returns the value that the records hold for key, or "".
func recorded(downloads records, key string) (string, error) {
	lines, err := downloads.read()
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if sum, lp, _ := strings.Cut(l, " "); lp == key {
			return sum, nil
		}
	}
	return "", nil
}

// record replaces the record of key.
func record(downloads records, sum, key string) error {
	lines, err := downloads.read()
	if err != nil {
		return err
	}
	lines = slices.DeleteFunc(lines, func(l string) bool {
		_, lp, _ := strings.Cut(l, " ")
		return l == "" || lp == key
	})
	return downloads.write(append(lines, sum+" "+key))
}

// forget removes the record of key.
func forget(downloads records, key string) error {
	lines, err := downloads.read()
	if err != nil {
		return err
	}
	n := len(lines)
	lines = slices.DeleteFunc(lines, func(l string) bool {
		_, lp, _ := strings.Cut(l, " ")
		return lp == key
	})
	if len(lines) == n {
		return nil
	}
	return downloads.write(lines)
}
