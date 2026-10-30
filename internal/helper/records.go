package helper

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// records is a file of records of a project, one per line: the pending
// handlers as <recipe>.<handler>, the pending then records and checks as
// JSON, or the unpacks as <sha256>:<owner>:<group> <unpack directory>.
type records struct {
	dir     string
	project string
	// what names the records in errors.
	what string
}

// recordsVersion is the format version of the record files. A file starts
// with a line "version <n>".
const recordsVersion = 1

// read returns the lines of the file after its version, also empty ones, so
// that the index i of a line gives its line number i+2.
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
	head, text, _ := strings.Cut(string(data), "\n")
	v, ok := strings.CutPrefix(head, "version ")
	n, err := strconv.Atoi(v)
	if !ok || err != nil || n < 1 {
		return nil, fmt.Errorf("read the %s: %s: no format version", h.what, filepath.Join(h.dir, h.project))
	}
	if n > recordsVersion {
		return nil, fmt.Errorf("upgrade winch to read %s", filepath.Join(h.dir, h.project))
	}
	text = strings.TrimSuffix(text, "\n")
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
	var b strings.Builder
	fmt.Fprintf(&b, "version %d\n", recordsVersion)
	for _, n := range names {
		b.WriteString(n + "\n")
	}
	return writeFile(h.dir, h.project, h.what, b.String())
}

// writeFile replaces the file name in dir in one rename, after the data is
// on disk.
func writeFile(dir, name, what, data string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	tmp := ".winch-" + rand.Text()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("record the %s: %w", what, err)
	}
	defer root.Remove(tmp)
	_, err = f.WriteString(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err == nil {
		err = syncDir(root)
	}
	if err != nil {
		return fmt.Errorf("record the %s: %w", what, err)
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
