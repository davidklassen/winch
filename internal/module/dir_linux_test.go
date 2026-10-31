package module

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// spec: Modules/file, dir, link
func TestWalkOwnersDirectorySwappedForLink(t *testing.T) {
	tmp := t.TempDir()
	top := filepath.Join(tmp, "top")
	for _, d := range []string{"b", "c"} {
		if err := os.MkdirAll(filepath.Join(top, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(top, "c", "secret"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fi, err := root.Lstat("top")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	// Every entry has another owner, so fn sees each one. It swaps b for a
	// link to c after the walk listed b as a directory, before it enters b.
	err = walkOwners(root, "top", fi, os.Getuid()+1, os.Getgid()+1, func(_ *os.Root, _, rel string, _ os.FileInfo) error {
		seen = append(seen, rel)
		if rel == "b" {
			if err := os.Remove(filepath.Join(top, "b")); err != nil {
				return err
			}
			return os.Symlink("c", filepath.Join(top, "b"))
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed while winch worked on it") {
		t.Errorf("walk error %v, want a changed directory", err)
	}
	if slices.Contains(seen, "b/secret") {
		t.Errorf("the walk followed the link: %q", seen)
	}
}
