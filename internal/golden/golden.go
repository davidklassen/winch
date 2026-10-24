// Package golden compares test output with files in testdata. Run the tests
// with UPDATE_GOLDEN=1 to rewrite the files.
package golden

import (
	"os"
	"path/filepath"
	"testing"
)

func Assert(t *testing.T, path string, got []byte) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_GOLDEN=1 to create it)", err)
	}
	if string(got) != string(want) {
		t.Errorf("%s differs (run with UPDATE_GOLDEN=1 to rewrite it)\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}
