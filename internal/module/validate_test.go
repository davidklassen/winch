package module

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spec: Modules/file, dir, link (validate)
func TestLinkValidateFailMessage(t *testing.T) {
	tests := []struct {
		name  string
		setup func(p string) error
		want  string
	}{
		{"create", func(string) error { return nil }, "validate failed, and the new symbolic link is removed: false"},
		{"new target", func(p string) error { return os.Symlink("/a", p) }, "validate failed, and the old symbolic link is back: false"},
		{"replace a file", func(p string) error { return os.WriteFile(p, []byte("old\n"), 0o644) }, "validate failed, and the old file is back: false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "x")
			if err := tt.setup(p); err != nil {
				t.Fatal(err)
			}
			l := &Link{Path: p, Target: new("/b"), Replace: true, Validation: new("false")}
			if err := l.Apply(context.Background(), nil); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Apply() = %v, want %q", err, tt.want)
			}
		})
	}
}
