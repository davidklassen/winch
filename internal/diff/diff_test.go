package diff

import "testing"

func TestDiff(t *testing.T) {
	tests := []struct{ old, new, want string }{
		{"a\n", "a\n", ""},
		{"", "hi\n", "@@ -0,0 +1,1 @@\n+hi\n"},
		{"a\nb\nc\n", "a\nB\nc\n", "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"},
		{"a", "b", "@@ -1,1 +1,1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n"},
	}
	for _, tt := range tests {
		if got := string(Diff([]byte(tt.old), []byte(tt.new))); got != tt.want {
			t.Errorf("Diff(%q, %q) = %q, want %q", tt.old, tt.new, got, tt.want)
		}
	}
}
