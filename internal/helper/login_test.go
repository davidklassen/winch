package helper

import "testing"

// spec: Modules/user and group
func TestLoginUID(t *testing.T) {
	tests := []struct {
		sudoUID string
		uid     int
		want    uint32
	}{
		{"1000", 0, 1000},
		{"", 0, 0},
		{"x", 0, 0},
		{"", 1000, 1000},
	}
	for _, tt := range tests {
		if got := LoginUID(tt.sudoUID, tt.uid); got != tt.want {
			t.Errorf("LoginUID(%q, %d) = %d, want %d", tt.sudoUID, tt.uid, got, tt.want)
		}
	}
}
