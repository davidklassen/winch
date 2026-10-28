package module

import "testing"

// spec: Modules/service and unit
func TestUnitActiveStates(t *testing.T) {
	for _, tt := range []struct {
		state string
		up    bool
	}{
		{"active", true},
		{"reloading", true},
		{"inactive", false},
		{"failed", false},
		{"activating", true},
		{"deactivating", false},
		{"maintenance", false},
		{"refreshing", true},
	} {
		t.Run(tt.state, func(t *testing.T) {
			if got := (unitState{active: tt.state}).up(); got != tt.up {
				t.Errorf("up() = %v, want %v", got, tt.up)
			}
		})
	}
}
