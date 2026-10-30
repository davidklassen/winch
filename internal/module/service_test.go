package module

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

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

// spec: Modules/service and unit
func TestUnloadedDropIn(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(dir, "app.service.d")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.conf", "b.conf", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(d, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A link to /dev/null masks a drop-in, and systemd skips a directory.
	if err := os.Symlink("/dev/null", filepath.Join(d, "masked.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d, "dir.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(d, "a.conf"), filepath.Join(d, "b.conf")
	for _, c := range []struct {
		name   string
		id     string
		loaded string
		want   bool
	}{
		{"all loaded", "app.service", a + " " + b, false},
		{"a new file", "app.service", a, true},
		{"a new directory", "app.service", "", true},
		{"no directory", "other.service", "", false},
		// systemctl set-property writes a drop-in that hides one of the
		// same name in /etc/systemd/system.
		{"a drop-in of the same name elsewhere", "app.service", "/etc/systemd/system.control/app.service.d/a.conf " + b, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := unloadedDropIn(dir, c.id, c.loaded)
			if err != nil || got != c.want {
				t.Errorf("unloadedDropIn = %v, %v; want %v", got, err, c.want)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (the start limit of ssh.service
// cannot close the port); Modules/service and unit (reset-failed)
func TestRestartSSHSocketResetsSSHService(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	s := &Service{Name: "ssh.socket", Restarted: true, todo: []string{"try-restart"}}
	if err := s.Apply(t.Context(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	if !slices.Contains(got, "reset-failed -- ssh.service") || !slices.Contains(got, "reset-failed -- ssh.socket") || got[len(got)-1] != "try-restart -- ssh.socket" {
		t.Errorf("systemctl calls %q, want a reset of both SSH units before the restart", got)
	}
}
