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
	if err := s.Apply(t.Context(), Silent{}); err != nil {
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

// spec: Modules/service and unit (the watch after a start)
func TestStartWatch(t *testing.T) {
	for _, c := range []struct {
		typ, cmd, canReload string
		watch               bool
	}{
		{"simple", "start", "yes", true},
		{"forking", "try-restart", "yes", true},
		{"notify", "start", "yes", false},
		{"notify-reload", "try-restart", "yes", false},
		{"dbus", "start", "yes", false},
		{"oneshot", "start", "yes", false},
		{"simple", "try-reload-or-restart", "yes", false},
		// A unit that cannot reload restarts.
		{"simple", "try-reload-or-restart", "no", true},
		// A socket or a timer has no type.
		{"", "start", "no", false},
	} {
		t.Run(c.typ+" "+c.cmd+" "+c.canReload, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "log")
			script := "#!/bin/sh\necho \"$*\" >> " + log + "\n" +
				"case \"$*\" in show*) echo Id=app.service; echo LoadState=loaded; echo ActiveState=active; echo SubState=running; echo InvocationID=1; echo Type=" + c.typ + "; echo CanReload=" + c.canReload + ";; esac\n"
			if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			s := &Service{Name: "app", todo: []string{c.cmd}, up: true}
			if err := s.Apply(t.Context(), Silent{}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			// The watch reads the unit state again after it.
			shows := strings.Count(string(data), "show ")
			if watched := shows == 2; watched != c.watch {
				t.Errorf("%d systemctl show calls, want the watch %v", shows, c.watch)
			}
		})
	}
}

// spec: Modules/service; CLI/Messages (a fix works in its case)
func TestMaskedNamesTheUnmask(t *testing.T) {
	for _, tt := range []struct {
		u    unitState
		want string
	}{
		{unitState{id: "a.service", file: "masked", fragment: "/etc/systemd/system/a.service"}, "a.service is masked; systemctl unmask a.service removes the mask"},
		{unitState{id: "a.service", file: "masked-runtime", fragment: "/run/systemd/system/a.service"}, "a.service is masked; systemctl unmask --runtime a.service removes the mask"},
		{unitState{id: `mnt-a\x2db.mount`, file: "masked", fragment: `/etc/systemd/system/mnt-a\x2db.mount`}, `mnt-a\x2db.mount is masked; systemctl unmask 'mnt-a\x2db.mount' removes the mask`},
		{unitState{id: "a.service", file: "masked", fragment: "/usr/lib/systemd/system/a.service"}, "a.service is masked by /usr/lib/systemd/system/a.service, which systemctl unmask does not remove; a unit step that writes a.service overrides it"},
	} {
		if got := masked(tt.u).Error(); got != tt.want {
			t.Errorf("got  %s\nwant %s", got, tt.want)
		}
	}
}
