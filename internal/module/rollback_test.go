package module

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

func mustSave(t *testing.T, tc Touch, archive string) Saved {
	t.Helper()
	s, err := Save(tc, archive)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func restoreAll(t *testing.T, saved ...Saved) {
	t.Helper()
	if err := Restore(t.Context(), saved); err != nil {
		t.Fatal(err)
	}
}

// spec: Running a pipeline/Lockout protection (the old content comes back
// with its owner and mode)
func TestRollbackFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(p, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	s := mustSave(t, Touch{p, true}, filepath.Join(dir, "1.tar"))
	if err := os.WriteFile(p, []byte("new\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	restoreAll(t, s)
	if data, _ := os.ReadFile(p); string(data) != "old\n" || mode(t, p) != 0o640 {
		t.Errorf("after the restore: %q, mode %v; want old content, 0640", data, mode(t, p))
	}
	if names, _ := filepath.Glob(filepath.Join(dir, ".winch-*")); len(names) > 0 {
		t.Errorf("temporary files stay: %q", names)
	}
}

// spec: Running a pipeline/Lockout protection (a path that the run created
// goes away)
func TestRollbackCreated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a", "b", "file")
	s := mustSave(t, Touch{p, true}, filepath.Join(dir, "1.tar"))
	if !s.Missing || s.Path != filepath.Join(dir, "a") {
		t.Fatalf("saved %+v, want the missing top directory %s", s, filepath.Join(dir, "a"))
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreAll(t, s)
	if _, err := os.Lstat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Errorf("%s stays after the restore: %v", filepath.Join(dir, "a"), err)
	}

	f := filepath.Join(dir, "new")
	s = mustSave(t, Touch{f, true}, filepath.Join(dir, "2.tar"))
	if err := os.WriteFile(f, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreAll(t, s)
	if _, err := os.Lstat(f); !os.IsNotExist(err) {
		t.Errorf("%s stays after the restore: %v", f, err)
	}
}

// spec: Running a pipeline/Lockout protection
func TestRollbackLink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "link")
	if err := os.Symlink("old-target", p); err != nil {
		t.Fatal(err)
	}
	s := mustSave(t, Touch{p, true}, filepath.Join(dir, "1.tar"))
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("a file now\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreAll(t, s)
	if target, err := os.Readlink(p); err != nil || target != "old-target" {
		t.Errorf("after the restore: link to %q, %v; want old-target", target, err)
	}
}

// spec: Running a pipeline/Lockout protection (owner and mode of a
// directory)
func TestRollbackDirAttrs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d")
	if err := os.Mkdir(p, 0o750); err != nil {
		t.Fatal(err)
	}
	s := mustSave(t, Touch{p, false}, filepath.Join(dir, "1.tar"))
	if s.Dir == nil || s.Archive != "" || s.Dir.Mode != 0o750 {
		t.Fatalf("saved %+v, want the attributes of the directory", s)
	}
	if err := os.Chmod(p, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "kept"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	restoreAll(t, s)
	if m := mode(t, p); m.Perm() != 0o750 {
		t.Errorf("mode after the restore %v, want 0750", m)
	}
	if _, err := os.Lstat(filepath.Join(p, "kept")); err != nil {
		t.Errorf("the restore of the attributes removed the content: %v", err)
	}
}

// spec: Running a pipeline/Lockout protection; Modules/dir (a purge removal
// comes back with its tree)
func TestRollbackTree(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "conf.d")
	for _, d := range []string{p, filepath.Join(p, "sub")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(p, "a.conf"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "sub", "b.conf"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.conf", filepath.Join(p, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(p, "sub"), 0o710); err != nil {
		t.Fatal(err)
	}
	s := mustSave(t, Touch{p, true}, filepath.Join(dir, "1.tar"))
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
	restoreAll(t, s)
	if data, _ := os.ReadFile(filepath.Join(p, "a.conf")); string(data) != "a\n" || mode(t, filepath.Join(p, "a.conf")) != 0o600 {
		t.Errorf("a.conf: %q, %v", data, mode(t, filepath.Join(p, "a.conf")))
	}
	if data, _ := os.ReadFile(filepath.Join(p, "sub", "b.conf")); string(data) != "b\n" {
		t.Errorf("sub/b.conf: %q", data)
	}
	if m := mode(t, filepath.Join(p, "sub")); m.Perm() != 0o710 || !m.IsDir() {
		t.Errorf("sub: %v, want a directory with 0710", m)
	}
	if target, _ := os.Readlink(filepath.Join(p, "link")); target != "a.conf" {
		t.Errorf("link: %q", target)
	}

	// A directory where the saved file was.
	f := filepath.Join(dir, "file")
	if err := os.WriteFile(f, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s = mustSave(t, Touch{f, true}, filepath.Join(dir, "2.tar"))
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	restoreAll(t, s)
	if data, err := os.ReadFile(f); string(data) != "old\n" {
		t.Errorf("file after the restore: %q, %v", data, err)
	}
}

// spec: Running a pipeline/Lockout protection (a failed copy fails clearly)
func TestRollbackSaveFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Save(Touch{p, true}, filepath.Join(dir, "missing", "1.tar"))
	if err == nil || !strings.HasPrefix(err.Error(), "keep the old state of "+p+" for the rollback: ") {
		t.Errorf("Save into a missing directory: %v", err)
	}
	fifo := filepath.Join(dir, "d", "fifo")
	if err := os.Mkdir(filepath.Dir(fifo), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "2.tar")
	_, err = Save(Touch{filepath.Dir(fifo), true}, archive)
	if err == nil || !strings.Contains(err.Error(), fifo+" is a named pipe; the rollback keeps only files, directories, and symbolic links") {
		t.Errorf("Save of a tree with a FIFO: %v", err)
	}
	if _, err := os.Lstat(archive); !os.IsNotExist(err) {
		t.Errorf("a failed save leaves its archive: %v", err)
	}
}

// spec: roadmap phase 16 (a rollback that puts back a unit file runs
// daemon-reload)
func TestRollbackReloads(t *testing.T) {
	if !reloads([]Saved{{Path: "/etc/ssh/sshd_config"}, {Path: "/etc/systemd/system/app.service"}}) {
		t.Error("a unit file does not reload")
	}
	if reloads([]Saved{{Path: "/etc/ssh/sshd_config"}}) {
		t.Error("sshd_config reloads")
	}
}

// spec: Modules/firewall (a failed check restores the old rules)
func TestRollbackLoadsFirewall(t *testing.T) {
	tests := []struct {
		saved []Saved
		want  bool
	}{
		{[]Saved{{Path: "/etc/winch/firewall.nft"}}, true},
		{[]Saved{{Path: "/etc/winch", Missing: true}}, true},
		{[]Saved{{Path: "/etc/winch", Dir: &Attrs{Mode: 0o755}}}, false},
		{[]Saved{{Path: "/etc/systemd/system/winch-firewall.service"}}, false},
		{[]Saved{{Path: "/etc/winch/other"}}, false},
		{[]Saved{{Path: "/etc/nftables.conf"}}, false},
	}
	for _, tt := range tests {
		if got := loadsFirewall(tt.saved); got != tt.want {
			t.Errorf("loadsFirewall(%v) = %v, want %v", tt.saved, got, tt.want)
		}
	}
}

// spec: Running a pipeline/Lockout protection (the timer runs the step again;
// a start is undone)
func TestServiceUndo(t *testing.T) {
	no, yes := false, true
	tests := []struct {
		name string
		s    Service
		todo []string
		want *Service
	}{
		{"start", Service{Name: "nftables", Running: &yes, Enabled: &yes}, []string{"enable", "start"}, &Service{Name: "nftables", Running: &no}},
		{"stop", Service{Name: "nftables", Running: &no}, []string{"stop"}, &Service{Name: "nftables", Running: &yes}},
		{"restart", Service{Name: "ssh", Restarted: true}, []string{"try-restart"}, &Service{Name: "ssh", Restarted: true}},
		{"reload", Service{Name: "ssh", Reloaded: true}, []string{"daemon-reload", "try-reload-or-restart"}, &Service{Name: "ssh", Reloaded: true}},
		{"enable only", Service{Name: "nftables", Enabled: &yes}, []string{"enable"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.s
			s.todo = tt.todo
			got := s.Undo()
			if (got == nil) != (tt.want == nil) {
				t.Fatalf("Undo = %+v, want %+v", got, tt.want)
			}
			if got == nil {
				return
			}
			show := func(s *Service) string {
				r, e := "-", "-"
				if s.Running != nil {
					r = map[bool]string{true: "true", false: "false"}[*s.Running]
				}
				if s.Enabled != nil {
					e = map[bool]string{true: "true", false: "false"}[*s.Enabled]
				}
				return s.Name + " running=" + r + " enabled=" + e + " restarted=" + map[bool]string{true: "y", false: "n"}[s.Restarted] + " reloaded=" + map[bool]string{true: "y", false: "n"}[s.Reloaded]
			}
			if show(got) != show(tt.want) {
				t.Errorf("Undo = %s, want %s", show(got), show(tt.want))
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (a user step that changes the
// keys of the login user); roadmap phase 16 (a purge of the sudo rules)
func TestGuard(t *testing.T) {
	admin := passwdEntry{name: "admin", uid: 1000, home: "/home/admin"}
	root := passwdEntry{name: "root", uid: 0, home: "/root"}
	keys := "changes the keys of the login user admin"
	sudo := "changes the sudo rules, which the login user admin needs"
	tests := []struct {
		name    string
		login   passwdEntry
		touches []Touch
		want    string
	}{
		{"the keys file", admin, []Touch{{"/home/admin/.ssh/authorized_keys", true}}, keys},
		{"the mode of ~/.ssh", admin, []Touch{{"/home/admin/.ssh", false}}, keys},
		{"the mode of the home", admin, []Touch{{"/home/admin", false}}, keys},
		{"a removed /home", admin, []Touch{{"/home", true}}, keys},
		{"the mode of /home", admin, []Touch{{"/home", false}}, ""},
		{"another user's keys", admin, []Touch{{"/home/deploy/.ssh/authorized_keys", true}}, ""},
		{"a file next to the keys", admin, []Touch{{"/home/admin/.ssh/config", true}}, ""},
		{"a sudo rule", admin, []Touch{{"/etc/sudoers.d/admin", true}}, sudo},
		{"a purge of the sudo rules", admin, []Touch{{"/etc/sudoers.d", false}, {"/etc/sudoers.d/90-cloud-init-users", true}}, sudo},
		{"sudoers", admin, []Touch{{"/etc/sudoers", true}}, sudo},
		{"a name with a common prefix", admin, []Touch{{"/etc/sudoers.dpkg-old", true}}, ""},
		{"root needs no sudo", root, []Touch{{"/etc/sudoers.d/admin", true}}, ""},
		{"a recursive owner of /home", admin, []Touch{{"/home", true}}, keys},
		{"root's keys", root, []Touch{{"/root/.ssh/authorized_keys", true}}, "changes the keys of the login user root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := guard(tt.touches, tt.login); got != tt.want {
				t.Errorf("guard = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (every path that the recipe
// changed or removed)
func TestTouches(t *testing.T) {
	no := false
	d := &Dir{Path: "/etc/sudoers.d", Purge: true, removed: []string{"/etc/sudoers.d/90-cloud-init-users"}}
	u := &User{Name: "admin", keys: true, keyHome: "/home/admin"}
	tests := []struct {
		m    Module
		want []Touch
	}{
		{&File{Path: "/etc/a"}, []Touch{{"/etc/a", true}}},
		{d, []Touch{{"/etc/sudoers.d", false}, {"/etc/sudoers.d/90-cloud-init-users", true}}},
		{&Dir{Path: "/srv/x", Absent: true}, []Touch{{"/srv/x", true}}},
		{&Dir{Path: "/home", Recurse: true}, []Touch{{"/home", true}}},
		{&Link{Path: "/etc/l"}, []Touch{{"/etc/l", true}}},
		{&Line{Path: "/etc/x"}, []Touch{{"/etc/x", true}}},
		{&Download{Unpack: "/opt/a"}, []Touch{{"/opt/a", false}}},
		{&User{Name: "deploy", mkHome: "/home/deploy"}, []Touch{{"/home/deploy", false}}},
		{u, []Touch{{"/home/admin/.ssh", false}, {"/home/admin/.ssh/authorized_keys", true}}},
		{&Hostname{Name: "mail"}, []Touch{{"/etc/hostname", true}}},
		{&Timezone{Name: "Etc/UTC"}, []Touch{{"/etc/localtime", true}, {"/etc/timezone", true}}},
		{&Unit{Name: "app.service"}, []Touch{{"/etc/systemd/system/app.service", true}}},
		{&Certbot{Name: "mail"}, []Touch{{"/etc/letsencrypt/renewal/mail.conf", true}, {"/etc/letsencrypt/live/mail", true}, {"/etc/letsencrypt/archive/mail", true}}},
		{&Service{Name: "ssh", Running: &no}, nil},
		{&Firewall{}, []Touch{{"/etc/winch/firewall.nft", true}, {"/etc/systemd/system/winch-firewall.service", true}, {"/etc/systemd/system/sysinit.target.wants/winch-firewall.service", true}, {"/etc/systemd/system/nftables.service.d/winch.conf", true}}},
		{&Firewall{Absent: true}, []Touch{{"/etc/winch/firewall.nft", true}, {"/etc/systemd/system/winch-firewall.service", true}, {"/etc/systemd/system/sysinit.target.wants/winch-firewall.service", true}, {"/etc/systemd/system/nftables.service.d/winch.conf", true}}},
	}
	for _, tt := range tests {
		if got := Touches(tt.m); !slices.Equal(got, tt.want) {
			t.Errorf("Touches(%T %s) = %v, want %v", tt.m, tt.m.Main(), got, tt.want)
		}
	}
}

// spec: Running a pipeline/Lockout protection (every module that writes paths
// names what the rollback keeps)
func TestEveryWriterTouches(t *testing.T) {
	// cmd writes its creates path, but its change is unknown: it keeps
	// nothing. A user keeps what its check found: nothing before a check.
	keepsNothing := []string{"cmd", "user"}
	for _, name := range Names() {
		m, _ := New(name)
		_, writes := m.(Writer)
		if touches := Touches(m) != nil; writes && touches == slices.Contains(keepsNothing, name) || !writes && touches {
			t.Errorf("module %s: Writer %v, Touches %v", name, writes, Touches(m))
		}
	}
}

// spec: Running a pipeline/Lockout protection (the restore runs in reverse
// order)
func TestRollbackOrder(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(dir, "d")
	f := filepath.Join(d, "f")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := mustSave(t, Touch{f, true}, filepath.Join(dir, "1.tar"))
	if err := os.WriteFile(f, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := mustSave(t, Touch{d, true}, filepath.Join(dir, "2.tar"))
	if err := os.RemoveAll(d); err != nil {
		t.Fatal(err)
	}
	restoreAll(t, first, second)
	if data, _ := os.ReadFile(f); string(data) != "old\n" {
		t.Errorf("f after the restore: %q, want the first state", data)
	}
}

// spec: Running a pipeline/Lockout protection (sshd from ssh.socket)
func TestSSHDConfig(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/ssh/sshd_config", true},
		{"/etc/ssh/sshd_config.d", true},
		{"/etc/ssh/sshd_config.d/port.conf", true},
		{"/etc/ssh/ssh_config", false},
		{"/etc/ssh/sshd_config.dpkg-old", false},
		{"/etc/ssh/sshd_config.d.old/port.conf", false},
	}
	for _, tt := range tests {
		if got := sshdConfig(tt.path); got != tt.want {
			t.Errorf("sshdConfig(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
