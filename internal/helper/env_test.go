package helper

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// spec: Modules (the environment of host commands)
func TestResetEnv(t *testing.T) {
	// libpam-tmpdir sets TMPDIR in the login session.
	t.Setenv("TMPDIR", "/tmp/user/0")
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("LANG", "de_DE.UTF-8")
	saved := os.Environ()
	t.Cleanup(func() {
		os.Clearenv()
		for _, kv := range saved {
			name, value, _ := strings.Cut(kv, "=")
			os.Setenv(name, value) //nolint:errcheck // cannot fail for a valid name
		}
	})
	ResetEnv()
	out, err := exec.Command("env").Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	slices.Sort(got)
	want := []string{
		"HOME=/root",
		"LC_ALL=C.UTF-8",
		"LOGNAME=root",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"USER=root",
	}
	if !slices.Equal(got, want) {
		t.Errorf("environment of a host command:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
