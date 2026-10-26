package module

import (
	"bufio"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// TestLockHolder is the fake lock holder of TestLockFilesNotesTheHolder. It
// holds the fcntl lock of the file in WINCH_LOCK_HOLDER until stdin closes.
func TestLockHolder(t *testing.T) {
	name := os.Getenv("WINCH_LOCK_HOLDER")
	if name == "" {
		t.Skip("runs only as the lock holder")
	}
	unlock, err := lockFiles(t.Context(), []string{name}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	fmt.Println("locked")
	io.Copy(io.Discard, os.Stdin) //nolint:errcheck // stdin closes at the end
}

func TestLockFilesNotesTheHolder(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		name := filepath.Join(dir, "lock")
		holder := exec.Command(os.Args[0], "-test.run=^TestLockHolder$")
		holder.Env = append(os.Environ(), "WINCH_LOCK_HOLDER="+name)
		release, err := holder.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := holder.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := holder.Start(); err != nil {
			t.Fatal(err)
		}
		stop := func() {
			release.Close()
			holder.Wait() //nolint:errcheck // the holder only holds the lock
		}
		defer stop()
		if line, _ := bufio.NewReader(out).ReadString('\n'); line != "locked\n" {
			t.Fatalf("holder printed %q", line)
		}
		// The lock stays taken for a few attempts of lockFiles. The bubble's clock
		// does not move until the holder exits.
		time.AfterFunc(2500*time.Millisecond, stop)

		var notes []string
		unlock, err := lockFiles(t.Context(), []string{filepath.Join(dir, "free"), name}, func(s string) { notes = append(notes, s) })
		if err != nil {
			t.Fatal(err)
		}
		unlock()
		want := []string{fmt.Sprintf("waiting for another apt run (pid %d)", holder.Process.Pid)}
		if !slices.Equal(notes, want) {
			t.Errorf("notes = %q, want %q", notes, want)
		}
	})
}

func TestLockFilesNamesAMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lists")
	_, err := lockFiles(t.Context(), []string{filepath.Join(dir, "lock")}, nil)
	if want := dir + " not found: the host needs apt and dpkg"; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}

// spec: Modules/pkg
func TestAptEnvStopsEveryPrompt(t *testing.T) {
	want := []string{"DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "APT_LISTBUGS_FRONTEND=none", "UCF_FORCE_CONFFOLD=1"}
	if !slices.Equal(aptEnv, want) {
		t.Errorf("aptEnv = %q, want %q", aptEnv, want)
	}
}

// spec: Modules/pkg
func TestParseShowpkgForeign(t *testing.T) {
	out := "Package: winch-mta-c:armhf\nVersions: \n1 (/var/lib/dpkg/status)\n\nPackage: libc6\nVersions: \n2.41 (/var/lib/dpkg/status)\n"
	_, foreign := parseShowpkg(out)
	if want := map[string]string{"winch-mta-c": "winch-mta-c:armhf"}; !maps.Equal(foreign, want) {
		t.Errorf("foreign = %q, want %q", foreign, want)
	}
}

// apt-cache showpkg prints nothing for a name that apt does not know, so bad
// output gives no providers and the install fails at apply.
// spec: Modules/pkg
func TestParseShowpkgBadOutput(t *testing.T) {
	for _, tc := range []struct{ name, out string }{
		{"empty", ""},
		{"junk lines", "\x00garbage\nW: something\n\n"},
		{"no Package line", "Versions: \nReverse Provides: \nlibssl3t64 3.5.1-1 (= )\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			providers, foreign := parseShowpkg(tc.out)
			if len(providers) != 0 || len(foreign) != 0 {
				t.Errorf("providers = %q, foreign = %q; want none", providers, foreign)
			}
		})
	}
}
