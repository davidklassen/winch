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
	_, foreign, _ := parseShowpkg(out)
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
			providers, foreign, _ := parseShowpkg(tc.out)
			if len(providers) != 0 || len(foreign) != 0 {
				t.Errorf("providers = %q, foreign = %q; want none", providers, foreign)
			}
		})
	}
}

// spec: Modules/pkg
func TestParseSimulation(t *testing.T) {
	const out = `Reading package lists...
The following additional packages will be installed:
  winch-fragile
The following packages will be upgraded:
  winch-fragile
1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Inst winch-fragile [1] (2 10.0.2.100 [all])
Inst libbaz (1 10.0.2.100 [arm64])
Inst winch-mta-c:armhf (1 10.0.2.100 [armhf])
Inst winch-uses-fragile (1 10.0.2.100 [all])
Inst half [1] (1 local [all])
Conf winch-fragile (2 10.0.2.100 [all])
Conf winch-uses-fragile (1 10.0.2.100 [all])
`
	installs, upgrades := parseSimulation(out, []string{"winch-uses-fragile", "half", "winch-mta-c:armhf"})
	if want := []string{"libbaz"}; !slices.Equal(installs, want) {
		t.Errorf("installs = %q, want %q", installs, want)
	}
	if want := []string{"winch-fragile"}; !slices.Equal(upgrades, want) {
		t.Errorf("upgrades = %q, want %q", upgrades, want)
	}
}

// spec: Modules/pkg
func TestParseShowpkgKnown(t *testing.T) {
	out := "Package: hello\nVersions: \n2.10-5 (/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_main_binary-arm64_Packages) (/var/lib/dpkg/status)\n\n" +
		"Package: at\nVersions: \n3.2.5-2 (/var/lib/dpkg/status)\n\n" +
		"Package: winch-mta\nVersions: \n\nReverse Provides: \nwinch-mta-a 1 (= )\n"
	_, _, known := parseShowpkg(out)
	if want := map[string]bool{"hello": true}; !maps.Equal(known, want) {
		t.Errorf("known = %v, want %v", known, want)
	}
}
