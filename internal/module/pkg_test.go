package module

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
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
	defer holder.Wait() //nolint:errcheck // the holder only holds the lock
	if line, _ := bufio.NewReader(out).ReadString('\n'); line != "locked\n" {
		release.Close()
		t.Fatalf("holder printed %q", line)
	}
	// The lock stays taken for a few attempts of lockFiles.
	time.AfterFunc(2500*time.Millisecond, func() { release.Close() })

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
}

func TestLockFilesNamesAMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lists")
	_, err := lockFiles(t.Context(), []string{filepath.Join(dir, "lock")}, nil)
	if want := dir + " not found: the host needs apt and dpkg"; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}
