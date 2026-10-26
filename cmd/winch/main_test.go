package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("WINCH_TEST_MAIN") != "" {
		os.Args = append([]string{"winch"}, os.Args[1:]...)
		main()
		return
	}
	os.Exit(m.Run())
}

// spec: Running a pipeline/Apply (Ctrl-C)
func TestInterruptEndsSecretEncrypt(t *testing.T) {
	cmd := exec.Command(os.Args[0], "secret", "encrypt")
	cmd.Env = append(os.Environ(), "WINCH_TEST_MAIN=1")
	cmd.Dir = t.TempDir()
	cfg := "name: acme\nrecipients: [age19a2pz02xj7w726k7vhfvz6fs7zs6dqsxg8xjm3w22a66th5tuals4agwtg]\n"
	if err := os.WriteFile(filepath.Join(cmd.Dir, "winch.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// The pipe stays open, so encrypt waits for its input.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	time.Sleep(500 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Logf("winch: %v", err)
	case <-time.After(5 * time.Second):
		cmd.Process.Kill() //nolint:errcheck // the test failed already
		t.Fatal("winch secret encrypt did not end after Ctrl-C")
	}
}
