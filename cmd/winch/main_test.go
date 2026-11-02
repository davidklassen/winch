package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/cli"
	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
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

// spec: Running a pipeline/Apply (Ctrl-C)
func TestTerminateActsAsInterrupt(t *testing.T) {
	// guard keeps the test binary alive when winch does not catch SIGTERM.
	guard := make(chan os.Signal, 2)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
		// With parallelism 1, web2 starts only after web1.
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    parallelism: 1
    steps:
      - file:
          path: /etc/a
          content: "a\n"
      - file:
          path: /etc/b
          content: "b\n"
`,
	})
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	sessions, kill := context.WithCancel(context.Background())
	defer kill()
	var errOut strings.Builder
	var asking atomic.Bool
	handleInterrupts("interrupted", &errOut, &asking, stop, kill)
	terminate := func(done context.Context) bool {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done.Done():
			return true
		case <-time.After(2 * time.Second):
			return false
		}
	}
	h := fakehost.New()
	h.OnApply = func(host, main string) {
		if host != "web1" || main != "/etc/a" {
			return
		}
		if !terminate(ctx) {
			t.Error("SIGTERM did not interrupt the apply")
		}
		if sessions.Err() != nil {
			t.Error("the first SIGTERM ended the sessions")
		}
	}
	var out strings.Builder
	code := cli.Main(ctx, []string{"apply", "site", "--yes"}, cli.Env{
		Dir: dir, In: strings.NewReader(""), Out: &out, Err: &errOut,
		Connect: h.ConnectorFor, Filter: secret.NewFilter(), Asking: &asking,
	})
	if code != 1 || !strings.HasSuffix(out.String(), "2 hosts: 0 changed, 0 unchanged, 2 failed\n") {
		t.Errorf("exit %d, stdout %q", code, out.String())
	}
	if want := "interrupted\nweb1: interrupted\nweb2: interrupted\n"; errOut.String() != want {
		t.Errorf("stderr %q, want %q", errOut.String(), want)
	}
	if _, ok := h.File("web1", "/etc/b"); ok {
		t.Error("a new step started after SIGTERM")
	}
	if !terminate(sessions) {
		t.Error("a second SIGTERM did not end the sessions")
	}
}

// nohup starts winch with SIGHUP ignored.
//
// spec: Running a pipeline/Apply (Ctrl-C)
func TestIgnoredHangupStaysIgnored(t *testing.T) {
	signal.Ignore(syscall.SIGHUP)
	defer signal.Reset(syscall.SIGHUP)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var asking atomic.Bool
	handleInterrupts("interrupted", io.Discard, &asking, stop, func() {})
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Error("an ignored SIGHUP interrupted winch")
	case <-time.After(500 * time.Millisecond):
	}
}

// spec: CLI/Messages; Running a pipeline/Apply (Ctrl-C)
func TestInterruptLine(t *testing.T) {
	for command, want := range map[string]string{
		"plan":  "winch plan: interrupted, and the running checks finish; press Ctrl-C again to end the sessions",
		"apply": "winch apply: interrupted, and the running steps finish; press Ctrl-C again to end the sessions",
		"run":   "winch run: interrupted, and the running steps finish; press Ctrl-C again to end the sessions",
		"exec":  "winch exec: interrupted, and the commands stop; press Ctrl-C again to end the sessions",
	} {
		if got := interruptLine(command); got != want {
			t.Errorf("interruptLine(%q) = %q, want %q", command, got, want)
		}
	}
}
