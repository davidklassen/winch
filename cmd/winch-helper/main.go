package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/davidklassen/winch/internal/helper"
	"github.com/davidklassen/winch/internal/module"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--rollback" {
		// The timer process has no one to tell about an error.
		_ = helper.RunTimer(context.Background(), os.Args[2], 200*time.Millisecond)
		return
	}
	login := module.State{LoginUID: helper.LoginUID(os.Getenv("SUDO_UID"), os.Getuid()), SSHConnection: os.Args[1]}
	helper.ResetEnv()
	// A write to a broken session fails instead of killing the helper, so
	// that it can put back the files of a handler that did not run. Notify,
	// unlike Ignore, does not pass to the commands that the helper starts.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	// The login user's umask reaches the helper through sudo.
	syscall.Umask(0o022)
	os.Chdir("/") //nolint:errcheck // / always exists
	self, err := os.Executable()
	if err == nil {
		err = helper.Serve(context.Background(), os.Stdin, os.Stdout, filepath.Dir(filepath.Dir(self)), self, login)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
