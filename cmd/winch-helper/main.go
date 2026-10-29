package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
	// Modules read the output of host commands, so it must not be translated.
	os.Setenv("LC_ALL", "C.UTF-8") //nolint:errcheck // cannot fail for a valid name
	os.Unsetenv("LANGUAGE")        //nolint:errcheck // cannot fail for a valid name
	// A sudoers without secure_path passes the login user's PATH, often
	// without /usr/sbin.
	os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") //nolint:errcheck // cannot fail for a valid name
	os.Setenv("HOME", "/root")                                                        //nolint:errcheck // cannot fail for a valid name
	login := module.State{LoginUID: helper.LoginUID(os.Getenv("SUDO_UID"), os.Getuid()), SSHConnection: os.Args[1]}
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "SUDO_") {
			os.Unsetenv(name) //nolint:errcheck // cannot fail for a valid name
		}
	}
	// A write to a broken session fails instead of killing the helper, so
	// that it can put back the files of a handler that did not run. Notify,
	// unlike Ignore, does not pass to the commands that the helper starts.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	// The login user's umask reaches the helper through sudo.
	syscall.Umask(0o022)
	os.Chdir("/")         //nolint:errcheck // / always exists
	os.Setenv("PWD", "/") //nolint:errcheck // cannot fail for a valid name
	self, err := os.Executable()
	if err == nil {
		err = helper.Serve(context.Background(), os.Stdin, os.Stdout, filepath.Dir(filepath.Dir(self)), self, login)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "winch helper:", err)
		os.Exit(1)
	}
}
