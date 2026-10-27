package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/davidklassen/winch/internal/helper"
)

func main() {
	// Modules read the output of host commands, so it must not be translated.
	os.Setenv("LC_ALL", "C.UTF-8") //nolint:errcheck // cannot fail for a valid name
	os.Unsetenv("LANGUAGE")        //nolint:errcheck // cannot fail for a valid name
	// A sudoers without secure_path passes the login user's PATH, often
	// without /usr/sbin.
	os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") //nolint:errcheck // cannot fail for a valid name
	os.Setenv("HOME", "/root")                                                        //nolint:errcheck // cannot fail for a valid name
	login := helper.LoginUID(os.Getenv("SUDO_UID"), os.Getuid())
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "SUDO_") {
			os.Unsetenv(name) //nolint:errcheck // cannot fail for a valid name
		}
	}
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
