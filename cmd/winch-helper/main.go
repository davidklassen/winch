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
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "SUDO_") {
			os.Unsetenv(name) //nolint:errcheck // cannot fail for a valid name
		}
	}
	// The login user's umask reaches the helper through sudo.
	syscall.Umask(0o022)
	self, err := os.Executable()
	if err == nil {
		err = helper.Serve(context.Background(), os.Stdin, os.Stdout, filepath.Dir(filepath.Dir(self)), self)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "winch helper:", err)
		os.Exit(1)
	}
}
