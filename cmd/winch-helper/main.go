package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/davidklassen/winch/internal/helper"
)

func main() {
	// Modules read the output of host commands, so it must not be translated.
	os.Setenv("LC_ALL", "C") //nolint:errcheck // cannot fail for a valid name
	self, err := os.Executable()
	if err == nil {
		err = helper.Serve(context.Background(), os.Stdin, os.Stdout, filepath.Dir(filepath.Dir(self)), self)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "winch helper:", err)
		os.Exit(1)
	}
}
