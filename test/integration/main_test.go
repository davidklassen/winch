package integration

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

var lab *vmtest.Lab

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if os.Getenv("WINCH_VM_IMAGE") == "" {
		fmt.Println("integration tests skipped: WINCH_VM_IMAGE is not set; run make test-integration")
		return 0
	}
	image, arch, err := vmtest.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dir, err := os.MkdirTemp("", "winch-it-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	lab, err = vmtest.NewLab(context.Background(), dir, image, arch)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Module cases open sessions from this process, so it needs the ssh
	// wrapper too.
	if err := os.Setenv("PATH", lab.PATH); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}
