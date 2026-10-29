package integration

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

var lab *vmtest.Lab

// oddDir is a path with spaces, shell characters, and UTF-8. A shell of root
// that runs it creates /tmp/pwn: ${HOME%%r*} is "/".
const oddDir = "/tmp/w/Grüße a b;$(touch ${HOME%%r*}tmp${HOME%%r*}pwn)'\"`*日本"

const mksock = `python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("/tmp/w/s")'`

// release holds the values of a VM image that the tests compare with.
type release struct {
	id, version, codename string
	// librecode is the library that fortune-mod depends on.
	librecode string
	// sudoDenied is the message of sudo -n without passwordless sudo.
	sudoDenied string
	// postinstFailed is the message of dpkg when a postinst fails.
	postinstFailed string
}

const (
	sudoPassword  = "sudo: a password is required"
	postinstError = "post-installation script subprocess returned error exit status 1"
)

var releases = map[string]release{
	"debian-13":    {id: "debian", version: "13", codename: "trixie", librecode: "librecode3", sudoDenied: sudoPassword, postinstFailed: postinstError},
	"ubuntu-24.04": {id: "ubuntu", version: "24.04", codename: "noble", librecode: "librecode0", sudoDenied: sudoPassword, postinstFailed: postinstError},
	"ubuntu-26.04": {id: "ubuntu", version: "26.04", codename: "resolute", librecode: "librecode3",
		sudoDenied: "sudo: I'm sorry nosudo. I'm afraid I can't do that", postinstFailed: "postinst maintainer script subprocess failed with exit status 1"},
}

// osRelease returns the values of the lab's image.
func osRelease() release {
	return releases[lab.OS()]
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if os.Getenv("WINCH_VM_IMAGE") == "" {
		fmt.Println("integration tests skipped: WINCH_VM_IMAGE is not set; run make test-integration")
		return 0
	}
	cfg, err := vmtest.FromEnv("../repo")
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
	lab, err = vmtest.NewLab(context.Background(), dir, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer lab.Close()
	if _, ok := releases[lab.OS()]; !ok {
		fmt.Fprintf(os.Stderr, "OS=%s: the tests know debian-13, ubuntu-24.04, and ubuntu-26.04\n", lab.OS())
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
