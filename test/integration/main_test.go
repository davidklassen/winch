package integration

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

var lab *vmtest.Lab

// oddDir is a path with spaces, shell characters, and UTF-8. A shell of root
// that runs it creates /tmp/pwn: ${HOME%%r*} is "/".
const oddDir = "/tmp/w/Grüße a b;$(touch ${HOME%%r*}tmp${HOME%%r*}pwn)'\"`*日本"

func mksock(path string) string {
	return `python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("` + path + `")'`
}

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
	code := runLab(m, dir, cfg)
	if code == 0 {
		os.RemoveAll(dir)
		return 0
	}
	if err := keepLogs(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Fprintf(os.Stderr, "the logs of the VMs are in %s\n", filepath.Join(dir, "vms"))
	return code
}

// keepLogs removes all files in dir but the console and QEMU logs of the VMs.
func keepLogs(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if filepath.Base(filepath.Dir(filepath.Dir(p))) == "vms" && (d.Name() == "console.log" || d.Name() == "qemu.log") {
			return nil
		}
		return os.Remove(p)
	})
}

func runLab(m *testing.M, dir string, cfg vmtest.Config) int {
	var err error
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
