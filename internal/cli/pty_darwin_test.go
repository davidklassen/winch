package cli

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// openPTY returns the controller and the terminal of a new pseudo-terminal.
func openPTY(t *testing.T) (controller, terminal *os.File) {
	t.Helper()
	controller, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { controller.Close() })
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, controller.Fd(), syscall.TIOCPTYGRANT, 0); errno != 0 {
		t.Fatal(errno)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, controller.Fd(), syscall.TIOCPTYUNLK, 0); errno != 0 {
		t.Fatal(errno)
	}
	var name [128]byte
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, controller.Fd(), syscall.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name))); errno != 0 {
		t.Fatal(errno)
	}
	terminal, err = os.OpenFile(string(name[:bytes.IndexByte(name[:], 0)]), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { terminal.Close() })
	return controller, terminal
}
