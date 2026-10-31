package vmtest

import (
	"os"
	"strconv"
	"syscall"
	"testing"
	"unsafe"
)

// OpenPTY returns the controller and the terminal of a new pseudo-terminal.
func OpenPTY(t *testing.T) (controller, terminal *os.File) {
	t.Helper()
	controller, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { controller.Close() })
	var unlock, n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, controller.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		t.Fatal(errno)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, controller.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); errno != 0 {
		t.Fatal(errno)
	}
	terminal, err = os.OpenFile("/dev/pts/"+strconv.Itoa(int(n)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { terminal.Close() })
	return controller, terminal
}
