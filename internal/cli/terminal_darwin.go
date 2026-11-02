package cli

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	ioctlGetTermios = syscall.TIOCGETA
	ioctlSetTermios = syscall.TIOCSETA
)

func discardInput(f *os.File) error {
	what := int32(1) // FREAD of <sys/fcntl.h>
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCFLUSH, uintptr(unsafe.Pointer(&what)))
	if errno != 0 {
		return errno
	}
	return nil
}
