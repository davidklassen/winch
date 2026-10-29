package cli

import (
	"os"
	"syscall"
)

const ioctlGetTermios = syscall.TCGETS

// tcflsh is TCFLSH of the Linux ioctls; package syscall has it only on arm64.
const tcflsh = 0x540b

func discardInput(f *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tcflsh, syscall.TCIFLUSH)
	if errno != 0 {
		return errno
	}
	return nil
}
