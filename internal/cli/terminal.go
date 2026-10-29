package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal reports whether f is a terminal. A character device such as
// /dev/null is not one.
func IsTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), ioctlGetTermios, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}

// UseColor reports whether a stream gets color: it is a terminal,
// NO_COLOR is empty, and TERM is not dumb.
func UseColor(terminal bool, getenv func(string) string) bool {
	return terminal && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
}

// TerminalWidth returns the number of columns of the terminal f, or 0.
func TerminalWidth(f *os.File) int {
	var ws struct{ row, col, x, y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0
	}
	return int(ws.col)
}
