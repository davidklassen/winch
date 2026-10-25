package module

import (
	"os"
	"syscall"
	"unsafe"
)

// fsIocGetflags is FS_IOC_GETFLAGS, _IOR('f', 1, long), on 64-bit Linux.
const fsIocGetflags = 0x80086601

// inodeFlags returns the inode flags of f, or 0 when its file system has none.
func inodeFlags(f *os.File) (uint32, error) {
	var flags uint32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetflags, uintptr(unsafe.Pointer(&flags)))
	switch errno {
	case 0:
		return flags, nil
	case syscall.ENOTTY, syscall.EOPNOTSUPP, syscall.EINVAL:
		return 0, nil
	}
	return 0, errno
}
