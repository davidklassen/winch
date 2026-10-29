package module

import (
	"os"

	"golang.org/x/sys/unix"
)

// exchange swaps the entries a and b in dir in one step.
func exchange(dir *os.Root, a, b string) error {
	d, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	fd := int(d.Fd())
	return unix.Renameat2(fd, a, fd, b, unix.RENAME_EXCHANGE)
}
