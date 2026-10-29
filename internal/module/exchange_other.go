//go:build !linux

package module

import (
	"errors"
	"os"
)

func exchange(*os.Root, string, string) error { return errors.ErrUnsupported }
