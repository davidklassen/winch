//go:build !linux

package module

import "os"

func inodeFlags(*os.File) (uint32, error) { return 0, nil }
