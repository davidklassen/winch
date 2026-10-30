// Package helperbin holds the helper binaries that winch sends to hosts.
// make builds them into bin/ before it builds winch. A build without make,
// such as go install, holds none.
package helperbin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
)

//go:embed bin
var files embed.FS

type Binary struct {
	Arch   string
	Data   []byte
	SHA256 string
}

func New(arch string, data []byte) Binary {
	h := sha256.Sum256(data)
	return Binary{Arch: arch, Data: data, SHA256: hex.EncodeToString(h[:])}
}

// Binaries returns the helpers in the binary, none in a build without make.
func Binaries() []Binary {
	var bins []Binary
	for _, arch := range []string{"amd64", "arm64"} {
		data, err := files.ReadFile("bin/helper-linux-" + arch)
		if err != nil {
			continue
		}
		bins = append(bins, New(arch, data))
	}
	return bins
}

// Embedded reports whether the binary holds helpers, without reading them.
func Embedded() bool {
	names, _ := fs.Glob(files, "bin/helper-linux-*")
	return len(names) > 0
}
