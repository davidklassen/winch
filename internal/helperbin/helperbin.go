// Package helperbin holds the helper binaries that winch sends to hosts.
// make builds them into this directory before it builds winch.
package helperbin

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

var (
	//go:embed helper-linux-amd64
	amd64 []byte
	//go:embed helper-linux-arm64
	arm64 []byte
)

type Binary struct {
	Arch   string
	Data   []byte
	SHA256 string
}

func New(arch string, data []byte) Binary {
	h := sha256.Sum256(data)
	return Binary{Arch: arch, Data: data, SHA256: hex.EncodeToString(h[:])}
}

func Binaries() []Binary {
	return []Binary{New("amd64", amd64), New("arm64", arm64)}
}
