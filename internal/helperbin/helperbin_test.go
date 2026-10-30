package helperbin

import (
	"bytes"
	"debug/elf"
	"testing"
)

// spec: Remote execution/Helper; Remote execution/Facts
func TestBinariesMatchArch(t *testing.T) {
	machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}
	bins := Binaries()
	if len(bins) != len(machines) || !Embedded() {
		t.Fatalf("%d helpers, embedded %t; want %d", len(bins), Embedded(), len(machines))
	}
	for _, b := range bins {
		f, err := elf.NewFile(bytes.NewReader(b.Data))
		if err != nil {
			t.Fatalf("%s: %v", b.Arch, err)
		}
		if want := machines[b.Arch]; f.Machine != want {
			t.Errorf("helper %s is built for %s, want %s", b.Arch, f.Machine, want)
		}
	}
}
