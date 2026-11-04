package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/secret"
)

// maskedRecords are the files in dir that hold the masked content of the
// files of a project that hold a secret.
type maskedRecords struct {
	dir string
}

// name returns the name of the record of the file that the step m writes, or
// "" for a module without text.
func (r maskedRecords) name(m module.Module) string {
	if _, ok := m.(module.WithText); !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(module.Touches(m)[0].Path))
	return hex.EncodeToString(sum[:])
}

func (r maskedRecords) path(m module.Module) string {
	name := r.name(m)
	if name == "" {
		return ""
	}
	return filepath.Join(r.dir, name)
}

// read returns the record of the step m, or nil when it has none.
func (r maskedRecords) read(m module.Module) (*string, error) {
	name := r.name(m)
	if name == "" {
		return nil, nil
	}
	f, err := os.OpenInRoot(r.dir, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the masked content: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read the masked content: %w", err)
	}
	return new(string(data)), nil
}

// keep records the masked content of the step m. A line step adds its line to
// the record cur of the file, and no step takes a line out: an old line can fit
// the record line of another step, whose secret stays in the file.
func (r maskedRecords) keep(m module.Module, cur *string, masked string) error {
	if _, ok := m.(*module.Line); ok {
		masked = secret.RecordAdd(cur, masked)
	}
	if cur != nil && *cur == masked {
		return nil
	}
	return writeFile(r.dir, r.name(m), "masked content", masked)
}

func (r maskedRecords) remove(m module.Module) error {
	p := r.path(m)
	if p == "" {
		return nil
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the masked content: %w", err)
	}
	return nil
}
