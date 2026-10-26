// Package facts holds the read-only values that the helper reads about a host.
package facts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

type Facts struct {
	OS OS `json:"os" expr:"os"`
}

type OS struct {
	ID       string `json:"id" expr:"id"`
	Version  string `json:"version" expr:"version"`
	Codename string `json:"codename" expr:"codename"`
}

// Read reads the facts from the first os-release file in paths that exists.
func Read(paths ...string) (Facts, error) {
	var data []byte
	var err error
	var path string
	for _, path = range paths {
		if data, err = os.ReadFile(path); !errors.Is(err, fs.ErrNotExist) {
			break
		}
	}
	if err != nil {
		return Facts{}, fmt.Errorf("read facts: %w", err)
	}
	f, err := Parse(data)
	if err != nil {
		return Facts{}, fmt.Errorf("read facts: %s: %w", path, err)
	}
	return f, nil
}

// Parse reads the facts from the text of /etc/os-release.
func Parse(data []byte) (Facts, error) {
	var f Facts
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch key {
		case "ID":
			f.OS.ID = unquote(value)
		case "VERSION_ID":
			f.OS.Version = unquote(value)
		case "VERSION_CODENAME":
			f.OS.Codename = unquote(value)
		}
	}
	if f.OS.ID == "" {
		return Facts{}, errors.New("no ID line")
	}
	return f, nil
}

// unquote removes the shell quotes of an os-release value.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	var b strings.Builder
	s = s[1 : len(s)-1]
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Map returns the facts with the names that templates read.
func (f Facts) Map() map[string]any {
	return map[string]any{"os": map[string]any{"id": f.OS.ID, "version": f.OS.Version, "codename": f.OS.Codename}}
}
