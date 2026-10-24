// Package facts holds the read-only values that the helper reads about a host.
package facts

import (
	"bufio"
	"bytes"
	"fmt"
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

// Read reads the facts from the os-release file at path.
func Read(path string) (Facts, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Facts{}, fmt.Errorf("read facts: %w", err)
	}
	return Parse(data), nil
}

// Parse reads the facts from the text of /etc/os-release.
func Parse(data []byte) Facts {
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
	return f
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
