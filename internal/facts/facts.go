// Package facts holds the read-only values that the helper reads about a host.
package facts

import (
	"bufio"
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Facts struct {
	OS             OS   `json:"os" expr:"os"`
	RebootRequired bool `json:"reboot_required" expr:"reboot_required"`
}

type OS struct {
	ID       string `json:"id" expr:"id"`
	Version  string `json:"version" expr:"version"`
	Codename string `json:"codename" expr:"codename"`
	Arch     string `json:"arch" expr:"arch"`
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
	// The start script picks the helper binary by uname -m, so the arch of
	// the helper is the arch of the host.
	f.OS.Arch = runtime.GOARCH
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
	return map[string]any{"os": map[string]any{"id": f.OS.ID, "version": f.OS.Version, "codename": f.OS.Codename, "arch": f.OS.Arch}, "reboot_required": f.RebootRequired}
}

// RebootRequired reports whether the host waits for a reboot: the flag file
// exists, or a kernel in boot is newer than the running release, of the same
// flavor. A release such as 6.12.43+deb13-arm64 has the version 6.12.43+deb13
// and the flavor arm64; Debian 12's 6.1.0-28-amd64 has the version 6.1.0-28.
func RebootRequired(flag, boot, release string) (bool, error) {
	_, err := os.Lstat(flag)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	entries, err := os.ReadDir(boot)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	running, flavor := kernelVersion(release)
	for _, e := range entries {
		k, ok := strings.CutPrefix(e.Name(), "vmlinuz-")
		if !ok {
			continue
		}
		if v, f := kernelVersion(k); f == flavor && compareVersions(v, running) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// kernelVersion splits a kernel release into its version and its flavor: the
// flavor starts at the first part after a "-" that starts with a letter.
// 6.1.0-28-cloud-amd64 has the version 6.1.0-28 and the flavor cloud-amd64.
func kernelVersion(release string) (string, string) {
	parts := strings.Split(release, "-")
	for i := 1; i < len(parts); i++ {
		if c := parts[i]; c != "" && (c[0] < '0' || c[0] > '9') {
			return strings.Join(parts[:i], "-"), strings.Join(parts[i:], "-")
		}
	}
	return release, ""
}

// compareVersions compares two Debian package versions as dpkg does: the
// epoch, then the rest in parts of non-digits and digits. In a non-digit part,
// a letter sorts before another character, and "~" before everything, also
// the end.
func compareVersions(a, b string) int {
	ea, ra := epoch(a)
	eb, rb := epoch(b)
	if ea != eb {
		return cmp.Compare(ea, eb)
	}
	for ra != "" || rb != "" {
		var na, nb string
		na, ra = cutSpan(ra, false)
		nb, rb = cutSpan(rb, false)
		if c := compareText(na, nb); c != 0 {
			return c
		}
		na, ra = cutSpan(ra, true)
		nb, rb = cutSpan(rb, true)
		if c := compareNumbers(na, nb); c != 0 {
			return c
		}
	}
	return 0
}

func epoch(v string) (int, string) {
	e, rest, ok := strings.Cut(v, ":")
	if !ok {
		return 0, v
	}
	n, err := strconv.Atoi(e)
	if err != nil {
		return 0, v
	}
	return n, rest
}

// cutSpan returns the leading digits of s, or its leading non-digits.
func cutSpan(s string, digits bool) (string, string) {
	i := strings.IndexFunc(s, func(r rune) bool { return (r >= '0' && r <= '9') != digits })
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}

func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	}
	return int(c) + 256
}

func compareText(a, b string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var ca, cb int
		if i < len(a) {
			ca = order(a[i])
		}
		if i < len(b) {
			cb = order(b[i])
		}
		if ca != cb {
			return cmp.Compare(ca, cb)
		}
	}
	return 0
}

func compareNumbers(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return cmp.Compare(len(a), len(b))
	}
	return strings.Compare(a, b)
}
