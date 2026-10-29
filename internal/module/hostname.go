package module

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Hostname struct {
	Name string `yaml:"name,required" json:"name"`
}

func (h *Hostname) Main() string { return h.Name }

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (h *Hostname) Validate() error {
	if !hostnameRe.MatchString(h.Name) {
		msg := fmt.Sprintf("%q is not a short host name: 1 to 63 lowercase letters, digits, and \"-\", without \"-\" at the start or the end", h.Name)
		if strings.Contains(h.Name, ".") {
			msg += "; for the first part of the inventory name, use !expr host.short"
		}
		return &yamlx.FieldError{Field: "name", Msg: msg}
	}
	return nil
}

// hostnameFile is the file of the static host name.
const hostnameFile = "/etc/hostname"

func (h *Hostname) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	data, err := os.ReadFile(hostnameFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, err
	}
	static := staticHostname(data)
	running, err := os.Hostname()
	if err != nil {
		return Result{}, err
	}
	var changes []string
	switch {
	case static == h.Name && running == h.Name:
		return Result{Status: OK}, nil
	case static == running:
		changes = []string{"name " + static + " → " + h.Name}
	default:
		if static != h.Name {
			changes = append(changes, "static name "+cmp.Or(static, "(none)")+" → "+h.Name)
		}
		if running != h.Name {
			changes = append(changes, "running name "+running+" → "+h.Name)
		}
	}
	if static != h.Name {
		if err := noFlagsAt(hostnameFile); err != nil {
			return Result{}, err
		}
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (h *Hostname) Apply(ctx context.Context, _ func(string)) error {
	_, err := run(ctx, nil, "hostnamectl", "set-hostname", "--", h.Name)
	return err
}

// staticHostname reads the name as systemd does: the first line that is
// not empty and not a comment.
func staticHostname(data []byte) string {
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}
