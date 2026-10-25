package module

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Service struct {
	Name    string `yaml:"name,required" json:"name"`
	Running *bool  `yaml:"running" json:"running,omitempty"`
	Enabled *bool  `yaml:"enabled" json:"enabled,omitempty"`

	// Check sets these for Apply: the systemctl commands, in order.
	todo  []string
	links []string
}

func (s *Service) Main() string { return s.Name }

var unitRe = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+$`)

func (s *Service) Validate() error {
	switch {
	case !unitRe.MatchString(s.Name):
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q is not a unit name", s.Name)}
	case s.Running == nil && s.Enabled == nil:
		return &yamlx.FieldError{Msg: "a service step needs running or enabled"}
	}
	return nil
}

func (s *Service) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	out, err := run(ctx, nil, "systemctl", "show", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,NeedDaemonReload", "--", s.Name)
	if err != nil {
		return Result{}, err
	}
	u := parseShow(out)
	if u.id != s.Name && u.id != s.Name+".service" {
		return Result{}, fmt.Errorf("%s is an alias of %s; use %s", s.Name, u.id, strings.TrimSuffix(u.id, ".service"))
	}
	missing := u.load == "not-found"
	switch {
	case missing, u.load == "loaded":
	case u.load == "masked" && (s.Enabled == nil || !*s.Enabled) && (s.Running == nil || !*s.Running):
	default:
		return Result{}, fmt.Errorf("%s has the load state %q", u.id, u.load)
	}
	if u.reload {
		s.todo = append(s.todo, "daemon-reload")
	}
	if s.Enabled != nil {
		switch {
		case missing:
			if *s.Enabled {
				s.todo = append(s.todo, "enable")
			}
		case !*s.Enabled && u.file == "enabled":
			s.todo = append(s.todo, "disable")
		case !*s.Enabled && u.file == "masked-runtime":
			// systemctl disable ignores a masked unit. When the mask goes
			// away, the enable links start the unit.
			s.links, err = enableLinks(u.id)
			if err != nil {
				return Result{}, err
			}
			if len(s.links) > 0 {
				s.todo = append(s.todo, "disable")
			}
		case !*s.Enabled, u.file == "enabled":
		case u.file == "disabled":
			s.todo = append(s.todo, "enable")
		default:
			return Result{}, fmt.Errorf("%s has the unit file state %q; enabled: true needs an enabled or disabled unit", u.id, u.file)
		}
	}
	if s.Running != nil {
		up := u.active == "active" || u.active == "activating" || u.active == "reloading"
		// A unit that waits to restart is down, but systemd starts it again
		// unless a stop cancels the restart.
		crashed := strings.HasPrefix(u.sub, "auto-restart")
		switch {
		case *s.Running && (!up || crashed):
			s.todo = append(s.todo, "start")
		case !*s.Running && up:
			s.todo = append(s.todo, "stop")
		}
	}
	if len(s.todo) == 0 {
		return Result{Status: OK}, nil
	}
	changes := s.todo
	if missing {
		changes = append([]string{u.id + " does not exist yet"}, changes...)
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (s *Service) Apply(ctx context.Context, _ func(string)) error {
	for _, c := range s.todo {
		if c == "disable" && s.links != nil {
			for _, l := range s.links {
				if err := os.Remove(l); err != nil {
					return fmt.Errorf("disable %s: %w", s.Name, err)
				}
			}
			c = "daemon-reload"
		}
		args := []string{c}
		if c != "daemon-reload" {
			args = append(args, "--", s.Name)
		}
		if _, err := run(ctx, nil, "systemctl", args...); err != nil {
			return err
		}
	}
	return nil
}

// enableLinks returns the links in /etc/systemd/system that systemctl
// disable removes: the ones with the unit's name, and the ones to the unit.
func enableLinks(id string) ([]string, error) {
	var links []string
	err := filepath.WalkDir("/etc/systemd/system", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type() != fs.ModeSymlink {
			return err
		}
		if d.Name() == id {
			links = append(links, p)
			return nil
		}
		target, err := os.Readlink(p)
		if err == nil && filepath.Base(target) == id {
			links = append(links, p)
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("find the enable links of %s: %w", id, err)
	}
	return links, nil
}

type unitState struct {
	id, load, active, sub, file string
	reload                      bool
}

func parseShow(out string) unitState {
	var u unitState
	for line := range strings.SplitSeq(out, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "Id":
			u.id = v
		case "LoadState":
			u.load = v
		case "ActiveState":
			u.active = v
		case "SubState":
			u.sub = v
		case "UnitFileState":
			u.file = v
		case "NeedDaemonReload":
			u.reload = v == "yes"
		}
	}
	return u
}
