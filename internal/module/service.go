package module

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Service struct {
	Name      string `yaml:"name,required" json:"name"`
	Running   *bool  `yaml:"running" json:"running,omitempty"`
	Enabled   *bool  `yaml:"enabled" json:"enabled,omitempty"`
	Reloaded  bool   `yaml:"reloaded" json:"reloaded,omitempty"`
	Restarted bool   `yaml:"restarted" json:"restarted,omitempty"`

	// Check sets these for Apply: the systemctl commands, in order.
	todo  []string
	links []string
}

func (s *Service) Main() string { return s.Name }

var unitRe = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+$`)

var unitTypes = []string{"service", "socket", "device", "mount", "automount", "swap", "target", "path", "timer", "slice", "scope"}

func (s *Service) Validate() error {
	// systemctl adds .service to a name without a unit-type suffix.
	stem, suffix := s.Name, ".service"
	if i := strings.LastIndexByte(s.Name, '.'); i >= 0 && slices.Contains(unitTypes, s.Name[i+1:]) {
		stem, suffix = s.Name[:i], ""
	}
	prefix, instance, at := strings.Cut(stem, "@")
	n := len(s.Name) + len(suffix)
	switch {
	case !unitRe.MatchString(s.Name):
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q is not a unit name", s.Name)}
	case at && prefix == "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs a name before \"@\"", s.Name)}
	case at && instance == "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs an instance name after \"@\"", s.Name)}
	case stem == "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs a name before the suffix", s.Name)}
	case n > 255 && suffix != "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("has %d characters with .service added; a unit name has at most 255", n)}
	case n > 255:
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("has %d characters; a unit name has at most 255", n)}
	case s.Reloaded && s.Restarted:
		return &yamlx.FieldError{Field: "restarted", Msg: "a service step has one of reloaded and restarted"}
	case s.Reloaded || s.Restarted:
		action := "reloaded"
		if s.Restarted {
			action = "restarted"
		}
		return takesNone(action, arg{"running", s.Running != nil}, arg{"enabled", s.Enabled != nil})
	case s.Running == nil && s.Enabled == nil:
		return &yamlx.FieldError{Msg: "a service step needs running or enabled"}
	}
	return nil
}

func (s *Service) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	out, err := run(ctx, nil, "systemctl", "show", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,Type,RemainAfterExit", "--", s.Name)
	if err != nil {
		return Result{}, err
	}
	u, err := parseShow(out)
	if err != nil {
		return Result{}, fmt.Errorf("systemctl show %s: %w", s.Name, err)
	}
	if u.id != s.Name && u.id != s.Name+".service" {
		return Result{}, fmt.Errorf("%s is an alias of %s; use %s", s.Name, u.id, strings.TrimSuffix(u.id, ".service"))
	}
	missing := u.load == "not-found"
	if missing && (s.Restarted || s.Reloaded) {
		return Result{Status: OK}, nil
	}
	switch {
	case missing, u.load == "loaded":
	case u.load == "masked" && (s.Enabled == nil || !*s.Enabled) && (s.Running == nil || !*s.Running):
	case u.load == "masked":
		return Result{}, fmt.Errorf("%s has the load state %q", u.id, u.load)
	default:
		return Result{}, withJournal(ctx, u.id, fmt.Errorf("%s has the load state %q", u.id, u.load))
	}
	if u.reload {
		s.todo = append(s.todo, "daemon-reload")
	}
	// try-restart and try-reload-or-restart leave a stopped unit stopped.
	switch {
	case s.Restarted:
		s.todo = append(s.todo, "try-restart")
	case s.Reloaded:
		s.todo = append(s.todo, "try-reload-or-restart")
	}
	if s.Enabled != nil {
		// systemctl disable ignores a masked unit: when the mask goes away,
		// the enable links start the unit. It also removes the link that
		// systemctl link made, and the unit is gone. For an instance, that
		// link is the template's, and systemctl disable keeps it.
		var linked bool
		if !*s.Enabled && u.file == "enabled" && !strings.Contains(u.id, "@") {
			fi, err := os.Lstat(filepath.Join(unitDir, u.id))
			linked = err == nil && fi.Mode().Type() == fs.ModeSymlink
		}
		switch {
		case missing:
			if *s.Enabled {
				s.todo = append(s.todo, "enable")
			}
		case !*s.Enabled && (u.load == "masked" || linked):
			s.links, err = enableLinks(u.id)
			if err != nil {
				return Result{}, err
			}
			if len(s.links) > 0 {
				s.todo = append(s.todo, "disable")
			}
		case !*s.Enabled && u.file == "enabled":
			s.todo = append(s.todo, "disable")
		case !*s.Enabled, u.file == "enabled":
		case u.file == "disabled", u.file == "enabled-runtime":
			s.todo = append(s.todo, "enable")
		case u.file == "linked":
			// systemd reports a unit without [Install] as static, but not
			// a linked one.
			ok, err := hasInstall(append([]string{u.fragment}, strings.Fields(u.dropIns)...))
			if err != nil {
				return Result{}, err
			}
			if !ok {
				return Result{}, fmt.Errorf("%s has no [Install] section with WantedBy, RequiredBy, UpheldBy, or Alias; enabled: true cannot enable it", u.id)
			}
			s.todo = append(s.todo, "enable")
		default:
			return Result{}, fmt.Errorf("%s has the unit file state %q; enabled: true needs an enabled, disabled, enabled-runtime, or linked unit", u.id, u.file)
		}
	}
	if s.Running != nil {
		if *s.Running && u.oneshot && !u.remain {
			return Result{}, fmt.Errorf("%s is a oneshot unit without RemainAfterExit=yes, so it is never running after its job; start its timer, or use cmd", u.id)
		}
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
	var changes []string
	for _, c := range s.todo {
		changes = append(changes, cmp.Or(planLabels[c], c))
	}
	if missing {
		changes = append([]string{u.id + " does not exist yet"}, changes...)
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

// planLabels are the plan lines of the commands that differ from the
// command.
var planLabels = map[string]string{"try-restart": "restart", "try-reload-or-restart": "reload"}

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
		_, err := run(ctx, nil, "systemctl", args...)
		switch {
		case err == nil:
		case c == "start", c == "stop", c == "try-restart", c == "try-reload-or-restart":
			return withJournal(ctx, s.Name, err)
		default:
			return err
		}
	}
	return nil
}

// withJournal adds the last 10 lines of the journal of unit to err.
func withJournal(ctx context.Context, unit string, err error) error {
	journal, jerr := run(ctx, nil, "journalctl", "--unit="+unit, "-n", "10", "--no-pager", "-o", "cat")
	if jerr != nil {
		return errors.Join(err, jerr)
	}
	return fmt.Errorf("%w\n%s", err, strings.TrimSpace(journal))
}

const unitDir = "/etc/systemd/system"

// enableLinks returns the links in /etc/systemd/system that systemctl
// disable removes: the ones with the unit's name, and the ones to the unit.
// The link at the unit's own path is the mask or the unit file.
func enableLinks(id string) ([]string, error) {
	own := filepath.Join(unitDir, id)
	var links []string
	err := filepath.WalkDir(unitDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type() != fs.ModeSymlink || p == own {
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

// hasInstall reports whether the unit files at paths, read in order, have
// an [Install] key that systemctl enable acts on. An empty value clears the
// earlier ones.
func hasInstall(paths []string) (bool, error) {
	set := map[string]bool{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return false, fmt.Errorf("read the unit file: %w", err)
		}
		var section string
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				section = line
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if ok && section == "[Install]" {
				set[strings.TrimSpace(k)] = strings.TrimSpace(v) != ""
			}
		}
	}
	return set["WantedBy"] || set["RequiredBy"] || set["UpheldBy"] || set["Alias"], nil
}

type unitState struct {
	id, load, active, sub, file, fragment, dropIns string
	reload, oneshot, remain                        bool
}

func parseShow(out string) (unitState, error) {
	var u unitState
	if out == "" {
		return u, errors.New("no output")
	}
	seen := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return u, fmt.Errorf("unexpected line %q", line)
		}
		seen[k] = true
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
		case "FragmentPath":
			u.fragment = v
		case "DropInPaths":
			u.dropIns = v
		case "NeedDaemonReload":
			u.reload = v == "yes"
		case "Type":
			u.oneshot = v == "oneshot"
		case "RemainAfterExit":
			u.remain = v == "yes"
		}
	}
	for _, k := range []string{"Id", "LoadState", "ActiveState"} {
		if !seen[k] {
			return u, fmt.Errorf("no %s line", k)
		}
	}
	return u, nil
}
