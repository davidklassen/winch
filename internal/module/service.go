package module

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
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

// Unit returns the unit name with its type. systemctl adds .service to a
// name without one.
func (s *Service) Unit() string {
	if i := strings.LastIndexByte(s.Name, '.'); i >= 0 && slices.Contains(unitTypes, s.Name[i+1:]) {
		return s.Name
	}
	return s.Name + ".service"
}

func (s *Service) Validate() error {
	unit := s.Unit()
	added := unit != s.Name
	stem := unit[:strings.LastIndexByte(unit, '.')]
	prefix, instance, at := strings.Cut(stem, "@")
	n := len(unit)
	switch {
	case !unitRe.MatchString(s.Name):
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q is not a unit name", s.Name)}
	case at && prefix == "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs a name before \"@\"", s.Name)}
	case at && instance == "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs an instance name after \"@\"", s.Name)}
	case stem == "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs a name before the suffix", s.Name)}
	case n > 255 && added:
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
	out, err := run(ctx, nil, "systemctl", "show", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,Type,RemainAfterExit,TriggeredBy", "--", s.Name)
	if err != nil {
		return Result{}, err
	}
	u, err := parseShow(out)
	if err != nil {
		return Result{}, fmt.Errorf("systemctl show %s: %w", s.Name, err)
	}
	if u.id != s.Unit() {
		return Result{}, fmt.Errorf("%s is an alias of %s; use %s", s.Name, u.id, strings.TrimSuffix(u.id, ".service"))
	}
	missing := u.load == "not-found"
	if missing && (s.Restarted || s.Reloaded) {
		return Result{Status: OK}, nil
	}
	off := (s.Enabled == nil || !*s.Enabled) && (s.Running == nil || !*s.Running)
	broken := u.load == "bad-setting" || u.load == "error"
	switch {
	case missing, u.load == "loaded", broken && off && !s.Restarted && !s.Reloaded:
	case u.load == "masked" && off:
	case u.load == "masked":
		return Result{}, fmt.Errorf("%s has the load state %q", u.id, u.load)
	default:
		return Result{}, withJournal(ctx, u.id, fmt.Errorf("%s has the load state %q", u.id, u.load))
	}
	var startedBy []string
	if (u.load == "loaded" || broken) && len(u.triggeredBy) > 0 && (s.Running != nil && !*s.Running || s.Enabled != nil && !*s.Enabled) {
		startedBy, err = activeOrEnabled(ctx, u.triggeredBy)
		if err != nil {
			return Result{}, err
		}
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
			in, err := installKeys(append([]string{u.fragment}, strings.Fields(u.dropIns)...))
			if err != nil {
				return Result{}, err
			}
			if len(in["WantedBy"])+len(in["RequiredBy"])+len(in["UpheldBy"])+len(in["Alias"]) == 0 {
				return Result{}, fmt.Errorf("%s has no [Install] section with WantedBy, RequiredBy, UpheldBy, or Alias; enabled: true cannot enable it", u.id)
			}
			s.todo = append(s.todo, "enable")
		default:
			if u.file == "indirect" {
				in, err := installKeys(append([]string{u.fragment}, strings.Fields(u.dropIns)...))
				if err != nil {
					return Result{}, err
				}
				if len(in["Also"]) > 0 {
					return Result{}, fmt.Errorf("%s has the unit file state %q; enabled: true cannot enable it; enable the units in its Also=: %s", u.id, u.file, strings.Join(in["Also"], ", "))
				}
			}
			return Result{}, fmt.Errorf("%s has the unit file state %q; enabled: true needs an enabled, disabled, enabled-runtime, or linked unit", u.id, u.file)
		}
	}
	if s.Running != nil {
		if *s.Running && u.oneshot && !u.remain {
			return Result{}, fmt.Errorf("%s is a oneshot unit without RemainAfterExit=yes, so it is never running after its job; start its timer, or use cmd", u.id)
		}
		up := u.up()
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
		return Result{Status: OK, StartedBy: startedBy}, nil
	}
	var changes []string
	for _, c := range s.todo {
		changes = append(changes, cmp.Or(planLabels[c], c))
	}
	if missing {
		changes = append([]string{u.id + " does not exist yet"}, changes...)
	}
	return Result{Status: Change, Action: Modify, Changes: changes, StartedBy: startedBy}, nil
}

// activeOrEnabled returns the units that are active or enabled.
func activeOrEnabled(ctx context.Context, units []string) ([]string, error) {
	out, err := run(ctx, nil, "systemctl", append([]string{"show", "--property=Id,LoadState,ActiveState,UnitFileState", "--"}, units...)...)
	if err != nil {
		return nil, err
	}
	var found []string
	for block := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n\n") {
		u, err := parseShow(block)
		if err != nil {
			return nil, fmt.Errorf("systemctl show %s: %w", strings.Join(units, " "), err)
		}
		if u.up() || u.file == "enabled" {
			found = append(found, u.id)
		}
	}
	return found, nil
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
		case err == nil && c == "start":
			if err := checkConditions(ctx, s.Unit()); err != nil {
				return err
			}
		case err == nil:
		case c == "start", c == "stop", c == "try-restart", c == "try-reload-or-restart":
			return withJournal(ctx, s.Name, err)
		default:
			return err
		}
	}
	return nil
}

// checkConditions fails when unit is down because a Condition failed.
// systemctl start exits 0 then, and systemd unloads the unit, so the unit
// state does not show the result.
func checkConditions(ctx context.Context, unit string) error {
	out, err := run(ctx, nil, "systemctl", "show", "--property=Id,LoadState,ActiveState", "--", unit)
	if err != nil {
		return err
	}
	u, err := parseShow(out)
	if err != nil {
		return fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	if u.up() {
		return nil
	}
	ctx, cancel := context.WithTimeoutCause(ctx, commandLimit, fmt.Errorf("no result after %s", commandLimit))
	defer cancel()
	// systemd-analyze writes the results to stderr.
	cmd := exec.CommandContext(ctx, "systemd-analyze", "condition", "--unit="+unit)
	var res bytes.Buffer
	cmd.Stdout, cmd.Stderr = &res, &res
	err = wait(ctx, cmd, KillDelay)
	if err == nil {
		return nil
	}
	failed := failedConditions(unit, res.String())
	if len(failed) == 0 {
		return failure("systemd-analyze condition", err, res.String())
	}
	return fmt.Errorf("%s did not start: %s failed", unit, strings.Join(failed, ", "))
}

// failedConditions returns the conditions that kept unit from its start,
// from the output of systemd-analyze condition. A failed triggering
// condition, with "|", counts only when no other condition failed.
func failedConditions(unit, out string) []string {
	var failed, triggers []string
	for line := range strings.SplitSeq(out, "\n") {
		rest, ok := strings.CutPrefix(line, unit+": ")
		cond, no := strings.CutSuffix(rest, " failed.")
		if !ok || !no || !strings.HasPrefix(cond, "Condition") {
			continue
		}
		if _, v, _ := strings.Cut(cond, "="); strings.HasPrefix(v, "|") {
			triggers = append(triggers, cond)
		} else {
			failed = append(failed, cond)
		}
	}
	if len(failed) == 0 {
		return triggers
	}
	return failed
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

// installKeys returns the [Install] keys of the unit files at paths, read in
// order. A value adds its words to the key, and an empty value clears it.
func installKeys(paths []string) (map[string][]string, error) {
	keys := map[string][]string{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read the unit file: %w", err)
		}
		var section string
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") {
				section = line
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || section != "[Install]" {
				continue
			}
			k = strings.TrimSpace(k)
			if words := strings.Fields(v); len(words) > 0 {
				keys[k] = append(keys[k], words...)
			} else {
				delete(keys, k)
			}
		}
	}
	return keys, nil
}

type unitState struct {
	id, load, active, sub, file, fragment, dropIns string
	triggeredBy                                    []string
	reload, oneshot, remain                        bool
}

func (u unitState) up() bool {
	return u.active == "active" || u.active == "activating" || u.active == "reloading"
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
		case "TriggeredBy":
			u.triggeredBy = strings.Fields(v)
		}
	}
	for _, k := range []string{"Id", "LoadState", "ActiveState"} {
		if !seen[k] {
			return u, fmt.Errorf("no %s line", k)
		}
	}
	return u, nil
}
