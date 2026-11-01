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
	"time"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Service struct {
	Name      string `yaml:"name,required" json:"name" line:"unit, with or without .service" doc:"Unit, with or without .service, such as nginx or certbot.timer."`
	Running   *bool  `yaml:"running" json:"running,omitempty" line:"start or stop; unset leaves it" doc:"Start or stop; unset leaves it. Without running, the step does not start or stop the unit."`
	Enabled   *bool  `yaml:"enabled" json:"enabled,omitempty" line:"start at boot; unset leaves it" doc:"Start at boot; unset leaves it. Without enabled, the step does not change it."`
	Reloaded  bool   `yaml:"reloaded" json:"reloaded,omitempty" line:"reload, in handlers and winch run only" doc:"Reload, in handlers and winch run only. A unit that cannot reload restarts."`
	Restarted bool   `yaml:"restarted" json:"restarted,omitempty" line:"restart, in handlers and winch run only" doc:"Restart, in handlers and winch run only. A stopped unit stays stopped."`
	// NewFile is the unit file that an earlier unit step of the host writes
	// in the run. For an instance, it is the file of the template. The
	// controller sets it.
	NewFile []byte `json:"new_file,omitempty"`
	// Started is set on a handler step when a service step of the run
	// started the unit after the handler's last notify, no earlier step of
	// the handler changed anything, and the step has no confirm_access. A
	// restart or a reload then checks as ok. The controller sets it.
	Started bool `json:"started,omitempty"`
	// Actions is set on a handler step and on the step of winch run, which
	// can use reloaded and restarted. The loader sets it.
	Actions bool `json:"-"`

	// Check sets these for Apply: the systemctl commands, in order.
	todo    []string
	links   []string
	crashed bool
	// up is whether the unit ran before the step and stays running.
	up bool
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

// UnitFile returns the name of the unit's file: the template for an instance.
func (s *Service) UnitFile() string {
	u := s.Unit()
	prefix, rest, ok := strings.Cut(u, "@")
	if !ok {
		return u
	}
	return prefix + "@" + rest[strings.LastIndexByte(rest, '.'):]
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
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs a name before the type", s.Name)}
	case n > 255 && added:
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("has %d characters with .service added; a unit name has at most 255", n)}
	case n > 255:
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("has %d characters; a unit name has at most 255", n)}
	case s.Reloaded && s.Restarted:
		return &yamlx.FieldError{At: "restarted", Msg: "a service step has at most one of reloaded and restarted"}
	case s.Reloaded || s.Restarted:
		action := "reloaded"
		if s.Restarted {
			action = "restarted"
		}
		return takesNone("not with "+action+": true", arg{"running", s.Running != nil}, arg{"enabled", s.Enabled != nil})
	case s.Running == nil && s.Enabled == nil && s.Actions:
		return &yamlx.FieldError{Msg: "a service step needs running, enabled, reloaded, or restarted"}
	case s.Running == nil && s.Enabled == nil:
		return &yamlx.FieldError{Msg: "a service step needs running or enabled"}
	}
	return nil
}

func (s *Service) Check(ctx context.Context, _ *State, _ Say) (Result, error) {
	out, err := run(ctx, nil, "systemctl", "show", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,Type,RemainAfterExit,TriggeredBy", "--", s.Name)
	if err != nil {
		return Result{}, err
	}
	u, err := parseShow(out)
	if err != nil {
		return Result{}, fmt.Errorf("systemctl show %s: %w", s.Name, err)
	}
	if !u.reload && u.load == "loaded" {
		if u.reload, err = unloadedDropIn(unitDir, u.id, u.dropIns); err != nil {
			return Result{}, fmt.Errorf("read the drop-ins: %w", err)
		}
	}
	fresh, err := s.fresh(u)
	if err != nil {
		return Result{}, err
	}
	switch {
	case u.id == s.Unit():
	case fresh:
		// The new file replaces the alias: a unit that systemd has not loaded.
		u = unitState{id: s.Unit(), load: "not-found"}
	default:
		return Result{}, fmt.Errorf("%s is an alias of %s; use %s", s.Name, u.id, strings.TrimSuffix(u.id, ".service"))
	}
	var files [][]byte
	if fresh || s.Enabled != nil && *s.Enabled && (u.file == "linked" || u.file == "indirect") {
		if files, err = s.files(u, fresh); err != nil {
			return Result{}, err
		}
	}
	if fresh {
		if err := u.fromFiles(files); err != nil {
			return Result{}, err
		}
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
		return Result{}, fmt.Errorf("%s is masked; systemctl unmask %s removes the mask", u.id, u.id)
	default:
		return Result{}, withJournal(ctx, u.id, fmt.Errorf("%s has the load state %q", u.id, u.load))
	}
	if s.Started {
		return Result{Status: OK}, nil
	}
	var startedBy []string
	if (u.load == "loaded" || broken) && len(u.triggeredBy) > 0 && (s.Running != nil && !*s.Running || s.Enabled != nil && !*s.Enabled) {
		startedBy, err = activeOrEnabled(ctx, u.triggeredBy)
		if err != nil {
			return Result{}, err
		}
	}
	// A oneshot unit without RemainAfterExit is up only while its job runs.
	s.up = u.up() && !u.restarting() && (u.typ != "oneshot" || u.remain)
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
		if !*s.Enabled && !fresh && u.file == "enabled" && !strings.Contains(u.id, "@") {
			fi, err := os.Lstat(filepath.Join(unitDir, u.id))
			linked = err == nil && fi.Mode().Type() == fs.ModeSymlink
		}
		switch {
		case missing && !fresh:
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
			if !installs(sectionKeys(files, "Install")) {
				return Result{}, fmt.Errorf("%s has no [Install] section with WantedBy, RequiredBy, UpheldBy, or Alias; enabled: true cannot enable it", u.id)
			}
			s.todo = append(s.todo, "enable")
		default:
			if u.file == "indirect" {
				if in := sectionKeys(files, "Install"); len(in["Also"]) > 0 {
					return Result{}, fmt.Errorf("%s has the unit file state %q; enabled: true cannot enable it; enable the units in its Also=: %s", u.id, u.file, strings.Join(in["Also"], ", "))
				}
			}
			return Result{}, fmt.Errorf("%s has the unit file state %q; enabled: true needs an enabled, disabled, enabled-runtime, or linked unit", u.id, u.file)
		}
	}
	if s.Running != nil {
		if *s.Running && u.typ == "oneshot" && !u.remain {
			return Result{}, fmt.Errorf("%s is a oneshot unit without RemainAfterExit=yes, so it is never running after its job; start its timer, or use cmd", u.id)
		}
		up := u.up()
		// A unit that waits to restart is down, but systemd starts it again
		// unless a stop cancels the restart.
		s.crashed = u.restarting()
		// A unit whose stop job timed out is still stopping; a stop waits
		// for it.
		stopping := u.active == "deactivating"
		switch {
		case *s.Running && (!up || s.crashed):
			s.todo = append(s.todo, "start")
		case !*s.Running && (up || stopping):
			s.todo = append(s.todo, "stop")
		}
	}
	var missingFiles []string
	if s.Running != nil && !*s.Running && !fresh {
		missingFiles, err = s.missingFiles(ctx, u)
		if err != nil {
			return Result{}, err
		}
	}
	if len(s.todo) == 0 {
		return Result{Status: OK, StartedBy: startedBy, MissingUnitFiles: missingFiles}, nil
	}
	started := slices.Contains(s.todo, "start")
	var changes []string
	for _, c := range s.todo {
		changes = append(changes, cmp.Or(planLabels[c], c))
	}
	if missing && (s.Running == nil || *s.Running) {
		changes = append([]string{u.id + " does not exist yet"}, changes...)
	}
	return Result{Status: Change, Action: Modify, Changes: changes, StartedBy: startedBy, MissingUnitFiles: missingFiles, Starts: started}, nil
}

func (s *Service) missingFiles(ctx context.Context, u unitState) ([]string, error) {
	var paths []string
	switch {
	case u.fragment != "":
		paths = []string{u.fragment}
	case u.load == "not-found":
		out, err := run(ctx, nil, "systemctl", "show", "--property=UnitPath", "--value")
		if err != nil {
			return nil, err
		}
		unit, file := s.Unit(), s.UnitFile()
		for _, dir := range strings.Fields(out) {
			paths = append(paths, filepath.Join(dir, unit))
			if file != unit {
				paths = append(paths, filepath.Join(dir, file))
			}
		}
	}
	for _, p := range paths {
		_, err := os.Stat(p)
		switch {
		case err == nil:
			return nil, nil
		case errors.Is(err, fs.ErrNotExist):
		default:
			return nil, fmt.Errorf("stat the unit file: %w", err)
		}
	}
	return paths, nil
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

// Undo returns the step that reverses what a checked step does to the running
// unit: a stop for a start, a start for a stop, and the same step for a
// restart or a reload. The undo of a restart or a reload of a running unit
// also starts it: a failed restart leaves the unit stopped, and a restart
// does nothing to a stopped unit. It returns nil for a step that does none of
// these.
func (s *Service) Undo() *Service {
	switch {
	case slices.Contains(s.todo, "start"):
		no := false
		return &Service{Name: s.Name, Running: &no}
	case slices.Contains(s.todo, "stop"):
		yes := true
		return &Service{Name: s.Name, Running: &yes}
	case s.Restarted, s.Reloaded:
		u := &Service{Name: s.Name, Restarted: s.Restarted, Reloaded: s.Reloaded}
		if s.up {
			yes := true
			u.Running = &yes
		}
		return u
	}
	return nil
}

// planLabels are the plan lines of the commands that differ from the
// command.
var planLabels = map[string]string{"try-restart": "restart", "try-reload-or-restart": "reload"}

func (s *Service) Apply(ctx context.Context, _ Say) error {
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
		// systemd 255 runs the start of a unit that waits to restart only
		// when its restart timer ends.
		if c == "start" && s.crashed {
			args[0] = "restart"
		}
		if c != "daemon-reload" {
			args = append(args, "--", s.Name)
		}
		starts := c == "start" || c == "try-restart" || c == "try-reload-or-restart"
		action := cmp.Or(planLabels[c], c)
		if starts {
			if err := resetFailed(ctx, s.Name); err != nil {
				return err
			}
			// ssh.socket starts ssh.service, whose start limit closes the
			// port of the socket.
			if s.Unit() == "ssh.socket" {
				if err := resetFailed(ctx, "ssh.service"); err != nil {
					return err
				}
			}
		}
		_, err := run(ctx, nil, "systemctl", args...)
		switch {
		case err == nil && starts && (c == "start" || s.up):
			if err := checkStarted(ctx, s.Unit(), action, c == "try-reload-or-restart"); err != nil {
				return err
			}
		case err == nil:
		case starts:
			return withJournal(ctx, s.Name, jobFailed(ctx, s.Unit(), action, err))
		case c == "stop":
			return withJournal(ctx, s.Name, err)
		default:
			return err
		}
	}
	return nil
}

// jobFailed names unit and action in err, the failure of systemctl. systemd
// cancels the job of a unit that ends during its reload, so the error also
// names the state of a unit that is not running.
func jobFailed(ctx context.Context, unit, action string, err error) error {
	u, serr := showUnit(ctx, unit)
	if serr != nil {
		return errors.Join(err, serr)
	}
	if u.up() && !u.restarting() {
		return fmt.Errorf("%s did not %s: %w", unit, action, err)
	}
	return fmt.Errorf("%s is not running after its %s: %s (%s)\n%w", unit, action, u.active, u.sub, err)
}

// resetFailed resets the start counter of unit, so that the start limit of
// systemd cannot block a start that winch needs. A unit that systemd has not
// loaded has no counter, and systemctl fails on it.
func resetFailed(ctx context.Context, unit string) error {
	_, err := run(ctx, nil, "systemctl", "reset-failed", "--", unit)
	if err != nil && strings.Contains(err.Error(), " not loaded.") {
		return nil
	}
	return err
}

// startWatch is how long a unit must keep running after its start. A
// Type=simple unit is active as soon as its process runs, also when the
// process exits a moment later.
const startWatch = 2 * time.Second

// watchTypes are the service types that do not report readiness.
var watchTypes = []string{"simple", "exec", "forking", "idle"}

// checkStarted fails when unit is not running after action. systemctl exits
// 0 also when a Condition failed, and when the unit ended or crashed right
// after its start. A unit whose type does not report readiness must keep
// running for startWatch, unless reload kept its process.
func checkStarted(ctx context.Context, unit, action string, reload bool) error {
	deadline := time.Now().Add(commandLimit)
	u, err := showUnit(ctx, unit)
	invocation := u.invocation
	for err == nil && u.active == "activating" && !u.restarting() && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		u, err = showUnit(ctx, unit)
	}
	if err == nil && u.up() && !u.restarting() && (!reload || !u.canReload) && slices.Contains(watchTypes, u.typ) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(startWatch):
		}
		u, err = showUnit(ctx, unit)
	}
	if err != nil {
		return err
	}
	if u.invocation != invocation {
		return withJournal(ctx, unit, fmt.Errorf("%s restarted after its %s", unit, action))
	}
	if u.up() && !u.restarting() {
		return nil
	}
	ctx, cancel := context.WithTimeoutCause(ctx, commandLimit, noResult(commandLimit))
	defer cancel()
	// systemd-analyze writes the results to stderr.
	cmd := exec.CommandContext(ctx, "systemd-analyze", "condition", "--unit="+unit)
	var res bytes.Buffer
	cmd.Stdout, cmd.Stderr = &res, &res
	err = wait(ctx, cmd, KillDelay)
	if err == nil {
		return withJournal(ctx, unit, fmt.Errorf("%s is not running after its %s: %s (%s)", unit, action, u.active, u.sub))
	}
	failed := failedConditions(unit, res.String())
	if len(failed) == 0 {
		return failure("systemd-analyze condition", err, res.String())
	}
	return fmt.Errorf("%s did not %s: %s failed", unit, action, strings.Join(failed, ", "))
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

// fresh reports whether systemd has not loaded NewFile yet.
func (s *Service) fresh(u unitState) (bool, error) {
	if s.NewFile == nil {
		return false, nil
	}
	if u.reload {
		return true, nil
	}
	p := filepath.Join(unitDir, s.UnitFile())
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, err
	case !fi.Mode().IsRegular():
		return true, nil
	}
	old, err := os.ReadFile(p)
	if err != nil {
		return false, fmt.Errorf("read the unit file: %w", err)
	}
	return !bytes.Equal(old, s.NewFile), nil
}

// files returns the unit file and its drop-ins, in the order that systemd
// reads them. With fresh, the unit file is NewFile.
func (s *Service) files(u unitState, fresh bool) ([][]byte, error) {
	paths := strings.Fields(u.dropIns)
	var files [][]byte
	if fresh {
		files = append(files, s.NewFile)
	} else {
		paths = append([]string{u.fragment}, paths...)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read the unit file: %w", err)
		}
		files = append(files, data)
	}
	return files, nil
}

// fromFiles sets the unit file state and the type that systemd reports after
// it loads files.
func (u *unitState) fromFiles(files [][]byte) error {
	if u.load == "bad-setting" || u.load == "error" {
		u.load = "loaded"
	}
	// systemd looks for enable links before it reads [Install].
	links, err := enableLinks(u.id)
	if err != nil {
		return err
	}
	in := sectionKeys(files, "Install")
	switch {
	case len(links) > 0:
		u.file = "enabled"
	case installs(in):
		u.file = "disabled"
	case len(in["Also"]) > 0:
		u.file = "indirect"
	default:
		u.file = "static"
	}
	if strings.HasSuffix(u.id, ".service") {
		sv := sectionKeys(files, "Service")
		switch typ := sv["Type"]; {
		case len(typ) > 0:
			u.typ = typ[len(typ)-1]
		case len(sv["ExecStart"]) == 0:
			u.typ = "oneshot"
		default:
			u.typ = "simple"
		}
		remain := sv["RemainAfterExit"]
		u.remain = len(remain) > 0 && slices.Contains([]string{"1", "yes", "y", "true", "t", "on"}, strings.ToLower(remain[len(remain)-1]))
	}
	return nil
}

// installs reports whether the [Install] keys let systemctl enable a unit.
func installs(in map[string][]string) bool {
	return len(in["WantedBy"])+len(in["RequiredBy"])+len(in["UpheldBy"])+len(in["Alias"]) > 0
}

// sectionKeys returns the keys of a section of unit files, read in order. A
// value adds its words to the key, and an empty value clears it.
func sectionKeys(files [][]byte, section string) map[string][]string {
	keys := map[string][]string{}
	for _, data := range files {
		var current string
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") {
				current = line
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || current != "["+section+"]" {
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
	return keys
}

type unitState struct {
	id, load, active, sub, file, fragment, dropIns, invocation, typ string
	triggeredBy                                                     []string
	reload, remain, canReload                                       bool
}

func (u unitState) up() bool {
	return u.active == "active" || u.active == "activating" || u.active == "reloading" || u.active == "refreshing"
}

// restarting reports whether the unit waits to restart after a crash.
func (u unitState) restarting() bool {
	return strings.HasPrefix(u.sub, "auto-restart")
}

// showUnit returns the load, active, and sub state of unit, its invocation,
// which changes with each start, its type, and whether it can reload.
func showUnit(ctx context.Context, unit string) (unitState, error) {
	out, err := run(ctx, nil, "systemctl", "show", "--property=Id,LoadState,ActiveState,SubState,InvocationID,Type,CanReload", "--", unit)
	if err != nil {
		return unitState{}, err
	}
	u, err := parseShow(out)
	if err != nil {
		return u, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	return u, nil
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
		case "InvocationID":
			u.invocation = v
		case "UnitFileState":
			u.file = v
		case "FragmentPath":
			u.fragment = v
		case "DropInPaths":
			u.dropIns = v
		case "NeedDaemonReload":
			u.reload = v == "yes"
		case "Type":
			u.typ = v
		case "CanReload":
			u.canReload = v == "yes"
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

// unloadedDropIn reports whether dir holds a drop-in of the unit id that
// systemd has not loaded. systemd 255 does not report a new drop-in
// directory in NeedDaemonReload. A drop-in of the same name from systemctl
// set-property hides the one in dir, and systemd skips a masked drop-in and
// a directory.
func unloadedDropIn(dir, id, loaded string) (bool, error) {
	paths, err := filepath.Glob(filepath.Join(dir, id+".d", "*.conf"))
	if err != nil {
		return false, err
	}
	have := strings.Fields(loaded)
	var hidden []string
	for _, l := range have {
		if strings.Contains(l, "/systemd/system.control/") {
			hidden = append(hidden, filepath.Base(l))
		}
	}
	for _, p := range paths {
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() || slices.Contains(have, p) || slices.Contains(hidden, filepath.Base(p)) {
			continue
		}
		return true, nil
	}
	return false, nil
}
