package module

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Pkg struct {
	Name       yamlx.Strings `yaml:"name,required" json:"name"`
	Recommends *bool         `yaml:"recommends" json:"recommends,omitempty"`
	Purge      bool          `yaml:"purge" json:"purge,omitempty"`
	Absent     bool          `yaml:"absent" json:"absent,omitempty"`

	// Check sets these for Apply.
	refresh bool
	todo    []string
	// configure holds half-done packages as name=version. The install of the
	// installed version finishes them and upgrades nothing.
	configure []string
	// auto holds installed packages that apt marked automatic.
	auto []string
}

func (p *Pkg) Main() string { return strings.Join(p.Name, ", ") }

var pkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

func (p *Pkg) Validate() error {
	if len(p.Name) == 0 {
		return &yamlx.FieldError{Field: "name", Msg: "needs at least one package"}
	}
	for _, n := range p.Name {
		if !pkgNameRe.MatchString(n) {
			return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q is not a package name", n)}
		}
	}
	switch {
	case p.Purge && !p.Absent:
		return &yamlx.FieldError{Field: "purge", Msg: "purge: true needs absent: true"}
	case p.Absent && p.Recommends != nil:
		return &yamlx.FieldError{Field: "recommends", Msg: "absent: true takes no recommends"}
	}
	return nil
}

var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive"}

// aptLock makes apt wait for another apt, such as unattended-upgrades.
const aptLock = "DPkg::Lock::Timeout=300"

func (p *Pkg) Check(ctx context.Context, st *State, note func(string)) (Result, error) {
	pkgs, err := readDpkg(ctx, note)
	if err != nil {
		return Result{}, err
	}
	if err := othersHalfDone(pkgs, p.Name); err != nil {
		return Result{}, err
	}
	var inst, conf, missing []string
	for _, n := range p.Name {
		pkg := pkgs[n]
		if pkg.state != installed && pkg.half == 0 {
			missing = append(missing, n)
		}
		switch {
		case !p.Absent && pkg.half != 0:
			conf = append(conf, n)
			p.configure = append(p.configure, n+"="+pkg.version)
		case !p.Absent && pkg.state != installed,
			p.Absent && (pkg.state == installed || pkg.half != 0),
			p.Purge && pkg.state == configFiles:
			if pkg.held {
				return Result{}, fmt.Errorf("%s is held; apt-mark unhold %s changes it", n, n)
			}
			p.todo = append(p.todo, n)
		case !p.Absent:
			inst = append(inst, n)
		}
	}
	if err := providedOnly(ctx, missing); err != nil {
		return Result{}, err
	}
	// apt-mark showauto with no names lists every automatic package.
	if len(inst) > 0 {
		out, err := run(ctx, nil, "apt-mark", append([]string{"showauto"}, inst...)...)
		if err != nil {
			return Result{}, err
		}
		p.auto = strings.Fields(out)
	}
	if len(p.todo) == 0 && len(p.configure) == 0 && len(p.auto) == 0 {
		return Result{Status: OK}, nil
	}
	var changes []string
	action := Modify
	if len(p.todo) > 0 {
		changes = []string{p.verb() + " " + strings.Join(p.todo, ", ")}
		if p.Absent {
			others, err := p.dependents(ctx)
			if err != nil {
				return Result{}, err
			}
			if len(others) > 0 {
				changes = append(changes, "also "+p.verb()+" "+strings.Join(others, ", "))
			}
			return Result{Status: Change, Action: Remove, Changes: changes}, nil
		}
		if p.Recommends != nil && !*p.Recommends {
			changes[0] += " (without recommended packages)"
		}
		p.refresh = !st.IndexFresh
		st.IndexFresh = true
		if p.refresh {
			changes = append([]string{"refresh the package index"}, changes...)
		}
		action = Create
	}
	if len(conf) > 0 {
		changes = append(changes, "configure "+strings.Join(conf, ", "))
	}
	if len(p.auto) > 0 {
		changes = append(changes, "mark "+strings.Join(p.auto, ", ")+" as manually installed")
	}
	return Result{Status: Change, Action: action, Changes: changes}, nil
}

// providedOnly fails on each name that apt knows only as provided by other
// packages. apt installs a sole provider under its own name, so the step never
// converges, and fails when there are several.
func providedOnly(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	out, err := run(ctx, nil, "apt-cache", append([]string{"showpkg"}, names...)...)
	if err != nil {
		return err
	}
	providers := parseShowpkg(out)
	var errs []error
	for _, n := range names {
		switch ps := providers[n]; len(ps) {
		case 0:
		case 1:
			errs = append(errs, fmt.Errorf("%s is provided by %s; name that package", n, ps[0]))
		default:
			errs = append(errs, fmt.Errorf("%s is provided by %s; name one of them", n, strings.Join(ps, ", ")))
		}
	}
	return errors.Join(errs...)
}

// parseShowpkg returns the sorted native providers of each package in the
// output of apt-cache showpkg that has no version of its own.
func parseShowpkg(out string) map[string][]string {
	providers := map[string][]string{}
	var name, section string
	hasVersion := false
	for line := range strings.SplitSeq(out, "\n") {
		if n, ok := strings.CutPrefix(line, "Package: "); ok {
			name, section, hasVersion = n, "", false
			continue
		}
		switch strings.TrimSpace(line) {
		case "Versions:", "Reverse Depends:", "Dependencies:", "Provides:", "Reverse Provides:":
			section = strings.TrimSpace(line)
			continue
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case section == "Versions:" && !strings.HasPrefix(line, " "):
			hasVersion = true
		// A step names packages of the native architecture, which have no
		// :arch suffix.
		case section == "Reverse Provides:" && !hasVersion && !strings.Contains(f[0], ":"):
			providers[name] = append(providers[name], f[0])
		}
	}
	for n, ps := range providers {
		slices.Sort(ps)
		providers[n] = slices.Compact(ps)
	}
	return providers
}

func (p *Pkg) verb() string {
	switch {
	case p.Purge:
		return "purge"
	case p.Absent:
		return "remove"
	}
	return "install"
}

// dependents returns the other packages that apt removes with the step's
// packages.
func (p *Pkg) dependents(ctx context.Context) ([]string, error) {
	out, err := run(ctx, aptEnv, "apt-get", append([]string{"-s", "-q", p.verb()}, p.todo...)...)
	if err != nil {
		return nil, err
	}
	var others []string
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (f[0] == "Remv" || f[0] == "Purg") && !slices.Contains(p.todo, f[1]) {
			others = append(others, f[1])
		}
	}
	return others, nil
}

func (p *Pkg) Apply(ctx context.Context, note func(string)) error {
	if len(p.auto) > 0 {
		if err := waitLocks(ctx, dpkgLocks, note); err != nil {
			return err
		}
		if _, err := run(ctx, nil, "apt-mark", append([]string{"manual", "-o", aptLock}, p.auto...)...); err != nil {
			return err
		}
	}
	if len(p.todo) == 0 && len(p.configure) == 0 {
		return nil
	}
	if p.refresh {
		// apt-get update does not wait for the index lock.
		if err := waitLocks(ctx, []string{indexLock}, note); err != nil {
			return err
		}
		if _, err := run(ctx, aptEnv, "apt-get", "update", "-q", "--error-on=any"); err != nil {
			return err
		}
	}
	args := []string{p.verb(), "-y", "-q", "-o", aptLock,
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
	if p.verb() == "install" {
		// An install that would remove a conflicting package fails.
		args = append(args, "--no-remove")
		switch {
		case p.Recommends == nil:
		case *p.Recommends:
			args = append(args, "--install-recommends")
		default:
			args = append(args, "--no-install-recommends")
		}
	}
	if err := waitLocks(ctx, dpkgLocks, note); err != nil {
		return err
	}
	_, err := run(ctx, aptEnv, "apt-get", slices.Concat(args, p.todo, p.configure)...)
	return err
}

// waitLocks waits until no other apt or dpkg run holds the locks. apt waits
// for the dpkg locks too, but prints nothing while it waits.
func waitLocks(ctx context.Context, names []string, note func(string)) error {
	unlock, err := lockFiles(ctx, names, note)
	if err != nil {
		return err
	}
	unlock()
	return nil
}

type pkgState int

const (
	notInstalled pkgState = iota
	configFiles
	installed
)

// halfDoneReasons maps the dpkg states of a package that dpkg did not fully
// install or configure to the reason.
var halfDoneReasons = map[byte]string{
	'H': "half installed: its installation failed",
	'U': "unpacked: its configuration did not run",
	'F': "half configured: its configuration failed",
	'W': "awaiting triggers: the trigger processing of another package did not run",
	't': "triggered: its trigger processing did not run",
}

type dpkgPkg struct {
	state pkgState
	held  bool
	// half is the dpkg state of a half-done package, or 0.
	half byte
	// version is the version of a half-done package.
	version string
}

// dpkgLocks are the fcntl locks that apt and dpkg use.
var dpkgLocks = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"}

// indexLock is the fcntl lock of the package index.
const indexLock = "/var/lib/apt/lists/lock"

// readDpkg returns every package that dpkg knows. It holds the locks of apt
// and dpkg while it reads, so it does not see the half-done packages of a
// running apt.
func readDpkg(ctx context.Context, note func(string)) (map[string]dpkgPkg, error) {
	unlock, err := lockFiles(ctx, dpkgLocks, note)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// Without a pattern, dpkg-query skips the packages that are not installed,
	// also held ones.
	// apt refuses to run while dpkg has journal entries that it did not merge.
	journal, err := os.ReadDir("/var/lib/dpkg/updates")
	if err != nil {
		return nil, err
	}
	for _, e := range journal {
		if strings.Trim(e.Name(), "0123456789") == "" {
			return nil, errors.New("dpkg was interrupted; run dpkg --configure -a")
		}
	}
	out, err := run(ctx, nil, "dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n", "*")
	if err != nil {
		return nil, err
	}
	return parseDpkg(out), nil
}

// othersHalfDone fails on each half-done package that names does not hold.
func othersHalfDone(pkgs map[string]dpkgPkg, names []string) error {
	var others []string
	for n, pkg := range pkgs {
		if pkg.half != 0 && !slices.Contains(names, n) {
			others = append(others, n)
		}
	}
	slices.Sort(others)
	var errs []error
	for _, n := range others {
		half := pkgs[n].half
		hint := "dpkg --configure -a"
		if half == 'H' {
			hint = "apt-get install --reinstall " + n
		}
		errs = append(errs, fmt.Errorf("%s is %s; fix the cause, then run %s", n, halfDoneReasons[half], hint))
	}
	return errors.Join(errs...)
}

// lockFiles takes fcntl locks in order. It waits as long as aptLock for all of
// them, and notes the first process that it waits for. unlock releases the
// locks.
func lockFiles(ctx context.Context, names []string, note func(string)) (unlock func(), err error) {
	var files []*os.File
	release := func() {
		for _, f := range files {
			f.Close()
		}
	}
	defer func() {
		if err != nil {
			release()
		}
	}()
	deadline := time.Now().Add(300 * time.Second)
	holder := ""
	for _, name := range names {
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o640)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s not found: the host needs apt and dpkg", filepath.Dir(name))
		}
		if err != nil {
			return nil, err
		}
		files = append(files, f)
		for {
			err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart})
			if err == nil {
				break
			}
			if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EACCES) {
				return nil, fmt.Errorf("lock %s: %w", name, err)
			}
			if holder == "" {
				lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
				if err := syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk); err != nil {
					return nil, fmt.Errorf("lock %s: %w", name, err)
				}
				// The holder can release the lock between the two calls.
				if lk.Type == syscall.F_UNLCK {
					continue
				}
				holder = fmt.Sprintf("another apt run (pid %d)", lk.Pid)
				note("waiting for " + holder)
			}
			if time.Now().After(deadline) {
				return nil, errors.New(holder + " held the package locks for 5 minutes")
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	return release, nil
}

// parseDpkg reads lines of a package name, its status abbreviation, such as
// "ii " or "hi ", and its version. The first letter is the selection, the
// second the state of the package.
func parseDpkg(out string) map[string]dpkgPkg {
	pkgs := map[string]dpkgPkg{}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || len(f[1]) < 2 {
			continue
		}
		name, abbrev := f[0], f[1]
		s := notInstalled
		switch abbrev[1] {
		case 'i':
			s = installed
		case 'c':
			s = configFiles
		}
		// One line per architecture: the most installed one counts, and a
		// half-done one makes the package half done.
		pkg := pkgs[name]
		pkg.state = max(pkg.state, s)
		pkg.held = pkg.held || abbrev[0] == 'h'
		if _, ok := halfDoneReasons[abbrev[1]]; ok && pkg.half == 0 {
			pkg.half, pkg.version = abbrev[1], f[2]
		}
		pkgs[name] = pkg
	}
	return pkgs
}
