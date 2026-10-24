package module

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
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
	verb    string
	todo    []string
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

func (p *Pkg) Check(ctx context.Context, st *State) (Result, error) {
	pkgs, err := readDpkg(ctx, p.Name)
	if err != nil {
		return Result{}, err
	}
	var inst []string
	for _, n := range p.Name {
		s := pkgs[n].state
		switch {
		case !p.Absent && s != installed,
			p.Absent && s == installed,
			p.Purge && s == configFiles:
			if pkgs[n].held {
				return Result{}, fmt.Errorf("%s is held; apt-mark unhold %s changes it", n, n)
			}
			p.todo = append(p.todo, n)
		case !p.Absent:
			inst = append(inst, n)
		}
	}
	// apt-mark showauto with no names lists every automatic package.
	if len(inst) > 0 {
		out, err := run(ctx, nil, "apt-mark", append([]string{"showauto"}, inst...)...)
		if err != nil {
			return Result{}, err
		}
		p.auto = strings.Fields(out)
	}
	if len(p.todo) == 0 && len(p.auto) == 0 {
		return Result{Status: OK}, nil
	}
	var changes []string
	action := Modify
	if len(p.todo) > 0 {
		p.verb = "install"
		switch {
		case p.Purge:
			p.verb = "purge"
		case p.Absent:
			p.verb = "remove"
		}
		changes = []string{p.verb + " " + strings.Join(p.todo, ", ")}
		if p.Absent {
			others, err := p.dependents(ctx)
			if err != nil {
				return Result{}, err
			}
			if len(others) > 0 {
				changes = append(changes, "also "+p.verb+" "+strings.Join(others, ", "))
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
	if len(p.auto) > 0 {
		changes = append(changes, "mark "+strings.Join(p.auto, ", ")+" as manually installed")
	}
	return Result{Status: Change, Action: action, Changes: changes}, nil
}

// dependents returns the other packages that apt removes with the step's
// packages.
func (p *Pkg) dependents(ctx context.Context) ([]string, error) {
	out, err := run(ctx, aptEnv, "apt-get", append([]string{"-s", "-q", p.verb}, p.todo...)...)
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

func (p *Pkg) Apply(ctx context.Context) error {
	if len(p.auto) > 0 {
		if _, err := run(ctx, nil, "apt-mark", append([]string{"manual", "-o", aptLock}, p.auto...)...); err != nil {
			return err
		}
	}
	if len(p.todo) == 0 {
		return nil
	}
	if p.refresh {
		if _, err := run(ctx, aptEnv, "apt-get", "update", "-q", "--error-on=any", "-o", aptLock); err != nil {
			return err
		}
	}
	args := []string{p.verb, "-y", "-q", "-o", aptLock,
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
	if p.verb == "install" {
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
	_, err := run(ctx, aptEnv, "apt-get", append(args, p.todo...)...)
	return err
}

type pkgState int

const (
	notInstalled pkgState = iota
	configFiles
	installed
)

type dpkgPkg struct {
	state pkgState
	held  bool
}

// readDpkg holds the locks of apt and dpkg while it reads, so it does not see
// the half-done packages of a running apt.
func readDpkg(ctx context.Context, names []string) (map[string]dpkgPkg, error) {
	for _, name := range []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"} {
		f, err := lockFile(ctx, name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}
	pkgs, err := dpkgStates(ctx, names)
	if err != nil {
		return nil, err
	}
	audit, err := run(ctx, nil, "dpkg", "--audit")
	if err != nil {
		return nil, err
	}
	// dpkg --audit exits 0 also when it lists half-installed packages.
	if strings.TrimSpace(audit) != "" {
		return nil, errors.New("dpkg was interrupted; run dpkg --configure -a")
	}
	return pkgs, nil
}

// lockFile takes the fcntl lock that apt and dpkg use. It waits as long as
// aptLock. Closing the file releases the lock.
func lockFile(ctx context.Context, name string) (*os.File, error) {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o640)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("/var/lib/dpkg not found: the host needs dpkg")
	}
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(300 * time.Second)
	for {
		err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart})
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EACCES) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", name, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("another apt or dpkg run holds %s", name)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// dpkgStates returns each named package that dpkg knows.
func dpkgStates(ctx context.Context, names []string) (map[string]dpkgPkg, error) {
	args := append([]string{"-W", "-f=${Package}\t${db:Status-Abbrev}\n"}, names...)
	out, err := exec.CommandContext(ctx, "dpkg-query", args...).Output()
	// dpkg-query exits 1 when it does not know one of the packages.
	if exit, ok := errors.AsType[*exec.ExitError](err); ok && exit.ExitCode() == 1 && unknownOnly(exit.Stderr) {
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	return parseDpkg(string(out)), nil
}

func unknownOnly(stderr []byte) bool {
	for line := range strings.SplitSeq(strings.TrimSpace(string(stderr)), "\n") {
		if !strings.HasPrefix(line, "dpkg-query: no packages found matching ") {
			return false
		}
	}
	return true
}

// parseDpkg reads lines of a package name and its status abbreviation, such
// as "ii " or "hi ". The first letter is the selection, the second the state
// of the package.
func parseDpkg(out string) map[string]dpkgPkg {
	pkgs := map[string]dpkgPkg{}
	for line := range strings.SplitSeq(out, "\n") {
		name, abbrev, ok := strings.Cut(line, "\t")
		if !ok || len(abbrev) < 2 {
			continue
		}
		s := notInstalled
		switch abbrev[1] {
		case 'i':
			s = installed
		case 'c':
			s = configFiles
		}
		// One line per architecture: the most installed one counts.
		pkg := pkgs[name]
		pkgs[name] = dpkgPkg{state: max(pkg.state, s), held: pkg.held || abbrev[0] == 'h'}
	}
	return pkgs
}
