package module

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"regexp"
	"slices"
	"strings"

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
	states, err := dpkgStates(ctx, p.Name)
	if err != nil {
		return Result{}, err
	}
	for _, n := range p.Name {
		s := states[n]
		switch {
		case !p.Absent && s != installed,
			p.Absent && s >= partial,
			p.Purge && s == configFiles:
			p.todo = append(p.todo, n)
		}
	}
	if len(p.todo) == 0 {
		return Result{Status: OK}, nil
	}
	p.verb = "install"
	switch {
	case p.Purge:
		p.verb = "purge"
	case p.Absent:
		p.verb = "remove"
	}
	changes := []string{p.verb + " " + strings.Join(p.todo, ", ")}
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
	return Result{Status: Change, Action: Create, Changes: changes}, nil
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
	if p.refresh {
		if _, err := run(ctx, aptEnv, "apt-get", "update", "-q", "-o", aptLock); err != nil {
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
	// partial is a package that dpkg did not finish to unpack or configure.
	partial
	installed
)

// dpkgStates returns the state of each named package that dpkg knows.
func dpkgStates(ctx context.Context, names []string) (map[string]pkgState, error) {
	args := append([]string{"-W", "-f=${Package}\t${db:Status-Abbrev}\n"}, names...)
	out, err := exec.CommandContext(ctx, "dpkg-query", args...).Output()
	// dpkg-query exits 1 when it does not know one of the packages.
	if exit, ok := errors.AsType[*exec.ExitError](err); ok && exit.ExitCode() == 1 && unknownOnly(exit.Stderr) {
		err = nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("dpkg-query not found: the host needs dpkg")
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
// as "ii " or "rc ". The second letter is the state of the package.
func parseDpkg(out string) map[string]pkgState {
	states := map[string]pkgState{}
	for line := range strings.SplitSeq(out, "\n") {
		name, abbrev, ok := strings.Cut(line, "\t")
		if !ok || len(abbrev) < 2 {
			continue
		}
		s := notInstalled
		switch abbrev[1] {
		case 'i', 'W', 't':
			s = installed
		case 'U', 'F', 'H':
			s = partial
		case 'c':
			s = configFiles
		}
		// One line per architecture: the most installed one counts.
		states[name] = max(states[name], s)
	}
	return states
}
