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
	Name       yamlx.Strings `yaml:"name,required" json:"name" line:"installed in one apt call" doc:"Installed in one apt call."`
	Recommends *bool         `yaml:"recommends" json:"recommends,omitempty" line:"install recommended packages too" doc:"Install recommended packages too." default:"true"`
	Purge      bool          `yaml:"purge" json:"purge,omitempty" line:"remove the config files too" doc:"Remove the config files too. purge needs absent."`
	Absent     bool          `yaml:"absent" json:"absent,omitempty" doc:"Remove the packages."`
	// Removed are the packages that earlier steps of the host remove. The
	// run sets them.
	Removed []string `json:"removed,omitempty"`
	// Installed are the packages that earlier steps of the host install or
	// upgrade. The run sets them for an absent step.
	Installed []string `json:"installed,omitempty"`

	// Check sets these for Apply.
	refresh bool
	todo    []string
	// configure holds half-done packages as name=version. The install of the
	// installed version finishes them and upgrades nothing.
	configure []string
	// auto holds installed packages that apt marked automatic.
	auto []string
	// pkgs are the packages that dpkg knows.
	pkgs map[string]dpkgPkg
}

func (p *Pkg) Main() string { return strings.Join(p.Name, ", ") }

var pkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

func (p *Pkg) Validate() error {
	if len(p.Name) == 0 {
		return &yamlx.FieldError{Field: "name", Msg: "needs at least one package"}
	}
	for i, n := range p.Name {
		switch {
		case !pkgNameRe.MatchString(n):
			return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q is not a package name", n)}
		case strings.HasSuffix(n, "-"):
			return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf(`%q ends in "-", which apt reads as a removal; use absent: true`, n)}
		case slices.Contains(p.Name[:i], n):
			return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%s is in the list twice", n)}
		}
	}
	switch {
	case p.Purge && !p.Absent:
		return &yamlx.FieldError{Field: "purge", Msg: "needs absent: true"}
	case p.Absent && p.Recommends != nil:
		return &yamlx.FieldError{Field: "recommends", Msg: "not with absent: true"}
	}
	return nil
}

var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "APT_LISTBUGS_FRONTEND=none", "UCF_FORCE_CONFFOLD=1", "NEEDRESTART_SUSPEND=1"}

// aptLock makes apt wait for another apt, such as unattended-upgrades.
const aptLock = "DPkg::Lock::Timeout=300"

// aptApply are the flags of an apt-get call that changes packages. It keeps
// changed conffiles and asks no question.
var aptApply = []string{"-y", "-q", "-o", aptLock, "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}

// aptSolver picks apt's classic solver. The solver of apt 3.1 and later
// ignores APT::Ignore-Hold, and fills a dependency that a removal breaks with
// an install, where the classic solver removes the dependent package.
const aptSolver = "APT::Solver=internal"

// aptGet runs apt-get without the time limit. An apt-get that the limit stops
// leaves dpkg half done.
func aptGet(ctx context.Context, args ...string) (string, error) {
	return runLimited(ctx, 0, KillDelay, aptEnv, "", "apt-get", slices.Concat(args, []string{"-o", aptSolver})...)
}

func (p *Pkg) Check(ctx context.Context, st *State, say Say) (Result, error) {
	pkgs, err := readDpkg(ctx, say.Progress)
	if err != nil {
		return Result{}, err
	}
	p.pkgs = pkgs
	var missing []string
	for _, n := range p.Name {
		if pkg := pkgs[n]; pkg.state != installed && pkg.half == 0 {
			missing = append(missing, n)
		}
	}
	providers, foreign, known, err := showpkg(ctx, missing)
	if err != nil {
		return Result{}, err
	}
	// An install of an unknown name plans as known after the refresh: a repo
	// step earlier in the run can add the name.
	var unknown []string
	for _, n := range missing {
		if _, ok := pkgs[n]; p.Absent && !ok && !known[n] && foreign[n] == "" && len(providers[n]) == 0 {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		entries, err := os.ReadDir(filepath.Dir(indexLock))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return Result{}, fmt.Errorf("read package index: %w", err)
		}
		if slices.ContainsFunc(entries, func(e os.DirEntry) bool {
			return !e.IsDir() && strings.Contains(e.Name(), "_Packages")
		}) {
			for _, n := range unknown {
				say.Note("apt does not know " + n)
			}
		}
	}
	names := slices.Clone(p.Name)
	for i, n := range names {
		if _, ok := pkgs[n]; !ok && foreign[n] != "" {
			names[i] = foreign[n]
		}
	}
	if err := othersHalfDone(pkgs, names); err != nil {
		return Result{}, err
	}
	var inst, conf []string
	for _, n := range names {
		pkg := pkgs[n]
		switch {
		case !p.Absent && pkg.half != 0:
			conf = append(conf, n)
			p.configure = append(p.configure, n+"="+pkg.version)
		case !p.Absent && pkg.state != installed,
			p.Absent && (pkg.state == installed || pkg.half != 0),
			p.Purge && pkg.state == configFiles:
			if pkg.held {
				return Result{}, fmt.Errorf("%s is held; apt-mark unhold %s removes the hold", n, n)
			}
			p.todo = append(p.todo, n)
		case !p.Absent:
			inst = append(inst, n)
		}
	}
	if p.Absent {
		for n, ps := range providers {
			providers[n] = slices.DeleteFunc(ps, func(q string) bool { return pkgs[q].state != installed && pkgs[q].half == 0 })
		}
		if err := providedOnly(missing, providers); err != nil {
			return Result{}, err
		}
	} else {
		mayBeProvided(missing, providers, say.Note)
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
			out, err := p.simulate(ctx, say.Progress)
			if err != nil {
				return Result{}, err
			}
			others := parseRemovals(out, p.todo)
			if err := checkAccess(slices.Concat(p.todo, others), st.LoginUID); err != nil {
				return Result{}, err
			}
			if len(others) > 0 {
				changes = append(changes, "also "+p.verb()+" "+strings.Join(others, ", "))
			}
			return Result{Status: Change, Action: Remove, Changes: changes}, nil
		}
		if p.Recommends != nil && !*p.Recommends {
			changes[0] += noRecommends
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
	switch {
	case slices.ContainsFunc(p.todo, func(n string) bool { return !known[n] }):
		changes = append(changes, OthersUnknown)
	case len(p.todo) > 0 || len(p.configure) > 0:
		others, err := p.others(ctx, say.Progress)
		if err != nil {
			return Result{}, err
		}
		changes = append(changes, others...)
	}
	if len(p.auto) > 0 {
		changes = append(changes, "mark "+strings.Join(p.auto, ", ")+" as manually installed")
	}
	return Result{Status: Change, Action: action, Changes: changes}, nil
}

const noRecommends = " (without recommended packages)"

// OthersUnknown is the plan line of an install whose other packages the
// package index does not know yet.
const OthersUnknown = "other packages: known after the refresh"

// PkgPlan reads the plan lines of a pkg change. installs are the packages
// that the step installs or configures in this run, also as dependencies. A
// configure runs the package's scripts. others are the
// other packages that apt installs, upgrades, or removes with the step's
// packages.
func PkgPlan(changes []string) (installs, others []string) {
	for _, c := range changes {
		verb, list, _ := strings.Cut(strings.TrimSuffix(c, noRecommends), " ")
		also := verb == "also"
		if also {
			verb, list, _ = strings.Cut(list, " ")
		}
		names := strings.Split(list, ", ")
		switch {
		case also && verb == "install":
			installs = append(installs, names...)
			others = append(others, names...)
		case also && (verb == "upgrade" || verb == "remove" || verb == "purge"):
			others = append(others, names...)
		case verb == "install" || verb == "configure":
			installs = append(installs, names...)
		}
	}
	return installs, others
}

// showpkg reads the package index for names. providers holds the sorted
// native providers of each name that has no version of its own. apt takes a
// name without a package of the native architecture or all as the foreign
// package that it knows, and foreign maps such a name to that package. known
// holds the packages that the package index has a version of.
func showpkg(ctx context.Context, names []string) (providers map[string][]string, foreign map[string]string, known map[string]bool, err error) {
	if len(names) == 0 {
		return nil, nil, nil, nil
	}
	out, err := run(ctx, nil, "apt-cache", append([]string{"showpkg"}, names...)...)
	if err != nil {
		return nil, nil, nil, err
	}
	providers, foreign, known = parseShowpkg(out)
	return providers, foreign, known, nil
}

// mayBeProvided notes each name that apt knows only as provided by other
// packages. An old index can miss a real package of the name, so apply checks
// them after the refresh.
func mayBeProvided(names []string, providers map[string][]string, note func(string)) {
	for _, n := range names {
		if ps := providers[n]; len(ps) > 0 {
			note(n + " may be provided by " + strings.Join(ps, ", ") + "; apply checks it after the refresh")
		}
	}
}

// providedOnly fails on each name that apt knows only as provided by other
// packages. apt installs a sole provider under its own name, so the step never
// converges, and fails when there are several.
func providedOnly(names []string, providers map[string][]string) error {
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

// parseShowpkg reads the output of apt-cache showpkg. It returns the providers,
// the foreign packages, and the known packages of showpkg.
func parseShowpkg(out string) (providers map[string][]string, foreign map[string]string, known map[string]bool) {
	providers, foreign, known = map[string][]string{}, map[string]string{}, map[string]bool{}
	var name, section string
	hasVersion := false
	for line := range strings.SplitSeq(out, "\n") {
		if n, ok := strings.CutPrefix(line, "Package: "); ok {
			name, section, hasVersion = n, "", false
			if bare, _, ok := strings.Cut(n, ":"); ok {
				foreign[bare] = n
			}
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
			// The status file of dpkg has no candidate to install.
			if strings.Contains(strings.ReplaceAll(line, "(/var/lib/dpkg/status)", ""), "(") {
				known[name] = true
			}
		// A step names packages of the native architecture, which have no
		// :arch suffix.
		case name != "" && section == "Reverse Provides:" && !hasVersion && !strings.Contains(f[0], ":"):
			providers[name] = append(providers[name], f[0])
		}
	}
	for n, ps := range providers {
		slices.Sort(ps)
		providers[n] = slices.Compact(ps)
	}
	return providers, foreign, known
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

// candidateStanzas returns the package stanzas of the candidate versions of
// the names that the package index knows.
func candidateStanzas(ctx context.Context, names []string) (string, error) {
	_, _, known, err := showpkg(ctx, names)
	if err != nil {
		return "", err
	}
	var show []string
	for _, n := range names {
		if known[n] {
			show = append(show, n)
		}
	}
	if len(show) == 0 {
		return "", nil
	}
	return run(ctx, nil, "apt-cache", append([]string{"show", "--no-all-versions"}, show...)...)
}

// writeStatus writes a copy of the dpkg status file with the candidates
// installed and the removed packages gone, and returns its path.
func writeStatus(candidates string, removed []string) (string, error) {
	status, err := os.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return "", fmt.Errorf("read dpkg status: %w", err)
	}
	f, err := os.CreateTemp("", "winch-status-")
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(installStanzas(string(status), candidates, removed))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write dpkg status: %w", err)
	}
	return f.Name(), nil
}

// installStanzas returns the dpkg status with the package stanzas of
// candidates as installed. They replace the stanzas of the same package and
// architecture. The stanzas of the removed packages, as name or name:arch,
// are left out.
func installStanzas(status, candidates string, removed []string) string {
	fields := func(stanza string) (name, arch string) {
		s := stanzas(stanza)
		if len(s) == 0 {
			return "", ""
		}
		return s[0]["package"], s[0]["architecture"]
	}
	var added []string
	keys := map[string]bool{}
	for c := range strings.SplitSeq(candidates, "\n\n") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		var lines []string
		for line := range strings.SplitSeq(c, "\n") {
			if !strings.HasPrefix(line, "Status:") {
				lines = append(lines, line)
			}
		}
		added = append(added, strings.Join(append(lines, "Status: install ok installed"), "\n"))
		name, arch := fields(c)
		keys[name+":"+arch] = true
	}
	var kept []string
	for st := range strings.SplitSeq(status, "\n\n") {
		if st = strings.TrimSpace(st); st == "" {
			continue
		}
		name, arch := fields(st)
		if !keys[name+":"+arch] && !slices.Contains(removed, name) && !slices.Contains(removed, name+":"+arch) {
			kept = append(kept, st)
		}
	}
	return strings.Join(slices.Concat(kept, added), "\n\n") + "\n"
}

func parseRemovals(out string, own []string) []string {
	var others []string
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (f[0] == "Remv" || f[0] == "Purg") && !slices.Contains(own, f[1]) {
			others = append(others, f[1])
		}
	}
	return others
}

// simulate runs the apt-get call of the step with -s. It holds the package
// locks, so it does not see the half-done packages of a running apt. apt reads
// a copy of the dpkg status in which p.Installed are installed and p.Removed
// are gone.
func (p *Pkg) simulate(ctx context.Context, progress func(string), flags ...string) (string, error) {
	// The copy has no stanza for a package that an earlier step removes, and
	// apt fails on a name that neither the copy nor the index has.
	todo := slices.DeleteFunc(slices.Clone(p.todo), func(n string) bool { return slices.Contains(p.Removed, n) })
	if len(todo) == 0 && len(p.configure) == 0 {
		return "", nil
	}
	candidates, err := candidateStanzas(ctx, p.Installed)
	if err != nil {
		return "", err
	}
	unlock, err := lockFiles(ctx, dpkgLocks, progress)
	if err != nil {
		return "", err
	}
	defer unlock()
	args := slices.Concat([]string{"-s", "-q", p.verb()}, flags)
	if candidates != "" || len(p.Removed) > 0 {
		status, err := writeStatus(candidates, p.Removed)
		if err != nil {
			return "", err
		}
		defer os.Remove(status)
		args = append(args, "-o", "Dir::State::status="+status)
	}
	return aptGet(ctx, slices.Concat(args, todo, p.configure)...)
}

// others returns the plan lines of the other packages that apt installs or
// upgrades with the step's packages. A held one fails.
func (p *Pkg) others(ctx context.Context, progress func(string)) ([]string, error) {
	// apt does not upgrade a held package and fails without its name.
	out, err := p.simulate(ctx, progress, append(p.installFlags(), "--remove", "-o", "APT::Ignore-Hold=true")...)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, n := range parseRemovals(out, nil) {
		if strings.Contains(n, ":") {
			errs = append(errs, fmt.Errorf("apt must remove %s; apt-get remove %s removes it", n, n))
		} else {
			errs = append(errs, fmt.Errorf("apt must remove %s; add a pkg step with name: %s and absent: true before this step", n, n))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	own := slices.Clone(p.todo)
	for _, c := range p.configure {
		n, _, _ := strings.Cut(c, "=")
		own = append(own, n)
	}
	installs, upgrades := parseSimulation(out, own)
	for _, n := range slices.Concat(installs, upgrades) {
		if p.pkgs[n].held {
			errs = append(errs, fmt.Errorf("%s is held; apt-mark unhold %s removes the hold", n, n))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	var lines []string
	if len(installs) > 0 {
		lines = append(lines, "also install "+strings.Join(installs, ", "))
	}
	if len(upgrades) > 0 {
		lines = append(lines, "also upgrade "+strings.Join(upgrades, ", "))
	}
	return lines, nil
}

// parseSimulation reads the output of apt-get -s install. It returns the
// packages that are not in own and that apt installs or upgrades.
func parseSimulation(out string, own []string) (installs, upgrades []string) {
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "Inst" || slices.Contains(own, f[1]) {
			continue
		}
		// An upgrade shows the installed version in brackets.
		if strings.HasPrefix(f[2], "[") {
			upgrades = append(upgrades, f[1])
		} else {
			installs = append(installs, f[1])
		}
	}
	return installs, upgrades
}

// installFlags are the flags of an install that change what apt installs.
func (p *Pkg) installFlags() []string {
	if p.Recommends != nil && !*p.Recommends {
		return []string{"--no-install-recommends"}
	}
	return []string{"--install-recommends"}
}

func (p *Pkg) Apply(ctx context.Context, say Say) error {
	if len(p.auto) > 0 {
		if err := waitLocks(ctx, dpkgLocks, say.Progress); err != nil {
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
		if err := waitIndexLock(ctx, say.Progress); err != nil {
			return err
		}
		if _, err := aptGet(ctx, "update", "-q", "--error-on=any"); err != nil {
			return err
		}
	}
	// The index of the check can be older than a refresh of this run, or
	// empty, as on a new host.
	if !p.Absent {
		providers, _, _, err := showpkg(ctx, p.todo)
		if err != nil {
			return err
		}
		if err := providedOnly(p.todo, providers); err != nil {
			return err
		}
	}
	// The check before the refresh read the old index.
	if p.refresh {
		if _, err := p.others(ctx, say.Progress); err != nil {
			return err
		}
	}
	args := append([]string{p.verb()}, aptApply...)
	if p.verb() == "install" {
		args = append(args, append(p.installFlags(), "--no-remove")...)
	}
	if err := waitLocks(ctx, dpkgLocks, say.Progress); err != nil {
		return err
	}
	_, err := aptGet(ctx, slices.Concat(args, p.todo, p.configure)...)
	return err
}

// waitIndexLock waits until no other apt run holds the lock of the package
// index. apt-get update does not wait for it. It creates a missing index
// directory, where no other run holds the lock.
func waitIndexLock(ctx context.Context, progress func(string)) error {
	_, err := os.Stat(filepath.Dir(indexLock))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return waitLocks(ctx, []string{indexLock}, progress)
}

// waitLocks waits until no other apt or dpkg run holds the locks. apt waits
// for the dpkg locks too, but prints nothing while it waits.
func waitLocks(ctx context.Context, names []string, progress func(string)) error {
	unlock, err := lockFiles(ctx, names, progress)
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
func readDpkg(ctx context.Context, progress func(string)) (map[string]dpkgPkg, error) {
	native, err := run(ctx, nil, "dpkg", "--print-architecture")
	if err != nil {
		return nil, err
	}
	unlock, err := lockFiles(ctx, dpkgLocks, progress)
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
	out, err := run(ctx, nil, "dpkg-query", "-W", "-f=${Package}\t${Architecture}\t${db:Status-Abbrev}\t${Version}\n", "*")
	if err != nil {
		return nil, err
	}
	pkgs, err := parseDpkg(out, strings.TrimSpace(native))
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	return pkgs, nil
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
// them, and tells progress the first process that it waits for. unlock
// releases the locks.
func lockFiles(ctx context.Context, names []string, progress func(string)) (unlock func(), err error) {
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
			return nil, fmt.Errorf("%s does not exist; pkg steps need apt and dpkg", filepath.Dir(name))
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
				progress("waiting for " + holder)
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

// parseDpkg reads lines of a package name, its architecture, its status
// abbreviation, such as "ii " or "hi ", and its version. The first letter is
// the selection, the second the state of the package.
func parseDpkg(out, native string) (map[string]dpkgPkg, error) {
	if out == "" {
		return nil, errors.New("no packages in the output")
	}
	pkgs := map[string]dpkgPkg{}
	for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || len(f[2]) != 3 {
			return nil, fmt.Errorf("unexpected line %q", line)
		}
		name, abbrev, version := f[0], f[2], f[3]
		// A step names packages of the native architecture or all. A foreign
		// package keeps the :arch suffix, as apt names it. A package that was
		// never installed can have no architecture.
		if arch := f[1]; arch != native && arch != "all" && arch != "" {
			name += ":" + arch
		}
		s := notInstalled
		switch abbrev[1] {
		case 'i':
			s = installed
		case 'c':
			s = configFiles
		}
		// The lines of the native architecture and all merge: the most
		// installed one counts, and a half-done one makes the package half
		// done.
		pkg := pkgs[name]
		pkg.state = max(pkg.state, s)
		pkg.held = pkg.held || abbrev[0] == 'h'
		if _, ok := halfDoneReasons[abbrev[1]]; ok && pkg.half == 0 {
			pkg.half, pkg.version = abbrev[1], version
		}
		pkgs[name] = pkg
	}
	return pkgs, nil
}

// cutsOff fails a removal of the SSH server or of a package that ships one of
// paths. info is the info directory of dpkg.
func cutsOff(removed, paths []string, info fs.FS) error {
	for _, n := range removed {
		base, _, _ := strings.Cut(n, ":")
		if base == "openssh-server" {
			return errors.New("this cuts off winch's access")
		}
		data, err := fs.ReadFile(info, n+".list")
		if errors.Is(err, fs.ErrNotExist) && base != n {
			data, err = fs.ReadFile(info, base+".list")
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("check winch's access: %w", err)
		}
		for line := range strings.Lines(string(data)) {
			if slices.Contains(paths, strings.TrimSuffix(line, "\n")) {
				return errors.New("this cuts off winch's access")
			}
		}
	}
	return nil
}

// accessPaths returns the files that the session of the login user uid needs:
// sudo for a login user other than root, and the login shell. Each comes as
// its path, the file that resolve finds through its links, and the twin of
// each on a merged /usr, where dpkg lists the path that the package ships.
func accessPaths(uid uint32, a accounts, resolve func(string) (string, error)) []string {
	var need []string
	if uid != 0 {
		need = append(need, "/usr/bin/sudo")
	}
	if login, ok := a.userByID(uid); ok && login.shell != "" {
		need = append(need, login.shell)
	}
	var paths []string
	for _, p := range need {
		files := []string{p}
		if r, err := resolve(p); err == nil && r != p {
			files = append(files, r)
		}
		for _, f := range files {
			twin, ok := strings.CutPrefix(f, "/usr")
			if !ok {
				twin = "/usr" + f
			}
			paths = append(paths, f, twin)
		}
	}
	return paths
}

func checkAccess(removed []string, uid uint32) error {
	if len(removed) == 0 {
		return nil
	}
	a, err := readAccounts()
	if err != nil {
		return fmt.Errorf("check winch's access: %w", err)
	}
	return cutsOff(removed, accessPaths(uid, a, filepath.EvalSymlinks), os.DirFS(dpkgInfo))
}
