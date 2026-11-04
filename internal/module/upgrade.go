package module

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Upgrade struct {
	Mode string `yaml:"mode,required" json:"mode" line:"safe or full" doc:"Safe or full. safe installs the upgrades that remove no package. full also installs the upgrades that add or remove packages."`
}

func (*Upgrade) Noun() string { return "an upgrade step" }

func (u *Upgrade) Main() string { return u.Mode }

func (u *Upgrade) Validate() error {
	if u.Mode != "safe" && u.Mode != "full" {
		return &yamlx.FieldError{Field: "mode", Msg: fmt.Sprintf("must be safe or full, not %q", u.Mode)}
	}
	return nil
}

// args are the apt-get arguments of the upgrade. safe removes no package.
func (u *Upgrade) args() []string {
	if u.Mode == "safe" {
		return []string{"upgrade", "--with-new-pkgs"}
	}
	return []string{"dist-upgrade"}
}

// winchLists is winch's package index. Its refresh leaves apt's own index as
// it is.
const winchLists = aptDir + "/lists"

// winchIndex are the apt flags that read winch's index. Without binary
// caches, apt writes no cache of that index into /var/cache/apt. apt fetches
// as root: the user _apt cannot enter the state directory, and apt gives the
// directories of the index to its sandbox user, which the check of the state
// directory rejects.
var winchIndex = []string{"-o", "Dir::State::Lists=" + winchLists, "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "-o", "APT::Sandbox::User=root"}

// plannedIndex are the apt flags that read winch's index of the planned
// sources. The refresh keeps the lists of the sources that the run changes,
// which an upgrade before the change reads at apply.
var plannedIndex = slices.Concat(winchIndex, []string{"-o", "Dir::Etc::SourceList=" + plannedList, "-o", "Dir::Etc::SourceParts=" + plannedParts, "-o", "APT::Get::List-Cleanup=0"})

// noUpdateHooks drops the commands that other packages run around a refresh,
// such as update-notifier on Ubuntu. They read and write apt's own state.
const noUpdateHooks = "#clear APT::Update::Pre-Invoke;\n#clear APT::Update::Post-Invoke;\n#clear APT::Update::Post-Invoke-Success;\n#clear APT::Update::Post-Invoke-Stats;\n"

// refreshWinchIndex refreshes winch's index, once until a step changes a
// source, and returns the apt flags that read it.
func refreshWinchIndex(ctx context.Context, st *State) ([]string, error) {
	index := winchIndex
	if st.Sources {
		index = plannedIndex
	}
	if st.Refreshed {
		return index, nil
	}
	if err := os.MkdirAll(path.Join(winchLists, "partial"), 0o700); err != nil {
		return nil, fmt.Errorf("create the package index: %w", err)
	}
	conf := path.Join(aptDir, "update.conf")
	if err := os.WriteFile(conf, []byte(noUpdateHooks), 0o600); err != nil {
		return nil, fmt.Errorf("create the package index: %w", err)
	}
	_, updateErr := aptGet(ctx, slices.Concat([]string{"update", "-q", "--error-on=any", "-c", conf}, index)...)
	// A failed refresh keeps the lists of the sources that apt fetched.
	if err := copyLinks(winchLists); err != nil {
		return nil, fmt.Errorf("copy the package index: %w", err)
	}
	if updateErr != nil {
		if st.Sources {
			return nil, fmt.Errorf("refresh the index of the sources that the run will have: %w", updateErr)
		}
		return nil, updateErr
	}
	st.Refreshed = true
	return index, nil
}

// copyLinks replaces each symbolic link in dir with a copy of its file. apt
// 2.7 links the index of a file: source, and the check of the state
// directory accepts only regular files.
func copyLinks(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink == 0 {
			continue
		}
		p := path.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (u *Upgrade) Check(ctx context.Context, st *State, say Say) (Result, error) {
	index, err := refreshWinchIndex(ctx, st)
	if err != nil {
		return Result{}, err
	}
	pkgs, err := readDpkg(ctx, say.Progress)
	if err != nil {
		return Result{}, err
	}
	if err := othersHalfDone(pkgs, nil); err != nil {
		return Result{}, err
	}
	unlock, err := lockFiles(ctx, dpkgLocks, say.Progress)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	out, err := aptGet(ctx, slices.Concat([]string{"-s", "-q"}, u.args(), index)...)
	if err != nil {
		return Result{}, err
	}
	changes := parseUpgrade(out)
	if err := checkAccess(parseRemovals(out, nil), st.LoginUID); err != nil {
		return Result{}, err
	}
	planPkgs(st, out, index, nil)
	if len(changes) == 0 {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (u *Upgrade) Apply(ctx context.Context, say Say) error {
	if err := waitLocks(ctx, dpkgLocks, say.Progress); err != nil {
		return err
	}
	_, err := aptGet(ctx, slices.Concat(u.args(), aptApply, winchIndex)...)
	return err
}

// planPkgs records the packages that the output of apt-get -s installs or
// upgrades, with the apt flags of the package index that it read. named are
// the packages that a pkg step names.
func planPkgs(st *State, out string, index, named []string) {
	if st == nil {
		return
	}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "Inst" {
			continue
		}
		// An upgrade shows the installed version in brackets.
		rest := f[2:]
		if strings.HasPrefix(rest[0], "[") {
			rest = rest[1:]
		}
		if len(rest) == 0 || !strings.HasPrefix(rest[0], "(") {
			continue
		}
		name, _, _ := strings.Cut(f[1], ":")
		pp := PlannedPkg{Version: strings.TrimPrefix(rest[0], "("), Index: index, Named: slices.Contains(named, name)}
		for _, w := range rest[1:] {
			if strings.HasPrefix(w, "[") {
				pp.Arch = strings.Trim(w, "[])")
				break
			}
		}
		if st.Packages == nil {
			st.Packages = map[string]PlannedPkg{}
		}
		st.Packages[name] = pp
	}
}

// parseUpgrade returns the plan lines of the output of apt-get -s: one per
// package that apt installs, upgrades, or removes.
func parseUpgrade(out string) []string {
	var lines []string
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 2 && f[0] == "Remv":
			lines = append(lines, "remove "+f[1])
		case len(f) >= 4 && f[0] == "Inst" && strings.HasPrefix(f[2], "["):
			lines = append(lines, fmt.Sprintf("upgrade %s %s → %s", f[1], strings.Trim(f[2], "[]"), strings.TrimPrefix(f[3], "(")))
		case len(f) >= 3 && f[0] == "Inst":
			lines = append(lines, fmt.Sprintf("install %s %s", f[1], strings.TrimPrefix(f[2], "(")))
		}
	}
	return lines
}

// UpgradesSSHServer reports whether changes, the plan lines of an upgrade step,
// upgrade openssh-server.
func UpgradesSSHServer(changes []string) bool {
	return slices.ContainsFunc(changes, func(c string) bool { return strings.HasPrefix(c, "upgrade openssh-server ") })
}
