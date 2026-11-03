package module

import (
	"context"
	"fmt"
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

// upgradeLists is the package index of upgrade. Its refresh leaves apt's own
// index as it is.
const upgradeLists = aptDir + "/lists"

// upgradeIndex are the apt-get flags that read the index of upgrade. Without
// binary caches, apt writes no cache of that index into /var/cache/apt. apt
// fetches as root: the user _apt cannot enter the state directory, and apt
// gives the directories of the index to its sandbox user, which the check of
// the state directory rejects.
var upgradeIndex = []string{"-o", "Dir::State::Lists=" + upgradeLists, "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "-o", "APT::Sandbox::User=root"}

// noUpdateHooks drops the commands that other packages run around a refresh,
// such as update-notifier on Ubuntu. They read and write apt's own state.
const noUpdateHooks = "#clear APT::Update::Pre-Invoke;\n#clear APT::Update::Post-Invoke;\n#clear APT::Update::Post-Invoke-Success;\n#clear APT::Update::Post-Invoke-Stats;\n"

func refreshUpgradeIndex(ctx context.Context) error {
	if err := os.MkdirAll(path.Join(upgradeLists, "partial"), 0o700); err != nil {
		return fmt.Errorf("create the package index: %w", err)
	}
	conf := path.Join(aptDir, "update.conf")
	if err := os.WriteFile(conf, []byte(noUpdateHooks), 0o600); err != nil {
		return fmt.Errorf("create the package index: %w", err)
	}
	_, err := aptGet(ctx, slices.Concat([]string{"update", "-q", "--error-on=any", "-c", conf}, upgradeIndex)...)
	return err
}

func (u *Upgrade) Check(ctx context.Context, st *State, say Say) (Result, error) {
	if !st.Refreshed {
		if err := refreshUpgradeIndex(ctx); err != nil {
			return Result{}, err
		}
	}
	st.Refreshed = true
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
	out, err := aptGet(ctx, slices.Concat([]string{"-s", "-q"}, u.args(), upgradeIndex)...)
	if err != nil {
		return Result{}, err
	}
	changes := parseUpgrade(out)
	if err := checkAccess(parseRemovals(out, nil), st.LoginUID); err != nil {
		return Result{}, err
	}
	if len(changes) == 0 {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (u *Upgrade) Apply(ctx context.Context, say Say) error {
	if err := waitLocks(ctx, dpkgLocks, say.Progress); err != nil {
		return err
	}
	_, err := aptGet(ctx, slices.Concat(u.args(), aptApply, upgradeIndex)...)
	return err
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
