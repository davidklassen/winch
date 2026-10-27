package module

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Upgrade struct {
	Mode string `yaml:"mode,required" json:"mode"`
}

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

func (u *Upgrade) Check(ctx context.Context, st *State, note func(string)) (Result, error) {
	if err := waitIndexLock(ctx, note); err != nil {
		return Result{}, err
	}
	if _, err := aptGet(ctx, "update", "-q", "--error-on=any"); err != nil {
		return Result{}, err
	}
	st.IndexFresh = true
	pkgs, err := readDpkg(ctx, note)
	if err != nil {
		return Result{}, err
	}
	if err := othersHalfDone(pkgs, nil); err != nil {
		return Result{}, err
	}
	unlock, err := lockFiles(ctx, dpkgLocks, note)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	out, err := aptGet(ctx, append([]string{"-s", "-q"}, u.args()...)...)
	if err != nil {
		return Result{}, err
	}
	changes := parseUpgrade(out)
	if len(changes) == 0 {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (u *Upgrade) Apply(ctx context.Context, note func(string)) error {
	if err := waitLocks(ctx, dpkgLocks, note); err != nil {
		return err
	}
	_, err := aptGet(ctx, slices.Concat(u.args(), aptApply)...)
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
