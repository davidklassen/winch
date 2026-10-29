package module

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Timezone struct {
	Name string `yaml:"name,required" json:"name"`
}

func (z *Timezone) Main() string { return z.Name }

var zoneRe = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`)

func (z *Timezone) Validate() error {
	if !zoneRe.MatchString(z.Name) {
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q is not a time zone name such as Etc/UTC or Europe/Berlin", z.Name)}
	}
	return nil
}

const (
	zoneinfo     = "/usr/share/zoneinfo/"
	localtime    = "/etc/localtime"
	timezoneFile = "/etc/timezone"
)

func (z *Timezone) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	missing, err := z.missing()
	if err != nil {
		return Result{}, err
	}
	cur, err := currentZone(localtime)
	if err != nil {
		return Result{}, err
	}
	var changes []string
	switch {
	case missing:
		changes = append(changes, "time zone "+cmp.Or(cur, "unknown")+" → "+z.Name+" ("+zoneinfo+z.Name+" does not exist yet)")
	case cur != z.Name:
		changes = append(changes, "time zone "+cmp.Or(cur, "unknown")+" → "+z.Name)
	}
	data, err := os.ReadFile(timezoneFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return Result{}, err
	case strings.TrimSpace(string(data)) != z.Name:
		if err := noFlagsAt(timezoneFile); err != nil {
			return Result{}, err
		}
		changes = append(changes, timezoneFile+" "+strings.TrimSpace(string(data))+" → "+z.Name)
	}
	if len(changes) == 0 {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

// missing reports whether the zone has no file: an earlier step, such as an
// install of tzdata-legacy, can still add it.
func (z *Timezone) missing() (bool, error) {
	fi, err := os.Stat(zoneinfo + z.Name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, err
	case !fi.Mode().IsRegular():
		return false, fmt.Errorf("%s is not a time zone: %s%s is %s", z.Name, zoneinfo, z.Name, kind(fi))
	}
	return false, nil
}

// currentZone returns the zone that the link p names, or "" when p is not a
// link into the zone files.
func currentZone(p string) (string, error) {
	target, err := os.Readlink(p)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.EINVAL) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	_, zone, ok := strings.Cut(target, strings.TrimPrefix(zoneinfo, "/"))
	if !ok {
		return "", nil
	}
	return zone, nil
}

func (z *Timezone) Apply(ctx context.Context, _ func(string)) error {
	missing, err := z.missing()
	if err != nil {
		return err
	}
	if missing {
		return fmt.Errorf("unknown time zone %s: %s%s does not exist; an old name such as US/Eastern needs the package tzdata-legacy", z.Name, zoneinfo, z.Name)
	}
	if _, err := run(ctx, nil, "timedatectl", "set-timezone", "--", z.Name); err != nil {
		return err
	}
	data, err := os.ReadFile(timezoneFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case strings.TrimSpace(string(data)) == z.Name:
		return nil
	}
	return writeRoot(timezoneFile, []byte(z.Name+"\n"), 0, 0, 0o644)
}
