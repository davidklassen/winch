package module

import (
	"bytes"
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
	Name string `yaml:"name,required" json:"name" line:"zone name, such as Europe/Berlin" doc:"Zone name, such as Europe/Berlin."`
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
	TimezoneFile = "/etc/timezone"
)

func (z *Timezone) Check(ctx context.Context, _ *State, _ Say) (Result, error) {
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
	data, err := os.ReadFile(TimezoneFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return Result{}, err
	case strings.TrimSpace(string(data)) != z.Name:
		if err := noFlagsAt(TimezoneFile); err != nil {
			return Result{}, err
		}
		changes = append(changes, TimezoneFile+" "+strings.TrimSpace(string(data))+" → "+z.Name)
	}
	if len(changes) == 0 {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (z *Timezone) missing() (bool, error) {
	return zoneMissing(zoneinfo, z.Name)
}

// zoneMissing reports whether the zone name has no file in dir: an earlier
// step, such as an install of tzdata-legacy, can still add it.
func zoneMissing(dir, name string) (bool, error) {
	fi, err := os.Stat(dir + name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, err
	case !fi.Mode().IsRegular():
		return false, fmt.Errorf("%s is not a time zone: %s%s is %s", name, dir, name, kind(fi))
	}
	data, err := os.ReadFile(dir + name)
	if err != nil {
		return false, err
	}
	if !bytes.HasPrefix(data, []byte("TZif")) {
		return false, fmt.Errorf("%s is not a time zone: %s%s does not start with TZif", name, dir, name)
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

func (z *Timezone) Apply(ctx context.Context, _ Say) error {
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
	data, err := os.ReadFile(TimezoneFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case strings.TrimSpace(string(data)) == z.Name:
		return nil
	}
	return writeRoot(TimezoneFile, []byte(z.Name+"\n"), 0, 0, 0o644)
}
