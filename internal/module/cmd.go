package module

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Cmd struct {
	Command string `yaml:"command,required" json:"command"`
	Creates string `yaml:"creates" json:"creates,omitempty"`
	User    string `yaml:"user" json:"user,omitempty"`
	Dir     string `yaml:"dir" json:"dir,omitempty"`
	Timeout *int   `yaml:"timeout" json:"timeout,omitempty"`
}

func (c *Cmd) Main() string { return strings.TrimSuffix(c.Command, "\n") }

func (c *Cmd) Validate() error {
	if err := checkCommand("command", &c.Command); err != nil {
		return err
	}
	if c.Timeout != nil {
		if *c.Timeout < 1 {
			return &yamlx.FieldError{Field: "timeout", Msg: "must be 1 or more seconds"}
		}
		if int64(*c.Timeout) > math.MaxInt64/int64(time.Second) {
			return &yamlx.FieldError{Field: "timeout", Msg: fmt.Sprintf("must be at most %d seconds", math.MaxInt64/int64(time.Second))}
		}
	}
	if c.Creates != "" {
		if err := checkAbs("creates", c.Creates); err != nil {
			return err
		}
		if i := strings.IndexAny(c.Creates, "*?["); i >= 0 {
			return &yamlx.FieldError{Field: "creates", Msg: fmt.Sprintf("names one path; %q is not allowed", c.Creates[i:i+1])}
		}
	}
	if c.Dir != "" {
		if err := checkAbs("dir", c.Dir); err != nil {
			return err
		}
	}
	if c.User != "" {
		return checkAccountName("user", "user", c.User)
	}
	return nil
}

func (c *Cmd) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	if c.Creates == "" {
		return Result{Status: Unknown}, nil
	}
	_, err := os.Lstat(c.Creates)
	switch {
	case err == nil:
		return Result{Status: OK}, nil
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return Result{Status: Change, Action: Create}, nil
	}
	return Result{}, err
}

func (c *Cmd) Apply(ctx context.Context, _ func(string)) error {
	var as *runAs
	if c.User != "" {
		a, err := readAccounts()
		if err != nil {
			return err
		}
		u, ok := a.user(c.User)
		if !ok {
			return fmt.Errorf("user %s does not exist", c.User)
		}
		// The groups that initgroups gives a login of the user.
		groups := []uint32{u.gid}
		for _, g := range a.groups {
			if slices.Contains(g.members, u.name) {
				groups = append(groups, g.gid)
			}
		}
		as = &runAs{user: u, groups: groups}
	}
	limit := commandLimit
	if c.Timeout != nil {
		limit = time.Duration(*c.Timeout) * time.Second
	}
	err := shellLimit(ctx, c.Command, cmp.Or(c.Dir, "/"), as, limit, KillDelay)
	// exec names sh, not the directory, when the user cannot enter it.
	if pe, ok := errors.AsType[*fs.PathError](err); ok && pe.Op == "fork/exec" && c.Dir != "" {
		return fmt.Errorf("dir %s: %w", c.Dir, pe.Err)
	}
	if err != nil || c.Creates == "" {
		return err
	}
	_, err = os.Lstat(c.Creates)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return fmt.Errorf("the command did not create %s", c.Creates)
	}
	return err
}
