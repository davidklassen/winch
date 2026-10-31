package module

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Cmd struct {
	Command string  `yaml:"command,required" json:"command" line:"shell script" doc:"Shell script. It runs through sh -e as root, in /, with stdin from /dev/null. A script of several lines stops at its first failed line. Without creates or unless, the check result is unknown."`
	Creates string  `yaml:"creates" json:"creates,omitempty" line:"path that marks the work as done" doc:"Path that marks the work as done. The step is ok when the path exists. When the command exits 0 and the path is still missing, the step fails. The path has no glob characters. A step has at most one of creates and unless."`
	Unless  *string `yaml:"unless" json:"unless,omitempty" line:"check command; exit 0 skips the step" doc:"Check command; exit 0 skips the step. It runs at the check as root, in /, with the timeout of the step. user and dir do not apply to it. A step has at most one of creates and unless."`
	User    string  `yaml:"user" json:"user,omitempty" line:"account that runs command" doc:"Account that runs command. Its home is HOME. The step starts no login session: PAM does not run, so the login umask and limits of the account do not apply, and the umask is 022." default:"root"`
	Dir     string  `yaml:"dir" json:"dir,omitempty" line:"working directory" doc:"Working directory." default:"/"`
	Timeout *int    `yaml:"timeout" json:"timeout,omitempty" line:"limit in seconds, also for unless" doc:"Limit in seconds, also for unless. After it, winch stops the command and the step fails." default:"600"`
}

func (c *Cmd) Main() string { return strings.TrimSuffix(c.Command, "\n") }

func (c *Cmd) UnlessCommand() string {
	if c.Unless == nil {
		return ""
	}
	return *c.Unless
}

func (c *Cmd) Validate() error {
	if err := checkCommand("command", &c.Command); err != nil {
		return err
	}
	if c.Timeout != nil {
		if err := CheckSeconds("timeout", *c.Timeout); err != nil {
			return err
		}
	}
	if err := checkCommand("unless", c.Unless); err != nil {
		return err
	}
	if c.Unless != nil && c.Creates != "" {
		return &yamlx.FieldError{Field: "unless", Msg: "a cmd has at most one of creates and unless"}
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

func (c *Cmd) Check(ctx context.Context, _ *State, _ Say) (Result, error) {
	res, err := c.check(ctx)
	if err != nil || res.Status == OK {
		return res, err
	}
	if c.User != "" {
		a, err := readAccounts()
		if err != nil {
			return Result{}, err
		}
		if _, ok := a.user(c.User); !ok {
			res.Missing = append(res.Missing, "user "+c.User)
		}
	}
	if c.Dir != "" {
		_, err := os.Stat(c.Dir)
		switch {
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
			res.Missing = append(res.Missing, "dir "+c.Dir)
		case err != nil:
			return Result{}, err
		}
	}
	return res, nil
}

func (c *Cmd) check(ctx context.Context) (Result, error) {
	if c.Unless != nil {
		err := ShellLimit(ctx, *c.Unless, c.limit(), KillDelay)
		switch {
		case err == nil:
			return Result{Status: OK}, nil
		case errors.As(err, new(*exec.ExitError)):
			return Result{Status: Change, Action: Modify}, nil
		}
		return Result{}, fmt.Errorf("unless: %w", err)
	}
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

func (c *Cmd) Apply(ctx context.Context, _ Say) error {
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
	err := shellLimit(ctx, c.Command, cmp.Or(c.Dir, "/"), nil, as, c.limit(), KillDelay)
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

func (c *Cmd) limit() time.Duration {
	if c.Timeout == nil {
		return commandLimit
	}
	return time.Duration(*c.Timeout) * time.Second
}
