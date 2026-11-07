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
	Unless  *string `yaml:"unless" json:"unless,omitempty" line:"check command as user, in dir; exit 0 skips the step" doc:"Check command; exit 0 skips the step. It runs at the check as user, with the user's home as HOME, in dir, with the timeout of the step. A dir that does not exist yet checks as change. When it fails and writes to stderr, the plan shows its last 3 lines. A step has at most one of creates and unless."`
	User    string  `yaml:"user" json:"user,omitempty" line:"account that runs command and unless" doc:"Account that runs command and unless. Its home is HOME. The step starts no login session: PAM does not run, so the login umask and limits of the account do not apply, and the umask is 022." default:"root"`
	Dir     string  `yaml:"dir" json:"dir,omitempty" line:"working directory, also for unless" doc:"Working directory, also for unless." default:"/"`
	Timeout *int    `yaml:"timeout" json:"timeout,omitempty" line:"limit in seconds, also for unless" doc:"Limit in seconds, also for unless. After it, winch stops the command and the step fails." default:"600"`
}

func (*Cmd) Noun() string { return "a cmd step" }

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
		return &yamlx.FieldError{At: "unless", Msg: "a cmd step has at most one of creates and unless"}
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
	res := Result{Status: Unknown}
	if c.Creates != "" {
		_, err := os.Lstat(c.Creates)
		switch {
		case err == nil:
			return Result{Status: OK}, nil
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
			res.Status, res.Action = Change, Create
		default:
			return Result{}, err
		}
	}
	as, ok, err := c.runAs()
	if err != nil {
		return Result{}, err
	}
	if !ok {
		res.Missing = append(res.Missing, "user "+c.User)
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
	if c.Unless == nil {
		return res, nil
	}
	res.Status, res.Action = Change, Modify
	if res.Missing != nil {
		return res, nil
	}
	stderr := &tailBuffer{max: outputLimit + 1}
	err = c.shell(ctx, *c.Unless, as, stderr)
	switch {
	case err == nil:
		return Result{Status: OK}, nil
	case !errors.As(err, new(*exec.ExitError)):
		return Result{}, fmt.Errorf("unless: %s: %w", FirstLine(*c.Unless), err)
	}
	if out := shownOutput(string(stderr.tail())); out != "" {
		lines := strings.Split(out, "\n")
		res.Stderr = strings.Join(lines[max(0, len(lines)-3):], "\n")
	}
	return res, nil
}

func (c *Cmd) Apply(ctx context.Context, _ Say) error {
	as, ok, err := c.runAs()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("user %s does not exist; no earlier user step creates it", c.User)
	}
	if err := c.shell(ctx, c.Command, as, nil); err != nil || c.Creates == "" {
		return err
	}
	_, err = os.Lstat(c.Creates)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return fmt.Errorf("the command exited 0 but did not create %s, so each run would run it again; make the command create it, or fix creates", c.Creates)
	}
	return err
}

// runAs is nil without user. ok is false when the user does not exist.
func (c *Cmd) runAs() (as *runAs, ok bool, err error) {
	if c.User == "" {
		return nil, true, nil
	}
	a, err := readAccounts()
	if err != nil {
		return nil, false, err
	}
	u, ok := a.user(c.User)
	if !ok {
		return nil, false, nil
	}
	// The groups that initgroups gives a login of the user.
	groups := []uint32{u.gid}
	for _, g := range a.groups {
		if slices.Contains(g.members, u.name) {
			groups = append(groups, g.gid)
		}
	}
	return &runAs{user: u, groups: groups}, true, nil
}

func (c *Cmd) shell(ctx context.Context, command string, as *runAs, stderr *tailBuffer) error {
	err := shellLimit(ctx, command, cmp.Or(c.Dir, "/"), nil, as, c.limit(), KillDelay, "timeout", stderr)
	// exec names sh, not the directory, when the user cannot enter it.
	if pe, ok := errors.AsType[*fs.PathError](err); ok && pe.Op == "fork/exec" && c.Dir != "" {
		return fmt.Errorf("dir %s: %w", c.Dir, pe.Err)
	}
	return err
}

func (c *Cmd) limit() time.Duration {
	if c.Timeout == nil {
		return commandLimit
	}
	return time.Duration(*c.Timeout) * time.Second
}
