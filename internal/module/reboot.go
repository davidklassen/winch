package module

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/yamlx"
)

type Reboot struct {
	IfRequired *bool `yaml:"if_required,required" json:"if_required" line:"only on a pending reboot" doc:"Only on a pending reboot. With false, the step always reboots."`
	// Timeout is the wait limit in seconds; nil is the default.
	Timeout *int `yaml:"timeout" json:"timeout,omitempty" line:"wait limit in seconds" doc:"Wait limit in seconds." default:"600"`
}

// defaultRebootTimeout is the wait limit of a reboot in seconds.
const defaultRebootTimeout = 600

func (r *Reboot) Main() string {
	if r.IfRequired != nil && *r.IfRequired {
		return "if required"
	}
	return ""
}

func (r *Reboot) Validate() error {
	if r.Timeout != nil && *r.Timeout < 1 {
		return &yamlx.FieldError{Field: "timeout", Msg: "must be 1 or more seconds"}
	}
	return nil
}

// Wait returns the wait limit.
func (r *Reboot) Wait() time.Duration {
	if r.Timeout == nil {
		return defaultRebootTimeout * time.Second
	}
	return time.Duration(*r.Timeout) * time.Second
}

// Check shows a reboot that will surely run as a change. Otherwise an earlier
// step of the run may still require one, so the step is deferred.
func (r *Reboot) Check(ctx context.Context, _ *State, _ Say) (Result, error) {
	if !*r.IfRequired {
		return Result{Status: Change, Action: Modify}, nil
	}
	required, err := RebootRequired()
	if err != nil {
		return Result{}, err
	}
	if required {
		return Result{Status: Change, Action: Modify, Changes: []string{"the host requires a reboot"}}, nil
	}
	return Result{Status: OK, Deferred: true}, nil
}

// Apply changes nothing: the controller reboots the host, since it must
// connect again.
func (r *Reboot) Apply(ctx context.Context, _ Say) error { return nil }

// RebootRequired reports whether the host waits for a reboot.
func RebootRequired() (bool, error) {
	running, err := runningKernel()
	if err != nil {
		return false, err
	}
	return facts.RebootRequired("/run/reboot-required", "/boot", running)
}

// Kernels returns the running kernel and the newest kernel of its flavor.
func Kernels() (string, string, error) {
	running, err := runningKernel()
	if err != nil {
		return "", "", err
	}
	newest, err := facts.NewestKernel("/boot", running)
	return running, newest, err
}

func runningKernel() (string, error) {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(release)), err
}
