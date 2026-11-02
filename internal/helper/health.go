package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

// runHealth decodes the params of health, runs the gate, and removes its
// record when it passes.
func runHealth(ctx context.Context, params json.RawMessage, checks records) error {
	var h protocol.Health
	if err := json.Unmarshal(params, &h); err != nil {
		return fmt.Errorf("decode health: %w", err)
	}
	if err := health(ctx, h, time.Second, module.KillDelay); err != nil {
		return err
	}
	line, err := json.Marshal(h.Check)
	if err != nil {
		return err
	}
	return checks.remove(string(line))
}

// health runs the command of a gate until it exits 0, and then until it has
// passed for h.Stable. A failed run starts the wait again. Runs start
// interval apart, and each run ends when the gate time ends. The gate fails
// when it does not pass within h.Timeout, and at once when sh cannot run the
// command.
func health(ctx context.Context, h protocol.Health, interval, killDelay time.Duration) error {
	deadline := time.Now().Add(h.Timeout)
	gate, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var passing time.Time
	var last error
	for {
		run := time.Now()
		if !run.Before(deadline) {
			break
		}
		err := module.ShellLimit(gate, h.Command, h.Timeout, killDelay)
		// The end of the gate stopped this run, so it has no result.
		if err != nil && gate.Err() != nil {
			break
		}
		// sh exits 126 or 127 when it cannot run the command, and a later run
		// will not change that.
		if exit, ok := errors.AsType[*exec.ExitError](err); ok && (exit.ExitCode() == 126 || exit.ExitCode() == 127) {
			return errors.New(strings.TrimPrefix(err.Error(), module.FirstLine(h.Command)+": "))
		}
		switch {
		case err != nil:
			passing, last = time.Time{}, err
		case passing.IsZero():
			passing = run
		}
		if !passing.IsZero() && time.Since(passing) >= h.Stable {
			return nil
		}
		select {
		case <-gate.Done():
		case <-time.After(time.Until(run.Add(interval))):
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !passing.IsZero() {
		return fmt.Errorf("passed, but not for %s within %s", module.Seconds(h.Stable), module.Seconds(h.Timeout))
	}
	if last == nil {
		return fmt.Errorf("did not pass within %s: the command did not finish", module.Seconds(h.Timeout))
	}
	msg := strings.TrimPrefix(last.Error(), module.FirstLine(h.Command)+": ")
	return fmt.Errorf("did not pass within %s: %s", module.Seconds(h.Timeout), msg)
}
