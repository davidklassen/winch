package helper

import (
	"context"
	"encoding/json"
	"fmt"
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
// when it does not pass within h.Timeout.
func health(ctx context.Context, h protocol.Health, interval, killDelay time.Duration) error {
	start := time.Now()
	deadline := start.Add(h.Timeout)
	var passing time.Time
	var last error
	for {
		run := time.Now()
		left := deadline.Sub(run)
		if left <= 0 {
			break
		}
		err := module.ShellLimit(ctx, h.Command, left, killDelay)
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
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Until(run.Add(interval))):
		}
	}
	if !passing.IsZero() {
		return fmt.Errorf("passed, but not for %s within %s", module.Seconds(h.Stable), module.Seconds(h.Timeout))
	}
	msg := strings.TrimPrefix(last.Error(), h.Command+": ")
	return fmt.Errorf("did not pass within %s: %s", module.Seconds(h.Timeout), msg)
}
