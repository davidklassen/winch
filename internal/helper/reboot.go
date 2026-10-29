package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

const bootIDFile = "/proc/sys/kernel/random/boot_id"

// reboot starts the reboot in a process of its own, a second from now, so
// the answer reaches the controller first. It returns the boot ID.
// systemctl reboot does not ask as molly-guard's reboot does.
func reboot() (string, error) {
	id, err := os.ReadFile(bootIDFile)
	if err != nil {
		return "", err
	}
	cmd := exec.Command("sh", "-c", "sleep 1; exec systemctl reboot")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start the reboot: %w", err)
	}
	go cmd.Wait() //nolint:errcheck // the reboot ends the helper
	return strings.TrimSpace(string(id)), nil
}

// booted reports whether the host has another boot ID than the one before
// the reboot, and then waits for the system to start.
func booted(ctx context.Context, params json.RawMessage) (protocol.Boot, error) {
	var b protocol.Booted
	if err := json.Unmarshal(params, &b); err != nil {
		return protocol.Boot{}, fmt.Errorf("decode booted: %w", err)
	}
	id, err := os.ReadFile(bootIDFile)
	if err != nil {
		return protocol.Boot{}, err
	}
	if strings.TrimSpace(string(id)) == b.Old {
		return protocol.Boot{Same: true}, nil
	}
	wait, cancel := context.WithTimeout(ctx, b.Wait)
	defer cancel()
	// is-system-running exits non-zero for every state but running.
	out, _ := exec.CommandContext(wait, "systemctl", "is-system-running", "--wait").Output()
	state := strings.TrimSpace(string(out))
	if wait.Err() != nil {
		out, _ = exec.CommandContext(ctx, "systemctl", "is-system-running").Output()
		state = strings.TrimSpace(string(out))
	}
	res := protocol.Boot{State: state}
	res.Kernel, res.Newest, err = module.Kernels()
	if err != nil {
		return res, fmt.Errorf("read the kernels: %w", err)
	}
	pkgs, err := os.ReadFile("/run/reboot-required.pkgs")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return res, err
	}
	res.Packages = strings.Fields(string(pkgs))
	slices.Sort(res.Packages)
	res.Packages = slices.Compact(res.Packages)
	if state != "degraded" {
		return res, nil
	}
	out, err = exec.CommandContext(ctx, "systemctl", "list-units", "--state=failed", "--plain", "--no-legend", "--no-pager").Output()
	if err != nil {
		return res, fmt.Errorf("list the failed units: %w", err)
	}
	for line := range strings.Lines(string(out)) {
		if f := strings.Fields(line); len(f) > 0 {
			res.Failed = append(res.Failed, f[0])
		}
	}
	return res, nil
}
