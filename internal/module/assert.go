package module

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Assert struct {
	Command string `yaml:"command,required" json:"command" line:"check command" doc:"Check command. It runs during apply, through sh -e as root, in /. Exit 0 passes."`
	Message string `yaml:"message,required" json:"message" line:"error when the check fails" doc:"Error when the check fails. The host fails with it when the command exits non-zero, followed by the shell's error when the exit is 126 or 127."`
}

func (a *Assert) Main() string { return strings.TrimSuffix(a.Command, "\n") }

func (a *Assert) Validate() error {
	if err := checkCommand("command", &a.Command); err != nil {
		return err
	}
	if a.Message == "" {
		return &yamlx.FieldError{Field: "message", Msg: "is empty"}
	}
	return nil
}

// Check runs nothing: the command can test what earlier steps change.
func (a *Assert) Check(ctx context.Context, _ *State, _ Say) (Result, error) {
	return Result{Status: OK, Deferred: true}, nil
}

func (a *Assert) Apply(ctx context.Context, _ Say) error {
	err := Shell(ctx, a.Command)
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		if code := exit.ExitCode(); code == 126 || code == 127 {
			return fmt.Errorf("%s: %w", a.Message, err)
		}
		return errors.New(a.Message)
	}
	return err
}
