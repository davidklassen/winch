package module

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Assert struct {
	Command string `yaml:"command,required" json:"command" line:"check command" doc:"Check command. It runs during apply, through sh -e as root, in /. Exit 0 passes."`
	Message string `yaml:"message,required" json:"message" line:"error when the check fails" doc:"Error when the check fails. The host fails with it when the command exits non-zero."`
}

func (a *Assert) Main() string { return strings.TrimSuffix(a.Command, "\n") }

func (a *Assert) Validate() error {
	if err := checkCommand("command", &a.Command); err != nil {
		return err
	}
	if a.Message == "" {
		return &yamlx.FieldError{Field: "message", Msg: "must not be empty"}
	}
	return nil
}

// Check runs nothing: the command can test what earlier steps change.
func (a *Assert) Check(ctx context.Context, _ *State, _ Say) (Result, error) {
	return Result{Status: OK, Deferred: true}, nil
}

func (a *Assert) Apply(ctx context.Context, _ Say) error {
	err := Shell(ctx, a.Command)
	if errors.As(err, new(*exec.ExitError)) {
		return errors.New(a.Message)
	}
	return err
}
