package module

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Assert struct {
	Command string `yaml:"command,required" json:"command" doc:"The command that runs during apply. It runs through sh -e as root, in /."`
	Message string `yaml:"message,required" json:"message" doc:"The error of the host when the command exits non-zero."`
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
func (a *Assert) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	return Result{Status: OK, Deferred: true}, nil
}

func (a *Assert) Apply(ctx context.Context, _ func(string)) error {
	err := Shell(ctx, a.Command)
	if errors.As(err, new(*exec.ExitError)) {
		return errors.New(a.Message)
	}
	return err
}
