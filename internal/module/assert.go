package module

import (
	"context"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Assert struct {
	Command string `yaml:"command,required" json:"command" line:"check command" doc:"Check command. It runs during apply, through sh -e as root, in /. Exit 0 passes."`
	Message string `yaml:"message,required" json:"message" line:"error when the check fails" doc:"Error when the check fails. The host fails with it when the command exits non-zero, followed by the exit status and the command's output."`
}

func (*Assert) Noun() string { return "an assert step" }

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
	out := &tailBuffer{max: outputLimit + 1}
	if err := shell(ctx, "-ec", a.Command, "/", nil, nil, commandLimit, "", KillDelay, out, out); err != nil {
		return failure(a.Message, err, string(out.tail()))
	}
	return nil
}
