package cli

import (
	"context"
	"fmt"

	"github.com/davidklassen/winch/internal/project"
)

func format(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		printError(env.stderr, "winch: fmt takes no arguments")
		return exitInvalid
	}
	files, err := project.Format(env.Dir)
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	for _, file := range files {
		fmt.Fprintln(env.stdout, file)
	}
	return exitOK
}
