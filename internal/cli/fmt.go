package cli

import (
	"context"
	"fmt"

	"github.com/davidklassen/winch/internal/project"
)

const fmtHelp = `Examples:
  winch fmt
  winch fmt --inventory ../shared/production.yaml

Fix the indentation and the step key order of the project files:
winch.yaml, the inventories, the pipelines, and the recipes.

Usage: winch fmt [flags]

fmt indents with two spaces, and indents list items under their key. It
puts step keys in this order: name, the module or recipe key, vars,
when, loop, then, confirm_access, notify. It keeps comments, blank
lines, and quoting. It prints each file that it changes.

When a file does not parse, fmt shows the error and changes no file.

Flags:
  --inventory <path>            An inventory file to format too.
`

func format(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		printError(env.stderr, "winch: fmt takes no arguments")
		return exitInvalid
	}
	files, err := project.Format(env.Dir, f.inventory)
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	for _, file := range files {
		fmt.Fprintln(env.stdout, file)
	}
	return exitOK
}
