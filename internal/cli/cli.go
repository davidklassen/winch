// Package cli is the winch command line.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/yamlx"
)

const (
	exitOK      = 0
	exitFailed  = 1
	exitInvalid = 3
	exitConfirm = 5
)

type Env struct {
	Dir      string
	In       io.Reader
	Out, Err io.Writer
	// Terminal is true when stdin and stderr are terminals.
	Terminal bool
	Connect  run.Connect
}

const mainHelp = `Examples:
  winch validate
  winch plan site --inventory inventories/test.yaml
  winch apply site --inventory inventories/test.yaml

winch configures Linux servers over SSH.

Usage: winch <command> [arguments] [flags]

Commands:
  validate   Load the project and check it. Connects to no host.
  plan       Show the changes. Change nothing.
  apply      Show the changes, ask, then make them.

Run "winch <command> --help" for the arguments and flags of a command.
`

type command struct {
	help string
	// yes is true when the command takes --yes.
	yes bool
	run func(ctx context.Context, env Env, f *flags, args []string) int
}

var commands = map[string]command{
	"validate": {help: validateHelp, run: validate},
	"plan":     {help: planHelp, run: plan},
	"apply":    {help: applyHelp, yes: true, run: apply},
}

const validateHelp = `Examples:
  winch validate
  winch validate --inventory inventories/production.yaml

Load the project and check schemas, names, and module arguments.

Usage: winch validate [flags]

Without --inventory and without inventory in winch.yaml, validate checks
every file in inventories/.

Flags:
  --inventory <path>   The inventory file to check.
`

const planHelp = `Examples:
  winch plan site
  winch plan site --inventory inventories/production.yaml

Show the changes that apply would make. Change nothing.

Usage: winch plan <pipeline> [flags]

Flags:
  --inventory <path>   The inventory file for this run.
`

const applyHelp = `Examples:
  winch apply site
  winch apply site --inventory inventories/test.yaml --yes

Show the changes, ask, then make them.

Usage: winch apply <pipeline> [flags]

winch asks only when stdin and stderr are terminals. Without a terminal
and without --yes, apply prints the plan and exits with code 5.

Flags:
  --inventory <path>   The inventory file for this run.
  --yes                Apply without the question.
`

type flags struct {
	inventory string
	yes       bool
}

func Main(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		fmt.Fprint(env.Err, mainHelp)
		return exitInvalid
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(env.Out, mainHelp)
		return exitOK
	}
	cmd, ok := commands[args[0]]
	if !ok {
		names := slices.Sorted(maps.Keys(commands))
		fmt.Fprintf(env.Err, "winch: unknown command %q%s\n\n%s", args[0], yamlx.Suggest(args[0], names), mainHelp)
		return exitInvalid
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var f flags
	fs.StringVar(&f.inventory, "inventory", "", "")
	if cmd.yes {
		fs.BoolVar(&f.yes, "yes", false, "")
	}
	pos, err := parse(fs, args[1:])
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(env.Out, cmd.help)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(env.Err, "winch %s: %v\nRun \"winch %s --help\" for the flags.\n", args[0], err, args[0])
		return exitInvalid
	}
	return cmd.run(ctx, env, &f, pos)
}

// parse parses flags before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func validate(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(env.Err, "winch: validate takes no arguments")
		return exitInvalid
	}
	if err := project.Validate(env.Dir, f.inventory); err != nil {
		fmt.Fprintln(env.Err, err)
		return exitInvalid
	}
	fmt.Fprintln(env.Out, "ok")
	return exitOK
}

func load(env Env, f *flags, cmd string, args []string) (*project.Project, bool) {
	if len(args) != 1 {
		fmt.Fprintf(env.Err, "winch: %s needs one pipeline\n", cmd)
		return nil, false
	}
	p, err := project.Load(env.Dir, f.inventory, args[0])
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return nil, false
	}
	return p, true
}

func plan(ctx context.Context, env Env, f *flags, args []string) int {
	p, ok := load(env, f, "plan", args)
	if !ok {
		return exitInvalid
	}
	pl := run.MakePlan(ctx, p, env.Connect)
	pl.Write(env.Out, env.Err)
	if len(pl.Failed) > 0 {
		return exitFailed
	}
	return exitOK
}

func apply(ctx context.Context, env Env, f *flags, args []string) int {
	p, ok := load(env, f, "apply", args)
	if !ok {
		return exitInvalid
	}
	pl := run.MakePlan(ctx, p, env.Connect)
	pl.Write(env.Out, env.Err)
	failed := exitOK
	if len(pl.Failed) > 0 {
		failed = exitFailed
	}
	if !pl.HasChanges() {
		return failed
	}
	if !f.yes {
		if !env.Terminal {
			fmt.Fprintf(env.Out, "To apply, run: %s\n", applyCommand(args[0], f))
			if failed != exitOK {
				return failed
			}
			return exitConfirm
		}
		fmt.Fprint(env.Err, "Apply these changes? [y/N] ")
		answer, _ := bufio.NewReader(env.In).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(env.Err, "Nothing changed.")
			return failed
		}
	}
	if !run.Apply(ctx, pl, env.Connect, env.Out, env.Err) {
		return exitFailed
	}
	return failed
}

func applyCommand(pipeline string, f *flags) string {
	cmd := "winch apply " + quote(pipeline)
	if f.inventory != "" {
		cmd += " --inventory " + quote(f.inventory)
	}
	return cmd + " --yes"
}

var plainRe = regexp.MustCompile(`^[A-Za-z0-9_./=:,@%+-]+$`)

func quote(s string) string {
	if plainRe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
