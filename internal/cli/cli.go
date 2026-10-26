// Package cli is the winch command line.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

const (
	exitOK          = 0
	exitFailed      = 1
	exitChanges     = 2
	exitInvalid     = 3
	exitUnreachable = 4
	exitConfirm     = 5
	exitHash        = 6
)

// precedence orders the exit codes: when two apply, the first in the list
// wins.
var precedence = []int{exitInvalid, exitFailed, exitUnreachable, exitHash, exitConfirm, exitChanges, exitOK}

// worst returns the exit code of a and b that comes first in precedence.
func worst(a, b int) int {
	if slices.Index(precedence, a) < slices.Index(precedence, b) {
		return a
	}
	return b
}

type Env struct {
	Dir      string
	In       io.Reader
	Out, Err io.Writer
	// Terminal is true when stdin and stderr are terminals.
	Terminal bool
	// Connect returns the function that opens sessions. With batch, ssh asks
	// no questions.
	Connect func(batch bool) run.Connect
	// Home is the home directory, or empty when it is not known.
	Home string
	// AgeKey is the value of WINCH_AGE_KEY.
	AgeKey string
	Filter *secret.Filter
	// Now is the clock of the JSON events. Nil means time.Now.
	Now func() time.Time
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
  secret     Encrypt a value, or encrypt all secrets again.

Run "winch <command> --help" for the arguments and flags of a command.
`

type command struct {
	help string
	// project is true when the command takes --inventory and --set.
	project bool
	// apply is true when the command takes --yes and --check.
	apply bool
	// exitCode is true when the command takes --exit-code.
	exitCode bool
	// hosts is true when the command connects to hosts: it takes --hosts,
	// --stages, --user, and --batch.
	hosts bool
	run   func(ctx context.Context, env Env, f *flags, args []string) int
}

var commands = map[string]command{
	"validate":       {help: validateHelp, project: true, run: validate},
	"plan":           {help: planHelp, project: true, exitCode: true, hosts: true, run: plan},
	"apply":          {help: applyHelp, project: true, apply: true, hosts: true, run: apply},
	"secret":         {help: secretHelp, run: secretUsage},
	"secret encrypt": {help: encryptHelp, run: secretEncrypt},
	"secret rekey":   {help: rekeyHelp, run: secretRekey},
}

const validateHelp = `Examples:
  winch validate
  winch validate --inventory inventories/production.yaml
  winch validate --set vars.release=1.4.2

Load the project and check schemas, names, and module arguments.

Usage: winch validate [flags]

Without --inventory and without inventory in winch.yaml, validate checks
every file in inventories/.

Flags:
  --inventory <path>            The inventory file to check.
  --set vars.<name>=<value>     Set a variable. The value parses as YAML.
                                Repeatable.
  --json                        Write JSON events on stdout.
`

const planHelp = `Examples:
  winch plan site
  winch plan site --inventory inventories/production.yaml
  winch plan site --set vars.nginx_port=8080
  winch plan site --hosts 'web & !web3' --stages nginx,site
  winch plan site --exit-code

Show the changes that apply would make, and the plan hash. Change
nothing.

Usage: winch plan <pipeline> [flags]

Flags:
  --inventory <path>            The inventory file for this run.
  --hosts <pattern>             Run only on these hosts: a group or a host,
                                with "," for union, "&" for intersection,
                                and "!" for exclusion.
  --stages <names>              Run only these stages, such as mail,monit.
  --user [<host>=]<name>        SSH login user, for all hosts or one host.
                                Repeatable.
  --set vars.<name>=<value>     Set a variable for this run. The value
                                parses as YAML. Repeatable.
  --batch                       ssh asks no questions, and sessions start
                                in parallel.
  --exit-code                   Exit with code 2 when the plan has
                                changes or pending handlers.
  --json                        Write JSON events on stdout.
`

const applyHelp = `Examples:
  winch apply site
  winch apply site --inventory inventories/test.yaml --yes
  winch apply site --hosts mail --stages mail
  winch apply site --check a3f9c2e1

Show the changes, ask, then make them.

Usage: winch apply <pipeline> [flags]

winch asks only when stdin and stderr are terminals. Without a terminal,
and without --yes or --check, apply prints the plan and exits with code
5. Its last line is the command that applies the plan with its hash.

With a terminal, ssh can ask questions, and sessions start one at a
time. Without one, or with --batch, ssh asks nothing, and sessions start
in parallel.

The first Ctrl-C lets the running step on each host finish and starts no
new step. A second Ctrl-C ends the sessions at once.

Flags:
  --inventory <path>            The inventory file for this run.
  --hosts <pattern>             Run only on these hosts: a group or a host,
                                with "," for union, "&" for intersection,
                                and "!" for exclusion.
  --stages <names>              Run only these stages, such as mail,monit.
  --user [<host>=]<name>        SSH login user, for all hosts or one host.
                                Repeatable.
  --set vars.<name>=<value>     Set a variable for this run. The value
                                parses as YAML. Repeatable.
  --batch                       ssh asks no questions, and sessions start
                                in parallel. The apply question stays.
  --yes                         Apply without the question.
  --check <hash>                Apply only when the plan has this hash.
                                Otherwise exit with code 6 and change
                                nothing.
  --json                        Write JSON events on stdout.
`

type flags struct {
	inventory string
	set       []string
	hosts     string
	stages    string
	users     []string
	batch     bool
	yes       bool
	// check is the value of --check, or nil without it.
	check    *string
	exitCode bool
	json     bool
}

// Main runs the command in args. All output passes through env.Filter.
func Main(ctx context.Context, args []string, env Env) int {
	env.Out, env.Err = env.Filter.Writer(env.Out), env.Filter.Writer(env.Err)
	if len(args) == 0 {
		fmt.Fprint(env.Err, mainHelp)
		return exitInvalid
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(env.Out, mainHelp)
		return exitOK
	}
	name := args[0]
	if name == "secret" && len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		name, args = "secret "+args[1], args[1:]
	}
	cmd, ok := commands[name]
	switch {
	case !ok && strings.HasPrefix(name, "secret "):
		fmt.Fprintf(env.Err, "winch: unknown secret command %q\n\n%s", args[0], secretHelp)
		return exitInvalid
	case !ok:
		var names []string
		for n := range commands {
			if !strings.Contains(n, " ") {
				names = append(names, n)
			}
		}
		slices.Sort(names)
		fmt.Fprintf(env.Err, "winch: unknown command %q%s\n\n%s", args[0], yamlx.Suggest(args[0], names), mainHelp)
		return exitInvalid
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var f flags
	if cmd.project {
		fs.StringVar(&f.inventory, "inventory", "", "")
		fs.Func("set", "", func(s string) error {
			f.set = append(f.set, s)
			return nil
		})
		fs.BoolVar(&f.json, "json", false, "")
	}
	if cmd.apply {
		fs.BoolVar(&f.yes, "yes", false, "")
		fs.Func("check", "", func(s string) error {
			f.check = &s
			return nil
		})
	}
	if cmd.exitCode {
		fs.BoolVar(&f.exitCode, "exit-code", false, "")
	}
	if cmd.hosts {
		fs.Func("hosts", "", notEmpty(&f.hosts))
		fs.Func("stages", "", notEmpty(&f.stages))
		fs.Func("user", "", func(s string) error {
			f.users = append(f.users, s)
			return nil
		})
		fs.BoolVar(&f.batch, "batch", false, "")
	}
	pos, err := parse(fs, args[1:])
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(env.Out, cmd.help)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(env.Err, "winch %s: %v\nRun \"winch %s --help\" for the flags.\n", name, err, name)
		return exitInvalid
	}
	return cmd.run(ctx, env, &f, pos)
}

// notEmpty returns a flag function that sets *v and rejects an empty value.
// An empty --hosts must not select every host.
func notEmpty(v *string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("must not be empty")
		}
		*v = s
		return nil
	}
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
	o := newOutput(env, f)
	if len(args) != 0 {
		o.fail(errors.New("winch: validate takes no arguments"))
		return o.end(exitInvalid, summary{})
	}
	warnings, err := project.Validate(env.Dir, f.inventory, f.set)
	if err != nil {
		o.fail(err)
		return o.end(exitInvalid, summary{})
	}
	o.warn(warnings)
	if o.ev == nil {
		fmt.Fprintln(env.Out, "ok")
	}
	return o.end(exitOK, summary{})
}

// identity returns the path of the age identity file.
func (env Env) identity() string {
	switch {
	case filepath.IsAbs(env.AgeKey):
		return env.AgeKey
	case env.AgeKey != "":
		return filepath.Join(env.Dir, env.AgeKey)
	case env.Home != "":
		return filepath.Join(env.Home, ".config", "winch", "age.key")
	}
	return ""
}

func (o *output) load(f *flags, cmd string, args []string) (*project.Project, bool) {
	if len(args) != 1 {
		o.fail(fmt.Errorf("winch: %s needs one pipeline", cmd))
		return nil, false
	}
	p, err := project.Load(o.env.Dir, f.inventory, args[0], f.set, project.Keys{Identity: o.env.identity(), Filter: o.env.Filter})
	if err != nil {
		o.fail(err)
		return nil, false
	}
	o.warn(p.Warnings)
	if err := p.Select(project.Selection{Hosts: f.hosts, Stages: f.stages, Users: f.users}); err != nil {
		o.fail(fmt.Errorf("winch %s: %w", cmd, err))
		return nil, false
	}
	return p, true
}

// sessions returns the function that opens sessions, and the options of the
// run. ssh asks questions only when winch can ask its own: then the sessions
// start one at a time.
func (env Env) sessions(f *flags) (run.Connect, run.Options) {
	serial := env.Terminal && !f.batch
	return env.Connect(!serial), run.Options{Serial: serial}
}

// failedCode is the exit code of the failed hosts: 1 when one failed, 4
// when all of them were unreachable, else 0.
func failedCode(failed map[string]error) int {
	code := exitOK
	for _, err := range failed {
		if errors.Is(err, run.ErrUnreachable) {
			code = worst(code, exitUnreachable)
		} else {
			code = worst(code, exitFailed)
		}
	}
	return code
}

func plan(ctx context.Context, env Env, f *flags, args []string) int {
	o := newOutput(env, f)
	p, ok := o.load(f, "plan", args)
	if !ok {
		return o.end(exitInvalid, summary{})
	}
	connect, opts := env.sessions(f)
	pl := run.MakePlan(ctx, p, connect, opts)
	o.plan(pl)
	code := failedCode(pl.Failed)
	if f.exitCode && pl.HasChanges() {
		code = worst(code, exitChanges)
	}
	return o.end(code, summary{plan: pl})
}

var hashRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

func apply(ctx context.Context, env Env, f *flags, args []string) int {
	o := newOutput(env, f)
	if f.check != nil && !hashRe.MatchString(*f.check) {
		o.fail(fmt.Errorf("winch: --check %q: a plan hash has 8 hex characters, such as a3f9c2e1", *f.check))
		return o.end(exitInvalid, summary{})
	}
	p, ok := o.load(f, "apply", args)
	if !ok {
		return o.end(exitInvalid, summary{})
	}
	connect, opts := env.sessions(f)
	pl := run.MakePlan(ctx, p, connect, opts)
	o.plan(pl)
	s := summary{plan: pl}
	code := failedCode(pl.Failed)
	if hash := pl.Hash(); f.check != nil && *f.check != hash {
		o.fail(fmt.Errorf("winch: the plan hash is %s, not %s; nothing changed", hash, *f.check))
		return o.end(worst(code, exitHash), s)
	}
	if !pl.HasChanges() {
		return o.end(code, s)
	}
	// After an interrupt, apply starts no host, so there is nothing to ask:
	// the hosts with changes fail as interrupted.
	if f.check == nil && !f.yes && ctx.Err() == nil {
		if !env.Terminal {
			s.command = applyCommand(args[0], f, pl.Hash())
			if o.ev == nil {
				fmt.Fprintf(env.Out, "To apply, run: %s\n", s.command)
			}
			return o.end(worst(code, exitConfirm), s)
		}
		if !ask(ctx, env) {
			fmt.Fprintln(env.Err, "Nothing changed.")
			return o.end(code, s)
		}
	}
	rep := run.Text(env.Out, env.Err)
	if o.ev != nil {
		rep = o.ev
	}
	s.apply = run.Apply(ctx, pl, connect, rep)
	return o.end(worst(code, failedCode(s.apply.Failed)), s)
}

// ask asks for confirmation. An interrupt answers no.
func ask(ctx context.Context, env Env) bool {
	fmt.Fprint(env.Err, "Apply these changes? [y/N] ")
	answer := make(chan string, 1)
	go func() {
		a, _ := bufio.NewReader(env.In).ReadString('\n')
		answer <- a
	}()
	select {
	case a := <-answer:
		a = strings.ToLower(strings.TrimSpace(a))
		return a == "y" || a == "yes"
	case <-ctx.Done():
		fmt.Fprintln(env.Err)
		return false
	}
}

// applyCommand is the command that applies the plan with the hash.
func applyCommand(pipeline string, f *flags, hash string) string {
	cmd := "winch apply " + quote(pipeline)
	if f.inventory != "" {
		cmd += " --inventory " + quote(f.inventory)
	}
	if f.hosts != "" {
		cmd += " --hosts " + quote(f.hosts)
	}
	if f.stages != "" {
		cmd += " --stages " + quote(f.stages)
	}
	for _, u := range f.users {
		cmd += " --user " + quote(u)
	}
	for _, s := range f.set {
		cmd += " --set " + quote(s)
	}
	if f.json {
		cmd += " --json"
	}
	return cmd + " --check " + hash
}

var plainRe = regexp.MustCompile(`^[A-Za-z0-9_./=:,@%+-]+$`)

func quote(s string) string {
	if plainRe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
