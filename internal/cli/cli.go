// Package cli is the winch command line.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/davidklassen/winch/internal/color"
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
	// ColorOut and ColorErr turn on color on stdout and stderr.
	ColorOut, ColorErr bool
	// Connect returns the function that opens sessions. With batch, ssh asks
	// no questions.
	Connect func(batch bool) run.Connect
	// Progress is nil, or shows the busy hosts.
	Progress run.Progress
	// Home is the home directory, or empty when it is not known.
	Home string
	// AgeKey is the value of WINCH_AGE_KEY.
	AgeKey string
	// AgeCmd is the value of WINCH_AGE_IDENTITY_CMD.
	AgeCmd string
	Filter *secret.Filter
	// Version is the version of winch, from the build info.
	Version string
	// NoHelpers is true in a binary built without the host helpers.
	NoHelpers bool
	// Now is the clock of the JSON events. Nil means time.Now.
	Now func() time.Time
	// stdout and stderr are Out and Err through Filter. Main sets them and
	// clears Out and Err.
	stdout, stderr *color.Writer
}

// runs are the functions of the commands, by name.
var runs = map[string]func(ctx context.Context, env Env, f *flags, args []string) int{
	"validate":        validate,
	"fmt":             format,
	"plan":            plan,
	"apply":           apply,
	"run":             runModule,
	"exec":            execCommand,
	"secret":          secretUsage,
	"secret init":     secretInit,
	"secret generate": secretGenerate,
	"secret encrypt":  secretEncrypt,
	"secret rekey":    secretRekey,
	"doc":             docCommand,
	"version":         version,
}

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
	host     string
	command  string
}

// Main runs the command in args. All output passes through env.Filter.
func Main(ctx context.Context, args []string, env Env) int {
	env.stdout = color.NewWriter(env.Out, env.Filter.Parts, env.ColorOut)
	env.stderr = color.NewWriter(env.Err, env.Filter.Parts, env.ColorErr)
	env.Out, env.Err = nil, nil
	if len(args) == 0 {
		writeHelp(env.stderr, mainCommand)
		return exitInvalid
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		writeHelp(env.stdout, mainCommand)
		return exitOK
	}
	name := args[0]
	if name == "--version" {
		name = "version"
	}
	if name == "secret" && len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		name, args = "secret "+args[1], args[1:]
	}
	cmd, ok := commandNamed(name)
	switch {
	case !ok && strings.HasPrefix(name, "secret "):
		printError(env.stderr, fmt.Sprintf("winch: unknown secret command %q", args[0]))
		fmt.Fprintln(env.stderr)
		return secretUsage(ctx, env, nil, nil)
	case !ok:
		_, names := subcommands(mainCommand)
		slices.Sort(names)
		printError(env.stderr, fmt.Sprintf("winch: unknown command %q%s", args[0], yamlx.Suggest(args[0], names)))
		fmt.Fprintln(env.stderr)
		writeHelp(env.stderr, mainCommand)
		return exitInvalid
	}
	var f flags
	fs := flagSet(cmd, &f)
	flagArgs := args[1:]
	// The words after -- of exec are the command, also those that start
	// with -.
	if i := slices.Index(flagArgs, "--"); name == "exec" && i >= 0 {
		f.command = strings.Join(flagArgs[i+1:], " ")
		flagArgs = flagArgs[:i]
	}
	pos, err := parse(fs, flagArgs)
	if errors.Is(err, flag.ErrHelp) {
		writeHelp(env.stdout, cmd)
		return exitOK
	}
	if err != nil {
		printError(env.stderr, fmt.Sprintf("winch %s: %v", name, err))
		fmt.Fprintf(env.stderr, "Run \"winch %s --help\" for the flags.\n", name)
		return exitInvalid
	}
	if env.NoHelpers && slices.Contains([]string{"plan", "apply", "run", "exec"}, name) {
		o := newOutput(env, &f)
		o.fail(errNoHelpers)
		return o.end(exitFailed, summary{})
	}
	return runs[name](ctx, env, &f, pos)
}

var errNoHelpers = errors.New(`winch: this binary has no host helpers, so it cannot work on hosts.
It was probably built with go install, which cannot include them.
Install a release: curl -fsSL https://winchstack.app/install.sh | sh`)

func version(_ context.Context, env Env, _ *flags, args []string) int {
	if len(args) != 0 {
		printError(env.stderr, "winch: version takes no arguments")
		return exitInvalid
	}
	line := fmt.Sprintf("winch %s %s/%s", env.Version, runtime.GOOS, runtime.GOARCH)
	if env.NoHelpers {
		line += " (built without host helpers)"
	}
	fmt.Fprintln(env.stdout, line)
	return exitOK
}

// flagSet returns the parser of the flags of cmd, which sets f.
func flagSet(cmd command, f *flags) *flag.FlagSet {
	fs := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	for _, fd := range cmd.flags {
		name := strings.TrimPrefix(fd.name, "--")
		switch name {
		case "inventory":
			fs.StringVar(&f.inventory, name, "", "")
		case "set":
			fs.Func(name, "", func(s string) error {
				f.set = append(f.set, s)
				return nil
			})
		case "json":
			fs.BoolVar(&f.json, name, false, "")
		case "yes":
			fs.BoolVar(&f.yes, name, false, "")
		case "check":
			fs.Func(name, "", func(s string) error {
				f.check = &s
				return nil
			})
		case "exit-code":
			fs.BoolVar(&f.exitCode, name, false, "")
		case "hosts":
			fs.Func(name, "", notEmpty(&f.hosts))
		case "stages":
			fs.Func(name, "", notEmpty(&f.stages))
		case "user":
			fs.Func(name, "", func(s string) error {
				f.users = append(f.users, s)
				return nil
			})
		case "batch":
			fs.BoolVar(&f.batch, name, false, "")
		case "host":
			fs.Func(name, "", notEmpty(&f.host))
		}
	}
	return fs
}

func commandNamed(name string) (command, bool) {
	i := slices.IndexFunc(commands, func(c command) bool { return c.name == name })
	if i < 0 {
		return command{}, false
	}
	return commands[i], true
}

// printError writes an error line, red on a terminal.
func printError(w *color.Writer, msg string) {
	color.Fprint(w, color.Text{{Style: color.Red, Text: secret.PrintableLines(msg) + "\n"}})
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
		fmt.Fprintln(env.stdout, "ok")
	}
	return o.end(exitOK, summary{})
}

// identity returns the source of the age identity.
func (env Env) identity() (secret.Identity, error) {
	switch {
	case env.AgeCmd != "" && env.AgeKey != "":
		return secret.Identity{}, errors.New("winch: WINCH_AGE_IDENTITY_CMD and WINCH_AGE_KEY are both set")
	case env.AgeCmd != "":
		return secret.Identity{Cmd: env.AgeCmd, Dir: env.Dir}, nil
	case filepath.IsAbs(env.AgeKey):
		return secret.Identity{Path: env.AgeKey}, nil
	case env.AgeKey != "":
		return secret.Identity{Path: filepath.Join(env.Dir, env.AgeKey)}, nil
	case env.Home != "":
		return secret.Identity{Path: filepath.Join(env.Home, ".config", "winch", "age.key")}, nil
	}
	return secret.Identity{}, nil
}

func (o *output) load(ctx context.Context, f *flags, cmd string, args []string) (*project.Project, bool) {
	if len(args) > 1 {
		o.fail(fmt.Errorf("winch: %s takes one pipeline", cmd))
		return nil, false
	}
	var name string
	if len(args) == 1 {
		name = args[0]
	}
	return o.loadWith(f, cmd, func(keys project.Keys) (*project.Project, error) {
		return project.Load(ctx, o.env.Dir, f.inventory, name, f.set, keys)
	})
}

// loadWith loads the project with load and selects the hosts and stages of
// the flags.
func (o *output) loadWith(f *flags, cmd string, load func(project.Keys) (*project.Project, error)) (*project.Project, bool) {
	identity, err := o.env.identity()
	if err != nil {
		o.fail(err)
		return nil, false
	}
	p, err := load(project.Keys{Identity: identity, Filter: o.env.Filter})
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
	return env.Connect(!serial), run.Options{Serial: serial, Progress: env.Progress}
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
	p, ok := o.load(ctx, f, "plan", args)
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

var hashRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

func apply(ctx context.Context, env Env, f *flags, args []string) int {
	o := newOutput(env, f)
	if !checkHash(o, f) {
		return o.end(exitInvalid, summary{})
	}
	p, ok := o.load(ctx, f, "apply", args)
	if !ok {
		return o.end(exitInvalid, summary{})
	}
	return o.apply(ctx, f, p, append([]string{"apply"}, args...))
}

func checkHash(o *output, f *flags) bool {
	if f.check != nil && !hashRe.MatchString(*f.check) {
		o.fail(fmt.Errorf("winch: --check %q: a plan hash has 16 hex characters, such as a3f9c2e1d07b4c58", *f.check))
		return false
	}
	return true
}

// apply plans, asks, and applies the pipeline of p. words are the command
// and its arguments, for the command that applies the plan.
func (o *output) apply(ctx context.Context, f *flags, p *project.Project, words []string) int {
	env := o.env
	connect, opts := env.sessions(f)
	opts.Keep = true
	pl := run.MakePlan(ctx, p, connect, opts)
	defer pl.Close()
	o.plan(pl)
	s := summary{plan: pl}
	code := failedCode(pl.Failed)
	if hash := pl.Hash(); f.check != nil && *f.check != hash {
		o.fail(fmt.Errorf("winch: the plan hash is %s, not %s; nothing changed", hash, *f.check))
		return o.end(worst(code, exitHash), s)
	}
	if !pl.HasWork() {
		return o.end(code, s)
	}
	// After an interrupt, apply starts no host, so there is nothing to ask:
	// the hosts with work fail as interrupted. Gone records alone are winch's
	// own records, not managed state.
	if pl.HasChanges() && f.check == nil && !f.yes && ctx.Err() == nil {
		if !env.Terminal {
			s.command = applyCommand(words, f, pl.Hash())
			if o.ev == nil {
				fmt.Fprintf(env.stdout, "To apply, run: %s\n", s.command)
			}
			return o.end(worst(code, exitConfirm), s)
		}
		if !ask(ctx, env) {
			fmt.Fprintln(env.stderr, "Nothing changed.")
			return o.end(code, s)
		}
	}
	rep := run.Text(env.stdout, env.stderr)
	if o.ev != nil {
		rep = o.ev
	}
	s.apply = run.Apply(ctx, pl, connect, rep)
	return o.end(worst(code, failedCode(s.apply.Failed)), s)
}

func runModule(ctx context.Context, env Env, f *flags, args []string) int {
	o := newOutput(env, f)
	if len(args) < 2 {
		o.fail(errors.New("winch: run needs a host pattern and a module"))
		return o.end(exitInvalid, summary{})
	}
	if !checkHash(o, f) {
		return o.end(exitInvalid, summary{})
	}
	p, ok := o.loadCommand(ctx, f, project.Command{Name: "run", Pattern: args[0], Module: args[1], Args: args[2:]})
	if !ok {
		return o.end(exitInvalid, summary{})
	}
	return o.apply(ctx, f, p, append([]string{"run"}, args...))
}

func execCommand(ctx context.Context, env Env, f *flags, args []string) int {
	o := newOutput(env, f)
	if f.command == "" {
		o.fail(errors.New("winch exec: put the command after --, such as winch exec all -- uptime"))
		return o.end(exitInvalid, summary{})
	}
	if len(args) != 1 {
		o.fail(errors.New("winch: exec needs one host pattern before --"))
		return o.end(exitInvalid, summary{})
	}
	p, ok := o.loadCommand(ctx, f, project.Command{Name: "exec", Pattern: args[0]})
	if !ok {
		return o.end(exitInvalid, summary{})
	}
	connect, opts := env.sessions(f)
	results := run.Exec(ctx, p.Name, p.Pipeline.Stages[0].Targets, f.command, connect, opts)
	if o.ev != nil {
		o.ev.Exec(results)
	} else {
		run.WriteExec(env.stdout, env.stderr, results)
	}
	failed := map[string]error{}
	code := exitOK
	for _, r := range results {
		if r.Err != nil {
			failed[r.Host] = r.Err
		}
		if r.ExitCode != 0 {
			code = exitFailed
		}
	}
	return o.end(worst(code, failedCode(failed)), summary{})
}

// loadCommand loads the project with the pipeline of c.
func (o *output) loadCommand(ctx context.Context, f *flags, c project.Command) (*project.Project, bool) {
	return o.loadWith(f, c.Name, func(keys project.Keys) (*project.Project, error) {
		return project.LoadCommand(ctx, o.env.Dir, f.inventory, keys, c)
	})
}

// ask asks for confirmation. An interrupt answers no. Keys typed before the
// question do not answer it.
func ask(ctx context.Context, env Env) bool {
	if f, ok := env.In.(*os.File); ok {
		if err := discardInput(f); err != nil {
			fmt.Fprintf(env.stderr, "winch: discard the typed input: %v\n", err)
			return false
		}
	}
	fmt.Fprint(env.stderr, "Apply these changes? [y/N] ")
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
		fmt.Fprintln(env.stderr)
		return false
	}
}

// applyCommand is the command that applies the plan with the hash. words are
// the command and its arguments.
func applyCommand(words []string, f *flags, hash string) string {
	cmd := "winch"
	for _, w := range words {
		cmd += " " + quote(w)
	}
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
