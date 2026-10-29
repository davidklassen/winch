package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"slices"
	"time"

	"github.com/davidklassen/winch/internal/cli"
	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/progress"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/session"
)

func main() {
	filter := secret.NewFilter()
	display := progress.New(os.Stderr, filter.Parts, cli.IsTerminal(os.Stderr) && os.Getenv("TERM") != "dumb",
		func() int { return cli.TerminalWidth(os.Stderr) }, time.Now)
	stdout, errOut := display.Writer(os.Stdout), display.Writer(os.Stderr)
	stderr := color.NewWriter(errOut, filter.Parts, false)
	// The first Ctrl-C ends ctx: no new step starts, and exec commands stop.
	// The second ends the sessions.
	ctx, stop := context.WithCancel(context.Background())
	sessions, kill := context.WithCancel(context.Background())
	// Other commands run no steps, so a Ctrl-C ends them at once. A third
	// Ctrl-C ends winch.
	if len(os.Args) > 1 && slices.Contains([]string{"plan", "apply", "run", "exec"}, os.Args[1]) {
		msg := "winch: interrupted; the running steps finish. Press Ctrl-C again to end the sessions."
		if os.Args[1] == "exec" {
			msg = "winch: interrupted; the commands stop. Press Ctrl-C again to end the sessions."
		}
		interrupts := make(chan os.Signal, 2)
		signal.Notify(interrupts, os.Interrupt)
		go func() {
			<-interrupts
			fmt.Fprintln(stderr, msg)
			stop()
			<-interrupts
			signal.Stop(interrupts)
			kill()
		}()
	}
	// Without a home directory and the WINCH_AGE_ variables, only a project
	// with secrets fails: it cannot read the identity.
	home, _ := os.UserHomeDir()
	end := display.Start()
	code := cli.Main(ctx, os.Args[1:], cli.Env{
		Dir:      ".",
		In:       os.Stdin,
		Out:      stdout,
		Err:      errOut,
		Terminal: cli.IsTerminal(os.Stdin) && cli.IsTerminal(os.Stderr),
		ColorOut: cli.UseColor(cli.IsTerminal(os.Stdout), os.Getenv),
		ColorErr: cli.UseColor(cli.IsTerminal(os.Stderr), os.Getenv),
		Connect: func(batch bool) run.Connect {
			return connect(sessions, stderr, display, batch)
		},
		Progress: display,
		Home:     home,
		AgeKey:   os.Getenv("WINCH_AGE_KEY"),
		AgeCmd:   os.Getenv("WINCH_AGE_IDENTITY_CMD"),
		Filter:   filter,
	})
	end()
	os.Exit(code)
}

// connect opens sessions that live until sessions ends, not until the
// context of the run ends: a session finishes its running step after the
// first Ctrl-C. Without batch, ssh can ask a question: the display holds
// during the login.
func connect(sessions context.Context, notes *color.Writer, display *progress.Display, batch bool) run.Connect {
	var hold func() func()
	if !batch {
		hold = display.Hold
	}
	hello := protocol.Hello{Run: rand.Text()[:8], Started: time.Now().UTC()}
	if u, err := user.Current(); err == nil {
		hello.User = u.Username
	}
	hello.Machine, _ = os.Hostname()
	bins := helperbin.Binaries()
	return func(_ context.Context, proj string, h project.Host) (run.Conn, error) {
		hello := hello
		hello.Project = proj
		s, err := session.Open(sessions, session.Config{
			Host:     h.Name,
			Address:  h.Address,
			User:     h.User,
			Binaries: bins,
			Hello:    hello,
			Progress: notes,
			Hold:     hold,
			Batch:    batch,
		})
		if errors.Is(err, session.ErrUnreachable) {
			err = run.MarkUnreachable(err)
		}
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
		return s, nil
	}
}
