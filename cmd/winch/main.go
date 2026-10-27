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
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/session"
)

func main() {
	filter := secret.NewFilter()
	stderr := color.NewWriter(os.Stderr, filter.Parts, false)
	// The first Ctrl-C ends ctx: no new step or exec command starts. The second ends the
	// sessions.
	ctx, stop := context.WithCancel(context.Background())
	sessions, kill := context.WithCancel(context.Background())
	// Other commands run no steps, so a Ctrl-C ends them at once. A third
	// Ctrl-C ends winch.
	if len(os.Args) > 1 && slices.Contains([]string{"plan", "apply", "run", "exec"}, os.Args[1]) {
		interrupts := make(chan os.Signal, 2)
		signal.Notify(interrupts, os.Interrupt)
		go func() {
			<-interrupts
			fmt.Fprintln(stderr, "winch: interrupted; the running steps finish. Press Ctrl-C again to end the sessions.")
			stop()
			<-interrupts
			signal.Stop(interrupts)
			kill()
		}()
	}
	// Without a home directory and the WINCH_AGE_ variables, only a project
	// with secrets fails: it cannot read the identity.
	home, _ := os.UserHomeDir()
	os.Exit(cli.Main(ctx, os.Args[1:], cli.Env{
		Dir:      ".",
		In:       os.Stdin,
		Out:      os.Stdout,
		Err:      os.Stderr,
		Terminal: cli.IsTerminal(os.Stdin) && cli.IsTerminal(os.Stderr),
		ColorOut: cli.UseColor(cli.IsTerminal(os.Stdout), os.Getenv),
		ColorErr: cli.UseColor(cli.IsTerminal(os.Stderr), os.Getenv),
		Connect: func(batch bool) run.Connect {
			return connect(sessions, stderr, batch)
		},
		Home:   home,
		AgeKey: os.Getenv("WINCH_AGE_KEY"),
		AgeCmd: os.Getenv("WINCH_AGE_IDENTITY_CMD"),
		Filter: filter,
	}))
}

// connect opens sessions that live until sessions ends, not until the
// context of the run ends: a session finishes its running step after the
// first Ctrl-C.
func connect(sessions context.Context, progress *color.Writer, batch bool) run.Connect {
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
			Progress: progress,
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
