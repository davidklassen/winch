package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/davidklassen/winch/internal/cli"
	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/session"
)

func main() {
	os.Exit(cli.Main(context.Background(), os.Args[1:], cli.Env{
		Dir:      ".",
		In:       os.Stdin,
		Out:      os.Stdout,
		Err:      os.Stderr,
		Terminal: cli.IsTerminal(os.Stdin) && cli.IsTerminal(os.Stderr),
		Connect:  connect(),
	}))
}

func connect() run.Connect {
	hello := protocol.Hello{Run: rand.Text()[:8], Started: time.Now().UTC()}
	if u, err := user.Current(); err == nil {
		hello.User = u.Username
	}
	hello.Machine, _ = os.Hostname()
	bins := helperbin.Binaries()
	return func(ctx context.Context, h project.Host) (run.Conn, error) {
		s, err := session.Open(ctx, session.Config{
			Host:     h.Name,
			Address:  h.Address,
			User:     h.User,
			Binaries: bins,
			Hello:    hello,
			Progress: os.Stderr,
		})
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
		return s, nil
	}
}
