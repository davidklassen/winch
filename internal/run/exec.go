package run

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

// ExecResult is the result of winch exec on one host. Ran is true when the
// command ran. Err is set when the host failed or was unreachable, also
// after the command ran.
type ExecResult struct {
	Host string
	module.ExecResult
	Ran bool
	Err error
}

// Exec runs command on the hosts at the same time. With opts.Serial, the
// sessions start one at a time. Each session closes after its command. When
// ctx ends, the commands stop.
func Exec(ctx context.Context, proj string, hosts []project.Host, command string, connect Connect, opts Options) []ExecResult {
	results := make([]ExecResult, len(hosts))
	open := func(h project.Host) (Conn, error) { return connect(context.WithoutCancel(ctx), proj, h) }
	errs := rollout(ctx, "exec", hosts, 0, opts, open, func(i int, c Conn) error {
		if ctx.Err() != nil {
			return errors.Join(ErrInterrupted, c.Close())
		}
		res, err := c.Exec(ctx, command)
		// The command can fail to start when the interrupt comes first.
		if err != nil && ctx.Err() != nil {
			err = ErrInterrupted
		}
		results[i].ExecResult, results[i].Ran = res, err == nil
		if cerr := c.Close(); err == nil {
			err = cerr
		}
		return err
	})
	for i, h := range hosts {
		results[i].Host, results[i].Err = h.Name, errs[i]
	}
	return results
}

// WriteExec prints a block per output: the hosts, the output, and the exit
// status when it is not 0. Hosts with the same output and exit code share a
// block. Host errors go to errOut.
func WriteExec(out, errOut *color.Writer, results []ExecResult) {
	type group struct {
		hosts []string
		res   module.ExecResult
	}
	var groups []*group
	for _, r := range results {
		if !r.Ran {
			continue
		}
		i := slices.IndexFunc(groups, func(g *group) bool { return g.res == r.ExecResult })
		if i < 0 {
			groups = append(groups, &group{res: r.ExecResult})
			i = len(groups) - 1
		}
		groups[i].hosts = append(groups[i].hosts, r.Host)
	}
	for _, g := range groups {
		var t color.Text
		header(&t, "", groupName(g.hosts))
		if o := strings.TrimSuffix(g.res.Output, "\n"); o != "" {
			for line := range strings.SplitSeq(secret.PrintableLines(o), "\n") {
				t.Add(color.Plain, "  "+line+"\n")
			}
		}
		switch {
		case g.res.Signal != 0:
			t.Add(color.Red, fmt.Sprintf("  killed by signal %d\n", g.res.Signal))
		case g.res.ExitCode != 0:
			t.Add(color.Red, fmt.Sprintf("  exit status %d\n", g.res.ExitCode))
		}
		t.Add(color.Plain, "\n")
		color.Fprint(out, t)
	}
	for _, r := range results {
		if r.Err != nil {
			hostError(errOut, r.Host, r.Err.Error())
		}
	}
}

// Exec writes an exec event per host, and a host event for each host that
// failed.
func (e *Events) Exec(results []ExecResult) {
	for _, r := range results {
		if r.Ran {
			e.Write("exec", struct {
				Host     string `json:"host"`
				Output   string `json:"output"`
				ExitCode int    `json:"exit_code"`
			}{r.Host, r.Output, r.ExitCode})
		}
		if r.Err != nil {
			e.Host(HostEvent{Phase: "exec", Host: r.Host, Status: hostStatus(r.Err), Error: r.Err.Error()})
		}
	}
}
