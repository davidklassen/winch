package run

import (
	"cmp"
	"context"
	"fmt"
	"sync"

	"github.com/davidklassen/winch/internal/project"
)

// rollout runs work on each host of a stage, at most limit hosts at a time
// (0: no limit). Hosts start in inventory order. With serial, rollout opens
// the sessions itself, one at a time; else each host opens its own. With a
// limit, a failure keeps the hosts that did not start from starting. After
// an interrupt, no host starts. work closes its session. rollout
// returns the error of each host.
func rollout(ctx context.Context, stage string, hosts []project.Host, limit int, serial bool,
	open func(project.Host) (Conn, error), work func(i int, c Conn) error) []error {
	errs := make([]error, len(hosts))
	var mu sync.Mutex
	failed := ""
	fail := func(i int, err error) {
		mu.Lock()
		defer mu.Unlock()
		errs[i] = err
		if failed == "" {
			failed = hosts[i].Name
		}
	}
	slots := make(chan struct{}, cmp.Or(limit, max(len(hosts), 1)))
	release := func() { <-slots }
	var wg sync.WaitGroup
	for i, h := range hosts {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			errs[i] = ErrInterrupted
			continue
		}
		mu.Lock()
		first := failed
		mu.Unlock()
		switch {
		case ctx.Err() != nil:
			errs[i] = ErrInterrupted
			release()
			continue
		case limit > 0 && first != "":
			errs[i] = fmt.Errorf("not started: %s failed in stage %s", first, stage)
			release()
			continue
		}
		run := func(conn Conn) {
			defer wg.Done()
			defer release()
			if conn == nil {
				var err error
				if conn, err = open(h); err != nil {
					fail(i, err)
					return
				}
			}
			if err := work(i, conn); err != nil {
				fail(i, err)
			}
		}
		var conn Conn
		if serial {
			var err error
			if conn, err = open(h); err != nil {
				fail(i, err)
				release()
				continue
			}
		}
		wg.Add(1)
		go run(conn)
	}
	wg.Wait()
	return errs
}
