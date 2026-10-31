package run_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
)

// spec: Remote execution/Sessions
func TestApplyKeepsPlanSessions(t *testing.T) {
	gone := protocol.Check{Pipeline: "site", Stage: "db"}
	tests := []struct {
		name string
		// setup runs before the plan, and wait during the question.
		setup, wait func(h *fakehost.Hosts)
		open        int
		connects    map[string]int
		// fail is the error of web1, or "".
		fail string
	}{
		{name: "alive", open: 2, connects: map[string]int{"web1": 1, "web2": 1, "web3": 1}},
		{name: "died", wait: func(h *fakehost.Hosts) { h.Kill("web1") },
			open: 2, connects: map[string]int{"web1": 2, "web2": 1, "web3": 1}},
		{name: "died and the destination changed", wait: func(h *fakehost.Hosts) {
			h.Kill("web1")
			h.SetDestination("web1", protocol.Destination{HostName: "192.0.2.99", Port: "22"})
		}, open: 2, connects: map[string]int{"web1": 1, "web2": 1, "web3": 1},
			fail: "failed: the SSH destination changed since the plan: web1:22 (uid 0) → 192.0.2.99:22 (uid 0); run winch plan again and check the new destination"},
		{name: "gone records only", setup: func(h *fakehost.Hosts) { h.Pend("web3", gone) },
			open: 3, connects: map[string]int{"web1": 1, "web2": 1, "web3": 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			h.SetFile("web3", "/etc/motd", "hello\nworld\n")
			h.SetFile("web2", "/etc/issue", "Debian\n")
			if tt.setup != nil {
				tt.setup(h)
			}
			plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{Keep: true})
			if h.Open != tt.open {
				t.Errorf("%d sessions are open after the plan, want %d of the hosts with work", h.Open, tt.open)
			}
			if tt.wait != nil {
				tt.wait(h)
			}
			var out, errOut bytes.Buffer
			o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
			plan.Close()
			for host, n := range tt.connects {
				if h.Connects[host] != n {
					t.Errorf("%s: %d connects, want %d", host, h.Connects[host], n)
				}
			}
			if tt.fail != "" {
				if err := o.Failed["web1"]; err == nil || err.Error() != tt.fail {
					t.Errorf("web1 error = %v, want %s", err, tt.fail)
				}
				if _, ok := h.File("web1", "/etc/motd"); ok {
					t.Error("web1 /etc/motd was written")
				}
			} else if !o.OK() {
				t.Fatalf("apply failed: %v\n%s", o.Failed, errOut.String())
			} else if c, _ := h.File("web1", "/etc/motd"); c != "hello\nworld\n" {
				t.Errorf("web1 /etc/motd = %q", c)
			}
			if c, _ := h.File("web2", "/etc/motd"); c != "hello\nworld\n" {
				t.Errorf("web2 /etc/motd = %q", c)
			}
			if _, ok := h.File("web2", "/etc/issue"); ok {
				t.Error("web2 /etc/issue exists")
			}
			if got := h.ChecksOf("web3"); len(got) != 0 {
				t.Errorf("web3 records = %v, want none", got)
			}
			if h.Open != 0 {
				t.Errorf("%d sessions are still open", h.Open)
			}
		})
	}
	t.Run("no answer", func(t *testing.T) {
		h := fakehost.New()
		plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{Keep: true})
		if h.Open != 3 {
			t.Errorf("%d sessions are open after the plan, want 3", h.Open)
		}
		plan.Close()
		if h.Open != 0 {
			t.Errorf("%d sessions are still open", h.Open)
		}
	})
	t.Run("a failed close of a host without work", func(t *testing.T) {
		h := fakehost.New()
		h.SetFile("web3", "/etc/motd", "hello\nworld\n")
		h.FailClose("web3")
		plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{Keep: true})
		defer plan.Close()
		if err := plan.Failed["web3"]; err == nil || !strings.Contains(err.Error(), "exit status 255") {
			t.Errorf("web3 error = %v, want the close error", err)
		}
	})
}
