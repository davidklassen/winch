package run_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
)

// spec: Running a pipeline/Plan
func TestApplyDestinationChanged(t *testing.T) {
	gone := protocol.Check{Pipeline: "site", Stage: "db"}
	tests := []struct {
		name string
		dest protocol.Destination
		want string
	}{
		{"another user", protocol.Destination{User: "admin", UID: 1000, HostName: "192.0.2.10", Port: "22"}, "admin@192.0.2.10:22 (uid 1000)"},
		{"another uid", protocol.Destination{UID: 1000, HostName: "192.0.2.10", Port: "22"}, "192.0.2.10:22 (uid 1000)"},
		{"another host name", protocol.Destination{HostName: "2001:db8::1", Port: "22"}, "[2001:db8::1]:22 (uid 0)"},
		{"another port", protocol.Destination{HostName: "192.0.2.10", Port: "2222"}, "192.0.2.10:2222 (uid 0)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			h.SetFile("web3", "/etc/motd", "hello\nworld\n")
			h.Pend("web3", gone)
			for _, host := range []string{"web1", "web3"} {
				h.SetDestination(host, protocol.Destination{HostName: "192.0.2.10", Port: "22"})
			}
			plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{})
			for _, host := range []string{"web1", "web3"} {
				h.SetDestination(host, tt.dest)
			}
			o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&bytes.Buffer{}), plain(&bytes.Buffer{})))
			want := "failed: the SSH destination changed since the plan: 192.0.2.10:22 (uid 0) → " + tt.want
			for _, host := range []string{"web1", "web3"} {
				if err := o.Failed[host]; err == nil || err.Error() != want {
					t.Errorf("%s error = %v, want %s", host, err, want)
				}
			}
			if _, ok := h.File("web1", "/etc/motd"); ok {
				t.Error("web1 /etc/motd was written")
			}
			if c, _ := h.File("web2", "/etc/motd"); c != "hello\nworld\n" {
				t.Errorf("web2 /etc/motd = %q", c)
			}
			if got := h.ChecksOf("web3"); len(got) != 1 || got[0] != gone {
				t.Errorf("web3 records = %v, want %v", got, gone)
			}
			if h.Open != 0 {
				t.Errorf("%d connections are still open", h.Open)
			}
		})
	}
}
