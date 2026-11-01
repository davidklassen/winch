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
			old := map[string]string{"web1": "22", "web3": "2200"}
			for host, port := range old {
				h.SetDestination(host, protocol.Destination{HostName: "192.0.2.10", Port: port})
			}
			plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{})
			for _, host := range []string{"web1", "web3"} {
				h.SetDestination(host, tt.dest)
			}
			o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&bytes.Buffer{}), plain(&bytes.Buffer{})))
			for host, port := range old {
				want := "the SSH destination changed since the plan: 192.0.2.10:" + port + " (uid 0) → " + tt.want + "; run winch plan again and check the new destination"
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

// spec: Inventory
func TestPlanSharedDestination(t *testing.T) {
	t.Run("same host name with other ports", func(t *testing.T) {
		h := fakehost.New()
		h.SetDestination("web1", protocol.Destination{HostName: "192.0.2.10", Port: "2201"})
		h.SetDestination("web2", protocol.Destination{HostName: "192.0.2.10", Port: "2202"})
		plan := run.MakePlan(context.Background(), load(t, "192.0.2.10"), h.Connector(), run.Options{})
		if len(plan.Failed) != 0 {
			t.Errorf("failed hosts: %v", plan.Failed)
		}
	})
	t.Run("same host name and port", func(t *testing.T) {
		h := fakehost.New()
		h.SetDestination("web1", protocol.Destination{HostName: "Mail.acme.com", Port: "2222"})
		h.SetDestination("web3", protocol.Destination{HostName: "mail.acme.com", Port: "2222"})
		plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{})
		want := map[string]string{
			"web1": `host web3 has the same SSH destination, Mail.acme.com:2222; keep one host for this destination, or give each host its own address or port`,
			"web3": `host web1 has the same SSH destination, mail.acme.com:2222; keep one host for this destination, or give each host its own address or port`,
		}
		for host, w := range want {
			if err := plan.Failed[host]; err == nil || err.Error() != w {
				t.Errorf("%s error = %v, want %s", host, err, w)
			}
		}
		if err := plan.Failed["web2"]; err != nil {
			t.Errorf("web2 error = %v", err)
		}
		if h.Connects["web1"] != 0 || h.Connects["web3"] != 0 {
			t.Errorf("connects = %v, want none to web1 and web3", h.Connects)
		}
	})
	t.Run("same private IP behind other jump hosts", func(t *testing.T) {
		h := fakehost.New()
		for host, jump := range map[string]string{"web1": "bastion-eu", "web3": "bastion-us"} {
			h.SetDestination(host, protocol.Destination{HostName: "10.0.0.5", Port: "22"})
			h.SetJump(host, jump)
		}
		plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{})
		if len(plan.Failed) != 0 {
			t.Errorf("failed hosts: %v", plan.Failed)
		}
	})
	t.Run("same private IP behind one jump host", func(t *testing.T) {
		h := fakehost.New()
		for _, host := range []string{"web1", "web3"} {
			h.SetDestination(host, protocol.Destination{HostName: "10.0.0.5", Port: "22"})
			h.SetJump(host, "bastion-eu")
		}
		plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{})
		want := map[string]string{
			"web1": `host web3 has the same SSH destination, 10.0.0.5:22 through bastion-eu; keep one host for this destination, or give each host its own address or port`,
			"web3": `host web1 has the same SSH destination, 10.0.0.5:22 through bastion-eu; keep one host for this destination, or give each host its own address or port`,
		}
		for host, w := range want {
			if err := plan.Failed[host]; err == nil || err.Error() != w {
				t.Errorf("%s error = %v, want %s", host, err, w)
			}
		}
	})
	t.Run("three hosts", func(t *testing.T) {
		h := fakehost.New()
		for _, host := range []string{"web1", "web2", "web3"} {
			h.SetDestination(host, protocol.Destination{HostName: "192.0.2.10", Port: "22"})
		}
		plan := run.MakePlan(context.Background(), load(t, "web3"), h.Connector(), run.Options{})
		want := map[string]string{
			"web1": `host web2 has the same SSH destination, 192.0.2.10:22; keep one host for this destination, or give each host its own address or port`,
			"web2": `host web1 has the same SSH destination, 192.0.2.10:22; keep one host for this destination, or give each host its own address or port`,
			"web3": `host web1 has the same SSH destination, 192.0.2.10:22; keep one host for this destination, or give each host its own address or port`,
		}
		for host, w := range want {
			if err := plan.Failed[host]; err == nil || err.Error() != w {
				t.Errorf("%s error = %v, want %s", host, err, w)
			}
		}
	})
	t.Run("hosts of skipped stages", func(t *testing.T) {
		h := fakehost.New()
		for _, host := range []string{"web1", "web3"} {
			h.SetDestination(host, protocol.Destination{HostName: "192.0.2.10", Port: "22"})
		}
		p := load(t, "web3")
		p.Pipeline.Stages[0].Skipped = true
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		if len(plan.Failed) != 0 {
			t.Errorf("failed hosts: %v", plan.Failed)
		}
	})
}
