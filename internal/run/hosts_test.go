package run_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/session"
)

// spec: Templates and expressions/Data; Running a pipeline/Plan
func TestPlanReadsFactsOfOtherHosts(t *testing.T) {
	tests := []struct {
		name    string
		content string
		reads   int
		want    string
	}{
		{name: "read", content: `!expr 'match("backup")[0].facts.os.codename'`, reads: 1, want: "forky"},
		{name: "read of all hosts", content: `!expr 'join(map(match("all"), .facts.os.codename), ",")'`, reads: 1, want: "trixie,forky"},
		{name: "no read", content: "trixie", want: "trixie"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := loadWeb1(t, map[string]string{
				"inventories/test.yaml": "hosts:\n  web1: {}\n  backup: {}\n",
				"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/backup-os\n          content: " + tt.content + "\n",
			})
			if err := p.Select(project.Selection{Hosts: "web1"}); err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			h.SetFacts("backup", facts.Facts{OS: facts.OS{ID: "debian", Codename: "forky"}})
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			plan.Close()
			if len(plan.Failed) > 0 {
				t.Fatalf("failed: %v", plan.Failed)
			}
			if n := h.FactsReads["backup"]; n != tt.reads {
				t.Errorf("facts of backup read %d times, want %d", n, tt.reads)
			}
			if n := h.FactsReads["web1"]; n != 1 {
				t.Errorf("facts of web1 read %d times, want 1", n)
			}
			if len(plan.Hosts) != 1 || plan.Hosts[0].Name != "web1" {
				t.Errorf("plan hosts = %v, want web1", plan.Hosts)
			}
			if got := string(plan.Stages[0].Hosts[0].Steps[0].Step.Args.(*module.File).Data); got != tt.want {
				t.Errorf("content = %q, want %q", got, tt.want)
			}
			if h.Open != 0 {
				t.Errorf("%d connections are still open", h.Open)
			}
		})
	}
}

// spec: Templates and expressions/Data
func TestPlanFactsReadFails(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nvars:\n  backup_os: !expr 'match(\"backup\")[0].facts.os.codename'\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n  web3: {}\n  web4: {}\n  backup: {}\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: web1,web2,web3,web4
    steps:
      - file:
          path: /etc/backup-os
          content: !expr vars.backup_os
        when: !expr host.name == "web4"
      - file:
          path: /etc/backup-os
          content: !expr 'match("backup")[0].facts.os.codename'
        when: !expr host.name == "web1"
      - recipe: backup
        when: !expr host.name == "web3"
`,
		"recipes/backup/recipe.yaml":       "steps:\n  - file:\n      path: /etc/backup-os\n      template: os.tmpl\n",
		"recipes/backup/templates/os.tmpl": "{{ range match \"backup\" }}{{ .facts.os.codename }}{{ end }}\n",
	})
	h := fakehost.New()
	h.SetUnreachable("backup")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	plan.Close()
	for _, host := range []string{"web1", "web3", "web4"} {
		err := plan.Failed[host]
		if err == nil || !strings.Contains(err.Error(), "read the facts of backup: ssh: connect to host backup: ") {
			t.Errorf("%s error = %v, want the error of the facts of backup", host, err)
		}
		if errors.Is(err, session.ErrUnreachable) {
			t.Errorf("%s is unreachable, but only backup is", host)
		}
	}
	if err := plan.Failed["web2"]; err != nil {
		t.Errorf("web2 error = %v", err)
	}
	if _, ok := plan.Failed["backup"]; ok {
		t.Errorf("backup fails, but the plan has no step for it")
	}
}

// spec: Inventory; Templates and expressions/Data
func TestFactsSessionSharedDestination(t *testing.T) {
	p := loadWeb1(t, map[string]string{
		"inventories/test.yaml": "hosts:\n  web1: {}\n  db2: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: web1\n    steps:\n      - file:\n          path: /etc/db-os\n          content: !expr 'match(\"db2\")[0].facts.os.codename'\n",
	})
	h := fakehost.New()
	for _, host := range []string{"web1", "db2"} {
		h.SetDestination(host, protocol.Destination{HostName: "192.0.2.10", Port: "22"})
	}
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	plan.Close()
	if err := plan.Failed["web1"]; err == nil || !strings.Contains(err.Error(), "host db2 has the same SSH destination") {
		t.Errorf("web1 error = %v, want the shared destination", err)
	}
	if _, ok := plan.Failed["db2"]; ok {
		t.Errorf("db2 fails, but the plan has no step for it")
	}
	if n := h.FactsReads["db2"]; n != 0 {
		t.Errorf("facts of db2 read %d times, want 0", n)
	}
}
