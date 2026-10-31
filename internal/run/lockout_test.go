package run_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/vmtest"
)

func loadWeb1(t *testing.T, files map[string]string) *project.Project {
	t.Helper()
	all := map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
	}
	for k, v := range files {
		all[k] = v
	}
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, all), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const sshRecipe = `steps:
  - file:
      path: /etc/ssh/sshd_config.d/local.conf
      content: "PasswordAuthentication no\n"
    notify: reload
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`

func lockoutProject(t *testing.T) *project.Project {
	return loadWeb1(t, map[string]string{
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - recipe: ssh
      - file:
          path: /etc/motd
          content: hi
  - name: firewall
    hosts: all
    steps:
      - file:
          path: /etc/nftables.conf
          content: "flush ruleset\n"
      - service:
          name: nftables
          running: true
        confirm_access: true
`,
		"recipes/ssh/recipe.yaml": sshRecipe,
	})
}

func applyWeb1(t *testing.T, p *project.Project, h *fakehost.Hosts) (string, *run.Outcome) {
	t.Helper()
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	return out.String() + errOut.String(), o
}

// spec: Running a pipeline/Lockout protection (the store of the recipe, the
// timer, the second connection)
func TestConfirmAccess(t *testing.T) {
	h := fakehost.New()
	h.SetResult("web1", "nftables", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"reload"}})
	_, o := applyWeb1(t, lockoutProject(t), h)
	if !o.OK() {
		t.Fatalf("apply failed: %v", o.Failed)
	}
	if want := []string{"ssh reload", "access", "confirm", "nftables start", "access", "confirm", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
	want := map[string]protocol.Guard{
		"web1 /etc/ssh/sshd_config.d/local.conf": {Recipe: "ssh", Save: true, Handlers: []string{"ssh.reload"}},
		"web1 ssh":                               {Recipe: "ssh", Save: true, Confirm: true},
		"web1 /etc/motd":                         {Pipeline: "site", Stage: "base"},
		"web1 /etc/nftables.conf":                {Pipeline: "site", Stage: "firewall", Save: true},
		"web1 nftables":                          {Pipeline: "site", Stage: "firewall", Save: true, Confirm: true},
	}
	for k, g := range want {
		if !reflect.DeepEqual(h.Guards[k], g) {
			t.Errorf("guard of %s = %+v, want %+v", k, h.Guards[k], g)
		}
	}
}

// spec: Running a pipeline/Lockout protection (when the second connection
// fails, the old files come back and the host fails)
func TestAccessFails(t *testing.T) {
	h := fakehost.New()
	h.SetResult("web1", "nftables", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"reload"}})
	h.FailAccess("web1")
	out, o := applyWeb1(t, lockoutProject(t), h)
	if o.OK() {
		t.Fatal("apply succeeded without access")
	}
	if want := []string{"ssh reload", "access", "rollback"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
	want := "web1: ssh: failed: handler ssh.reload: service ssh: no new SSH connection works: ssh: connect to host web1 port 22: Connection timed out; the old files are back"
	if !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
	if _, ok := h.File("web1", "/etc/motd"); ok {
		t.Error("the host went on after the rollback")
	}
}

// spec: Running a pipeline/Lockout protection (a user step that changes the
// keys of the login user gets the same protection)
func TestGuardedResult(t *testing.T) {
	h := fakehost.New()
	h.SetResult("web1", "mail", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"changes the sudo rules, which the login user admin needs"}, Guard: true})
	p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - hostname:\n          name: mail\n"})
	_, o := applyWeb1(t, p, h)
	if !o.OK() {
		t.Fatalf("apply failed: %v", o.Failed)
	}
	if want := []string{"access", "confirm", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
	if g := h.Guards["web1 mail"]; !reflect.DeepEqual(g, protocol.Guard{Pipeline: "site", Stage: "base"}) {
		t.Errorf("guard %+v: the step has no confirm_access", g)
	}
}

func rebootProject(t *testing.T, ifRequired string, more string) *project.Project {
	return loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n" + more +
		"      - reboot:\n          if_required: " + ifRequired + "\n          timeout: 30\n"})
}

// spec: Modules/reboot (also when an earlier step of the run requires the
// reboot, and in a handler); CLI/Output (marks); roadmap phase 16 (the apply
// line says that the host rebooted and names the failed units)
func TestRebootStep(t *testing.T) {
	motd := "      - file:\n          path: /etc/motd\n          content: hi\n"
	tests := []struct {
		name          string
		ifRequired    string
		more          string
		pipeline      string
		required      bool
		requiredAfter bool
		boot          *protocol.Boot
		wantPlan      string
		wantApply     string
		wantLog       []string
		wantErr       string
		noConnect     bool
	}{
		{name: "always", ifRequired: "false", wantPlan: "    ~ reboot\n", wantApply: "web1: base: ~ reboot (rebooted)\n", wantLog: []string{"reboot 30s", "access"}},
		{name: "required", ifRequired: "true", required: true, wantPlan: "    ~ reboot if required\n", wantApply: "web1: base: ~ reboot if required (rebooted)\n", wantLog: []string{"reboot 30s", "access"}},
		{name: "degraded", ifRequired: "false", boot: &protocol.Boot{State: "degraded", Failed: []string{"a.service", "b.service"}},
			wantPlan: "    ~ reboot\n", wantApply: "web1: base: ~ reboot (rebooted; degraded, failed units: a.service, b.service)\n", wantLog: []string{"reboot 30s", "access"}},
		{name: "still required", ifRequired: "true", required: true, boot: &protocol.Boot{State: "running", Kernel: "6.12.43+deb13-amd64", Newest: "99.0.0+deb13-amd64"},
			wantPlan: "    ~ reboot if required\n", wantApply: "", wantLog: []string{"reboot 30s"},
			wantErr: "base: failed: reboot if required: the host still needs a reboot after the reboot: running kernel 6.12.43+deb13-amd64, newest kernel 99.0.0+deb13-amd64"},
		{name: "always, still required", ifRequired: "false", required: true, boot: &protocol.Boot{State: "running", Kernel: "6.12.43+deb13-amd64", Newest: "99.0.0+deb13-amd64"},
			wantPlan: "    ~ reboot\n", wantApply: "", wantLog: []string{"reboot 30s"},
			wantErr: "base: failed: reboot: the host still needs a reboot after the reboot: running kernel 6.12.43+deb13-amd64, newest kernel 99.0.0+deb13-amd64"},
		{name: "still required by packages", ifRequired: "true", required: true, boot: &protocol.Boot{State: "running", Kernel: "6.12.43+deb13-amd64", Newest: "6.12.43+deb13-amd64", Packages: []string{"dbus", "libc6"}},
			wantPlan: "    ~ reboot if required\n", wantApply: "", wantLog: []string{"reboot 30s"},
			wantErr: "base: failed: reboot if required: the host still needs a reboot after the reboot: /run/reboot-required lists the packages dbus, libc6"},
		{name: "maybe, with a change", ifRequired: "true", more: motd, wantPlan: "    * reboot if required\n", wantApply: "web1: base: + file /etc/motd\n", wantLog: []string{"access"}},
		{name: "maybe, alone", ifRequired: "true", wantPlan: "0 to change, 1 unchanged", wantApply: "", noConnect: true},
		{name: "an earlier step requires the reboot", ifRequired: "true", more: motd, requiredAfter: true, wantPlan: "    * reboot if required\n",
			wantApply: "web1: base: + file /etc/motd\nweb1: base: ~ reboot if required (rebooted)\n", wantLog: []string{"reboot 30s", "access"}},
		{name: "a reboot in a handler", pipeline: motd + "        notify: restart\n    handlers:\n      restart:\n        - reboot:\n            if_required: false\n            timeout: 30\n",
			wantPlan: "    ! handler base.restart\n", wantApply: "web1: base: + file /etc/motd\nweb1: base: ~ handler base.restart: reboot (rebooted)\n", wantLog: []string{"reboot 30s", "access"}},
		{name: "a handler reboot if required, required by an earlier step", requiredAfter: true, pipeline: motd + "        notify: restart\n    handlers:\n      restart:\n        - reboot:\n            if_required: true\n            timeout: 30\n",
			wantPlan: "    ! handler base.restart\n", wantApply: "web1: base: + file /etc/motd\nweb1: base: ~ handler base.restart: reboot if required (rebooted)\n", wantLog: []string{"reboot 30s", "access"}},
		{name: "a handler reboot if required, not required", pipeline: motd + "        notify: restart\n    handlers:\n      restart:\n        - reboot:\n            if_required: true\n            timeout: 30\n",
			wantPlan: "    ! handler base.restart\n", wantApply: "web1: base: + file /etc/motd\n", wantLog: []string{"access"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			h.SetFacts("web1", facts.Facts{OS: facts.OS{ID: "debian", Version: "13"}, RebootRequired: tt.required})
			if tt.boot != nil {
				h.SetBoot("web1", *tt.boot)
			}
			if tt.requiredAfter {
				h.OnApply = func(host, main string) {
					if main == "/etc/motd" {
						h.SetFacts(host, facts.Facts{OS: facts.OS{ID: "debian", Version: "13"}, RebootRequired: true})
					}
				}
			}
			var p *project.Project
			if tt.pipeline != "" {
				p = loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n" + tt.pipeline})
			} else {
				p = rebootProject(t, tt.ifRequired, tt.more)
			}
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			plan.Write(plain(&out), plain(&errOut))
			if !strings.Contains(out.String(), tt.wantPlan) {
				t.Errorf("plan:\n%s\nwant %q", out.String(), tt.wantPlan)
			}
			out.Reset()
			connects := h.Connects["web1"]
			o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
			if tt.noConnect && h.Connects["web1"] != connects {
				t.Error("apply connected to a host whose plan has only * steps")
			}
			if tt.wantErr == "" && !o.OK() {
				t.Fatalf("apply failed: %v", o.Failed)
			}
			if got := fmt.Sprint(o.Failed); !strings.Contains(got, tt.wantErr) {
				t.Fatalf("apply failed with %s, want %q", got, tt.wantErr)
			}
			var got string
			for line := range strings.Lines(out.String()) {
				if strings.HasPrefix(line, "web1: ") {
					got += line
				}
			}
			if got != tt.wantApply {
				t.Errorf("apply lines %q, want %q", got, tt.wantApply)
			}
			if !slices.Equal(h.Log["web1"], tt.wantLog) {
				t.Errorf("log %q, want %q", h.Log["web1"], tt.wantLog)
			}
			if slices.Contains(tt.wantLog, "reboot 30s") && h.FactsReads["web1"] != 2 {
				t.Errorf("facts read %d times, want 2: plan, and after the reboot", h.FactsReads["web1"])
			}
		})
	}
}

// spec: Running a pipeline/Plan (the hash covers the evaluated steps)
func TestHashCoversConfirmAccess(t *testing.T) {
	hash := func(confirm string) string {
		h := fakehost.New()
		h.SetResult("web1", "nftables", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"reload"}})
		p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - service:\n          name: nftables\n          running: true\n        confirm_access: " + confirm + "\n"})
		return run.MakePlan(context.Background(), p, h.Connector(), run.Options{}).Hash()
	}
	if hash("true") == hash("false") {
		t.Error("the plan hash does not cover confirm_access")
	}
}

// spec: Running a pipeline/Plan (two steps that manage the same thing)
func TestSameHostnameAndTimezone(t *testing.T) {
	for _, tt := range []struct{ module, a, b, want string }{
		{"hostname", "mail", "web", "the host name is also in"},
		{"timezone", "Etc/UTC", "Europe/Berlin", "the time zone is also in"},
	} {
		h := fakehost.New()
		p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - " + tt.module + ":\n          name: " + tt.a + "\n      - " + tt.module + ":\n          name: " + tt.b + "\n"})
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		if err := plan.Failed["web1"]; err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: plan error %v, want %q", tt.module, err, tt.want)
		}
	}
}

// spec: Modules/firewall (a host has at most one firewall step in a run)
func TestTwoFirewalls(t *testing.T) {
	step := "      - name: %s\n        firewall:\n          allow:\n            - tcp: 22\n"
	for _, tt := range []struct{ name, pipeline string }{
		{"one stage", "stages:\n  - name: base\n    hosts: all\n    steps:\n" + fmt.Sprintf(step, "Open SSH") + fmt.Sprintf(step, "Open SSH again")},
		{"two stages", "stages:\n  - name: base\n    hosts: all\n    steps:\n" + fmt.Sprintf(step, "Open SSH") + "  - name: web\n    hosts: all\n    steps:\n" + fmt.Sprintf(step, "Open SSH again")},
	} {
		h := fakehost.New()
		p := loadWeb1(t, map[string]string{"pipelines/site.yaml": tt.pipeline})
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		err := plan.Failed["web1"]
		if err == nil || !strings.Contains(err.Error(), ": Open SSH again: firewall: the firewall is also in ") || !strings.Contains(err.Error(), ": Open SSH: firewall; a host has one firewall step") {
			t.Errorf("%s: plan error %v", tt.name, err)
		}
	}
}

// spec: Modules/firewall (another step manages the firewall file or the unit
// file)
func TestFirewallFiles(t *testing.T) {
	firewall := "      - firewall:\n          allow:\n            - tcp: 22\n"
	file := "      - file:\n          path: /etc/winch/firewall.nft\n          content: \"\"\n"
	unit := "      - unit:\n          name: winch-firewall.service\n          content: \"\"\n"
	dropIn := "      - file:\n          path: /etc/systemd/system/nftables.service.d/winch.conf\n          content: \"\"\n"
	service := "      - service:\n          name: winch-firewall\n          running: false\n"
	for _, tt := range []struct{ name, steps, want string }{
		{"file after", firewall + file, "file /etc/winch/firewall.nft: the path /etc/winch/firewall.nft is also in base: firewall"},
		{"file before", file + firewall, "firewall: the path /etc/winch/firewall.nft is also in base: file /etc/winch/firewall.nft"},
		{"unit", firewall + unit, "the path /etc/systemd/system/winch-firewall.service is also in base: firewall"},
		{"drop-in", firewall + dropIn, "the path /etc/systemd/system/nftables.service.d/winch.conf is also in base: firewall"},
		{"service after", firewall + service, "service winch-firewall: the unit winch-firewall.service is also in base: firewall"},
		{"service before", service + firewall, "firewall: the unit winch-firewall.service is also in base: service winch-firewall"},
	} {
		h := fakehost.New()
		h.SetResult("web1", "winch-firewall", module.Result{Status: module.OK})
		p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n" + tt.steps})
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		if err := plan.Failed["web1"]; err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: plan error %v, want %q", tt.name, err, tt.want)
		}
	}
}

// spec: Running a pipeline/Plan (two steps that manage the same thing);
// Modules/certbot
func TestSameCertificate(t *testing.T) {
	step := func(domains string) string {
		return "      - certbot:\n          name: example.com\n          domains: [" + domains + "]\n          email: a@example.com\n"
	}
	for _, tt := range []struct {
		name, second string
		want         string
	}{
		{"other domains", step("example.com, www.example.com"), "base: certbot example.com: the certificate example.com is also in base: certbot example.com, with other arguments"},
		{"the same step", step("example.com"), ""},
	} {
		h := fakehost.New()
		p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n" + step("example.com") + tt.second})
		plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
		err := plan.Failed["web1"]
		if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: plan error %v, want %q", tt.name, err, tt.want)
		}
	}
}

// spec: Running a pipeline/Lockout protection (every file that the recipe
// changed: a step in another recipe or a stage that notifies the handler)
func TestConfirmAccessAcrossRecipes(t *testing.T) {
	h := fakehost.New()
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - recipe: hardening
      - file:
          path: /etc/ssh/sshd_config.d/stage.conf
          content: "X11Forwarding no\n"
        notify: ssh.reload
      - recipe: ssh
`,
		"recipes/hardening/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/sshd_config.d/hardening.conf
      content: "PermitRootLogin no\n"
    notify: ssh.reload
`,
		"recipes/ssh/recipe.yaml": sshRecipe,
	})
	if _, o := applyWeb1(t, p, h); !o.OK() {
		t.Fatalf("apply failed: %v", o.Failed)
	}
	want := map[string]protocol.Guard{
		"/etc/ssh/sshd_config.d/hardening.conf": {Recipe: "hardening", Handlers: []string{"ssh.reload"}},
		"/etc/ssh/sshd_config.d/stage.conf":     {Pipeline: "site", Stage: "base", Handlers: []string{"ssh.reload"}},
	}
	for path, w := range want {
		if g := h.Guards["web1 "+path]; !reflect.DeepEqual(g, w) {
			t.Errorf("guard of %s = %+v, want its own store and that of the handler's recipe %+v", path, g, w)
		}
	}
}

const notifyNftablesRecipes = `steps:
  - file:
      path: /etc/nftables-ssh.nft
      content: "table inet ssh {}\n"
    notify: [nftables.reload, nftables.restart]
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`

const nftablesHandlersRecipe = `steps:
  - file:
      path: /etc/nftables.conf
      content: "flush ruleset\n"
handlers:
  reload:
    - service:
        name: nftables
        reloaded: true
      confirm_access: true
  restart:
    - service:
        name: nftables
        restarted: true
      confirm_access: true
`

// spec: Running a pipeline/Lockout protection (a step saves in the store of
// its own recipe and in that of each other recipe whose confirm_access handler
// it notifies)
func TestConfirmAccessOwnAndNotifiedStores(t *testing.T) {
	for _, tt := range []struct {
		name, steps string
		want        protocol.Guard
	}{
		{"both recipes run", "      - recipe: ssh\n      - recipe: nftables\n", protocol.Guard{Recipe: "ssh", Save: true, Handlers: []string{"nftables.reload", "nftables.restart"}}},
		{"nftables does not run", "      - recipe: ssh\n      - recipe: nftables\n        when: !expr host.name == \"db1\"\n", protocol.Guard{Recipe: "ssh", Save: true}},
	} {
		h := fakehost.New()
		p := loadWeb1(t, map[string]string{
			"pipelines/site.yaml":          "stages:\n  - name: base\n    hosts: all\n    steps:\n" + tt.steps,
			"recipes/ssh/recipe.yaml":      notifyNftablesRecipes,
			"recipes/nftables/recipe.yaml": nftablesHandlersRecipe,
			"inventories/test.yaml":        "hosts:\n  web1: {}\n  db1: {}\n",
		})
		if _, o := applyWeb1(t, p, h); !o.OK() {
			t.Fatalf("%s: apply failed: %v", tt.name, o.Failed)
		}
		if g := h.Guards["web1 /etc/nftables-ssh.nft"]; !reflect.DeepEqual(g, tt.want) {
			t.Errorf("%s: guard = %+v, want %+v", tt.name, g, tt.want)
		}
	}
}

// spec: Running a pipeline/Lockout protection (gap: two tries of the access,
// 5 seconds apart)
func TestAccessSecondTry(t *testing.T) {
	h := fakehost.New()
	h.SetTimer(time.Minute)
	h.FailAccessOnce("web1")
	h.SetResult("web1", "mail", module.Result{Status: module.Change, Action: module.Modify, Guard: true})
	p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - hostname:\n          name: mail\n"})
	if _, o := applyWeb1(t, p, h); !o.OK() {
		t.Fatalf("apply failed: %v", o.Failed)
	}
	if want := []string{"access", "access", "confirm", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
}

// spec: Running a pipeline/Lockout protection (a guarded step that ends after
// its rollback timer fails)
func TestTimerEndedFirst(t *testing.T) {
	h := fakehost.New()
	h.SetTimer(-time.Second)
	h.SetResult("web1", "mail", module.Result{Status: module.Change, Action: module.Modify, Guard: true})
	p := loadWeb1(t, map[string]string{"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - hostname:\n          name: mail\n"})
	out, o := applyWeb1(t, p, h)
	if o.OK() {
		t.Fatal("apply succeeded after the timer ended")
	}
	if want := []string{"rollback"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
	if want := "hostname mail: the rollback timer ended first; the old files are back"; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}

	h = fakehost.New()
	h.SetTimer(-time.Second)
	h.FailRollback(errors.New("restore /etc/hostname: no space left on device"))
	h.SetResult("web1", "mail", module.Result{Status: module.Change, Action: module.Modify, Guard: true})
	out, _ = applyWeb1(t, p, h)
	if want := "hostname mail: the rollback timer ended first; the rollback failed: restore /etc/hostname: no space left on device"; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
}

// spec: Running a pipeline/Lockout protection (the access check after the
// last step and handler of a host that changed something)
func TestLostAccessAfterRun(t *testing.T) {
	p := loadWeb1(t, map[string]string{"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: hi
  - name: app
    hosts: all
    steps:
      - file:
          path: /etc/issue
          content: hi
`})
	h := fakehost.New()
	if _, o := applyWeb1(t, p, h); !o.OK() {
		t.Fatalf("apply failed: %v", o.Failed)
	}
	if want := []string{"access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}

	// Only the first stage changes something.
	h = fakehost.New()
	h.SetFile("web1", "/etc/issue", "hi")
	h.FailAccess("web1")
	out, o := applyWeb1(t, p, h)
	if o.OK() {
		t.Fatal("apply succeeded without access")
	}
	if want := "web1: failed: winch lost access after the run: ssh: connect to host web1 port 22: Connection timed out"; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
	if want := []string{"access", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
}
