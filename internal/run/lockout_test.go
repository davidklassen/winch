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
)

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
		"web1 /etc/ssh/sshd_config.d/local.conf": {Store: "ssh", Save: true, Handlers: []string{"ssh.reload"}, SSHD: []string{"ssh"}},
		"web1 ssh":                               {Store: "ssh", Save: true, Confirm: true, LoadsSSHD: true},
		"web1 /etc/motd":                         {Store: "site\tbase"},
		"web1 /etc/nftables.conf":                {Store: "site\tfirewall", Save: true},
		"web1 nftables":                          {Store: "site\tfirewall", Save: true, Confirm: true},
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
	if want := []string{"ssh reload", "access", "rollback", "access", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
	want := "web1: ssh: failed: handler ssh.reload: service ssh: the access check failed: ssh: connect to host web1 port 22: Connection timed out; the old files are back"
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
	if g := h.Guards["web1 mail"]; !reflect.DeepEqual(g, protocol.Guard{Store: "site\tbase"}) {
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
			wantPlan: "    ~ reboot\n", wantApply: "web1: base: ~ reboot (rebooted with failed units: a.service, b.service)\n", wantLog: []string{"reboot 30s", "access"}},
		{name: "still required", ifRequired: "true", required: true, boot: &protocol.Boot{State: "running", Kernel: "6.12.43+deb13-amd64", Newest: "99.0.0+deb13-amd64"},
			wantPlan: "    ~ reboot if required\n", wantApply: "", wantLog: []string{"reboot 30s"},
			wantErr: "base: failed: reboot if required: the host still needs a reboot after it rebooted: running kernel 6.12.43+deb13-amd64, newest kernel 99.0.0+deb13-amd64"},
		{name: "always, still required", ifRequired: "false", required: true, boot: &protocol.Boot{State: "running", Kernel: "6.12.43+deb13-amd64", Newest: "99.0.0+deb13-amd64"},
			wantPlan: "    ~ reboot\n", wantApply: "", wantLog: []string{"reboot 30s"},
			wantErr: "base: failed: reboot: the host still needs a reboot after it rebooted: running kernel 6.12.43+deb13-amd64, newest kernel 99.0.0+deb13-amd64"},
		{name: "still required by packages", ifRequired: "true", required: true, boot: &protocol.Boot{State: "running", Kernel: "6.12.43+deb13-amd64", Newest: "6.12.43+deb13-amd64", Packages: []string{"dbus", "libc6"}},
			wantPlan: "    ~ reboot if required\n", wantApply: "", wantLog: []string{"reboot 30s"},
			wantErr: "base: failed: reboot if required: the host still needs a reboot after it rebooted: /run/reboot-required lists the packages dbus, libc6"},
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
		if err == nil || !strings.Contains(err.Error(), ": Open SSH again: firewall: the firewall is also in ") || !strings.Contains(err.Error(), "base#1 Open SSH: firewall; a host has one firewall step") {
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
		{"file after", firewall + file, "file /etc/winch/firewall.nft: the path /etc/winch/firewall.nft is also in base#1 firewall, with other arguments; use one step"},
		{"file before", file + firewall, "firewall: the path /etc/winch/firewall.nft is also in base#1 file /etc/winch/firewall.nft"},
		{"unit", firewall + unit, "the path /etc/systemd/system/winch-firewall.service is also in base#1 firewall"},
		{"drop-in", firewall + dropIn, "the path /etc/systemd/system/nftables.service.d/winch.conf is also in base#1 firewall"},
		{"service after", firewall + service, "service winch-firewall: the unit winch-firewall.service is also in base#1 firewall"},
		{"service before", service + firewall, "firewall: the unit winch-firewall.service is also in base#1 service winch-firewall"},
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
		{"other domains", step("example.com, www.example.com"), "base: certbot example.com: the certificate example.com is also in base#1 certbot example.com, with other arguments; use one step"},
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
		"/etc/ssh/sshd_config.d/hardening.conf": {Store: "hardening", Handlers: []string{"ssh.reload"}, SSHD: []string{"ssh"}},
		"/etc/ssh/sshd_config.d/stage.conf":     {Store: "site\tbase", Handlers: []string{"ssh.reload"}, SSHD: []string{"ssh"}},
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
		{"both recipes run", "      - recipe: ssh\n      - recipe: nftables\n", protocol.Guard{Store: "ssh", Save: true, Handlers: []string{"nftables.reload", "nftables.restart"}}},
		{"nftables does not run", "      - recipe: ssh\n      - recipe: nftables\n        when: !expr host.name == \"db1\"\n", protocol.Guard{Store: "ssh", Save: true}},
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
	if want := "web1: the access check after the run failed: ssh: connect to host web1 port 22: Connection timed out"; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
	if want := []string{"access", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
}

// spec: Running a pipeline/Lockout protection (the access check after the run
// also runs when a step fails the host after an earlier change of that host)
func TestLostAccessAfterFailedStep(t *testing.T) {
	p := loadWeb1(t, map[string]string{"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: hi
      - file:
          path: /etc/issue
          content: hi
  - name: app
    hosts: all
    steps:
      - file:
          path: /etc/hosts
          content: hi
`})
	h := fakehost.New()
	h.FailApply("web1 /etc/issue")
	h.FailAccess("web1")
	out, o := applyWeb1(t, p, h)
	if o.OK() {
		t.Fatal("apply succeeded after a failed step")
	}
	if want := "web1: base: failed: file /etc/issue: "; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
	if want := "; the access check after the run failed: ssh: connect to host web1 port 22: Connection timed out"; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
	if want := []string{"access", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}

	// The failed step is the first change of the host.
	h = fakehost.New()
	h.SetFile("web1", "/etc/motd", "hi")
	h.FailApply("web1 /etc/issue")
	h.FailAccess("web1")
	out, o = applyWeb1(t, p, h)
	if o.OK() {
		t.Fatal("apply succeeded after a failed step")
	}
	if want := "web1: base: failed: file /etc/issue: "; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
	if strings.Contains(out, "access check") {
		t.Errorf("output:\n%s\nwant no access check", out)
	}
	if len(h.Log["web1"]) != 0 {
		t.Errorf("log %q, want none", h.Log["web1"])
	}

	// Only an earlier stage changes something.
	h = fakehost.New()
	h.SetFile("web1", "/etc/issue", "hi")
	h.FailApply("web1 /etc/hosts")
	h.FailAccess("web1")
	out, o = applyWeb1(t, p, h)
	if o.OK() {
		t.Fatal("apply succeeded after a failed step")
	}
	if want := "web1: app: failed: file /etc/hosts: "; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
	if want := "; the access check after the run failed: ssh: connect to host web1 port 22: Connection timed out"; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
}

// spec: Remote execution/Sessions (a host whose login needed a prompt plans
// as usual, but apply stops before its first change)
func TestApplyAfterPrompt(t *testing.T) {
	p := loadWeb1(t, map[string]string{"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: hi
`})
	h := fakehost.New()
	h.SetPrompted("web1")
	out, o := applyWeb1(t, p, h)
	if o.OK() {
		t.Fatal("apply succeeded after a login with a prompt")
	}
	if want := "web1: the access check cannot log in without a prompt; add the key to the agent with ssh-add"; !strings.Contains(out, want) {
		t.Errorf("output:\n%s\nwant %q", out, want)
	}
	if _, ok := h.File("web1", "/etc/motd"); ok {
		t.Error("apply wrote /etc/motd")
	}
	if len(h.Log["web1"]) > 0 {
		t.Errorf("log %q, want nothing", h.Log["web1"])
	}

	// A host without a change only loses its gone records.
	h = fakehost.New()
	h.SetFile("web1", "/etc/motd", "hi")
	h.Pend("web1", protocol.Check{Pipeline: "site", Stage: "old"})
	h.SetPrompted("web1")
	if out, o := applyWeb1(t, p, h); !o.OK() {
		t.Fatalf("apply failed:\n%s", out)
	}
	if got := h.ChecksOf("web1"); len(got) > 0 {
		t.Errorf("records %v, want the gone record removed", got)
	}
}

// spec: Running a pipeline/Lockout protection (the plan warns when sshd loads
// a changed config without confirm_access)
func TestSSHDWarning(t *testing.T) {
	const (
		warning  = "sshd loads a changed config without an access check; reload it in a service handler with confirm_access: true"
		untested = "sshd's config changes, and no step reloads sshd with confirm_access: true; the new config loads untested at the next restart"
	)
	recipe := func(path, handler string) string {
		return `steps:
  - file:
      path: ` + path + `
      content: "UsePAM no\n"
    notify: restart
handlers:
  restart:
    - service:
        name: ` + handler + `
`
	}
	then := func(cmd string) string {
		return "steps:\n  - file:\n      path: /etc/ssh/sshd_config\n      content: \"UsePAM no\\n\"\n    then: " + cmd + "\n"
	}
	tests := []struct {
		name, recipe, want string
		// untested is the position of the warning that no guarded reload
		// tests the change.
		untested string
		// have are the files that are already in place on the host.
		have []string
		// pipeline is the pipeline, when it is not one stage that runs the
		// recipe.
		pipeline string
	}{
		{"restart", recipe("/etc/ssh/sshd_config", "ssh\n        restarted: true"), "recipes/ssh/recipe.yaml:8:7", "", nil, ""},
		{"reload of sshd in sshd_config.d", recipe("/etc/ssh/sshd_config.d/local.conf", "sshd.service\n        reloaded: true"), "recipes/ssh/recipe.yaml:8:7", "", nil, ""},
		{"confirm_access", recipe("/etc/ssh/sshd_config", "ssh\n        restarted: true\n      confirm_access: true"), "", "", nil, ""},
		{"drop-in of ssh.service", recipe("/etc/systemd/system/ssh.service.d/override.conf", "ssh\n        restarted: true"), "recipes/ssh/recipe.yaml:8:7", "", nil, ""},
		{"drop-in of ssh.socket", recipe("/etc/systemd/system/ssh.socket.d/port.conf", "ssh.socket\n        restarted: true"), "recipes/ssh/recipe.yaml:8:7", "", nil, ""},
		{"drop-in of ssh.socket with confirm_access", recipe("/etc/systemd/system/ssh.socket.d/port.conf", "ssh.socket\n        restarted: true\n      confirm_access: true"), "", "", nil, ""},
		{"reload of ssh.socket", recipe("/etc/ssh/sshd_config", "ssh.socket\n        reloaded: true"), "recipes/ssh/recipe.yaml:8:7", "", nil, ""},
		{"drop-in of another unit", recipe("/etc/systemd/system/nginx.service.d/override.conf", "ssh\n        restarted: true"), "", "", nil, ""},
		{"no sshd config change", recipe("/etc/motd", "ssh\n        restarted: true"), "", "", nil, ""},
		{"restart of another unit", recipe("/etc/ssh/sshd_config", "nginx\n        restarted: true"), "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"then", `steps:
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
    then: systemctl restart ssh
`, "recipes/ssh/recipe.yaml:2:5", "", nil, ""},
		{"then of another unit", then("sshd -t && systemctl restart nginx"), "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"then of init.d", then("/etc/init.d/ssh restart"), "recipes/ssh/recipe.yaml:2:5", "", nil, ""},
		{"then of sshd.service", then("systemctl restart sshd.service"), "recipes/ssh/recipe.yaml:2:5", "", nil, ""},
		{"then of ssh.socket", then("systemctl restart ssh.socket"), "recipes/ssh/recipe.yaml:2:5", "", nil, ""},
		{"then that starts ssh.socket", then("systemctl start ssh.socket"), "recipes/ssh/recipe.yaml:2:5", "", nil, ""},
		{"then that starts ssh", then("systemctl start ssh"), "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"then that stops ssh.socket", then("systemctl stop ssh.socket"), "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"then of ssh-agent", then("systemctl restart ssh-agent"), "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"then of two lines", then(`"systemctl restart caddy\nsshd -T"`), "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"config already in place", recipe("/etc/ssh/sshd_config", "ssh\n        restarted: true"), "", "", []string{"/etc/ssh/sshd_config"}, ""},
		{"handler not notified", `steps:
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
  - file:
      path: /etc/motd
      content: hi
    notify: restart
handlers:
  restart:
    - service:
        name: ssh
        restarted: true
`, "", "recipes/ssh/recipe.yaml:2:5", []string{"/etc/motd"}, ""},
		{"handler notified by another step", `steps:
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
  - file:
      path: /etc/motd
      content: hi
    notify: restart
handlers:
  restart:
    - service:
        name: ssh
        restarted: true
`, "", "", []string{"/etc/ssh/sshd_config"}, ""},
		{"then of a later step", `steps:
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
  - cmd: {command: "true"}
    then: systemctl restart ssh
`, "recipes/ssh/recipe.yaml:5:5", "", nil, ""},
		{"then before the change", `steps:
  - cmd: {command: "true"}
    then: systemctl restart ssh
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
`, "", "recipes/ssh/recipe.yaml:4:5", nil, ""},
		{"then that does not run", `steps:
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
  - file:
      path: /etc/motd
      content: hi
    then: systemctl restart ssh
`, "", "recipes/ssh/recipe.yaml:2:5", []string{"/etc/motd"}, ""},
		{"then of a handler step", `steps:
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
    notify: restart
handlers:
  restart:
    - file:
        path: /etc/motd
        content: hi
      then: service ssh reload
`, "recipes/ssh/recipe.yaml:8:7", "", nil, ""},
		{"drop-in without a reload", `steps:
  - file:
      path: /etc/ssh/sshd_config.d/local.conf
      content: "UsePAM no\n"
`, "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"drop-in with a confirm_access reload", recipe("/etc/ssh/sshd_config.d/local.conf", "ssh\n        reloaded: true\n      confirm_access: true"), "", "", nil, ""},
		{"confirm_access reload not notified", `steps:
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
  - file:
      path: /etc/motd
      content: hi
    notify: reload
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`, "", "recipes/ssh/recipe.yaml:2:5", []string{"/etc/motd"}, ""},
		{"confirm_access on running", recipe("/etc/ssh/sshd_config", "ssh\n        running: true\n      confirm_access: true"), "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"confirm_access restart of another unit", recipe("/etc/ssh/sshd_config", "nginx\n        restarted: true\n      confirm_access: true"), "", "recipes/ssh/recipe.yaml:2:5", nil, ""},
		{"then of a guarded handler of another unit", recipe("/etc/ssh/sshd_config", "nginx\n        restarted: true\n      confirm_access: true\n      then: systemctl restart ssh"), "recipes/ssh/recipe.yaml:8:7", "", nil, ""},
		{"confirm_access reload in an earlier stage", recipe("/etc/motd", "ssh\n        reloaded: true\n      confirm_access: true"), "", "pipelines/site.yaml:9:9", nil, `stages:
  - name: base
    hosts: all
    steps:
      - recipe: ssh
  - name: late
    hosts: all
    steps:
      - file:
          path: /etc/ssh/sshd_config
          content: "UsePAM no\n"
`},
	}
	for _, tt := range tests {
		pipeline := tt.pipeline
		if pipeline == "" {
			pipeline = "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: ssh\n"
		}
		p := loadWeb1(t, map[string]string{
			"pipelines/site.yaml":     pipeline,
			"recipes/ssh/recipe.yaml": tt.recipe,
		})
		h := fakehost.New()
		for _, f := range tt.have {
			h.SetFile("web1", f, map[string]string{"/etc/ssh/sshd_config": "UsePAM no\n", "/etc/motd": "hi"}[f])
		}
		plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
		if len(plan.Failed) > 0 {
			t.Fatalf("%s: plan failed: %v", tt.name, plan.Failed)
		}
		var got []string
		for _, w := range plan.Warnings {
			got = append(got, w.Error())
		}
		var want []string
		if tt.want != "" {
			want = append(want, tt.want+": "+warning)
		}
		if tt.untested != "" {
			want = append(want, tt.untested+": "+untested)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: warnings %q, want %q", tt.name, got, want)
		}
	}
}

// spec: Running a pipeline/Lockout protection (an untested sshd file never
// stays on the host)
func TestSSHDUntestedWarning(t *testing.T) {
	const untested = "sshd's config changes, and no step reloads sshd with confirm_access: true; the new config loads untested at the next restart"
	const guarded = `steps:
  - file:
      path: /etc/motd
      content: hi
    notify: reload
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`
	tests := []struct {
		name     string
		files    map[string]string
		setup    func(h *fakehost.Hosts)
		warnings []string
	}{
		{"ssh.socket restart under the access check", map[string]string{
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - line:
          path: /etc/ssh/sshd_config
          match: "^#?PermitRootLogin "
          line: PermitRootLogin no
`,
		}, func(h *fakehost.Hosts) {
			h.SetResult("web1", "^#?PermitRootLogin ", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"restarts ssh.socket, which winch connects to", "daemon-reload", module.SSHSocketRestart}})
		}, nil},
		{"guarded reload on another host", map[string]string{
			"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: ssh\n",
			"recipes/ssh/recipe.yaml": `steps:
  - file:
      path: /etc/ssh/sshd_config
      content: "UsePAM no\n"
  - file:
      path: /etc/motd
      content: hi
    notify: reload
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
`,
		}, func(h *fakehost.Hosts) { h.SetFile("web1", "/etc/motd", "hi") }, []string{"recipes/ssh/recipe.yaml:2:5: " + untested}},
		{"guarded reload of another recipe after a stage step", map[string]string{
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/ssh/sshd_config
          content: "UsePAM no\n"
      - recipe: ssh
`,
			"recipes/ssh/recipe.yaml": guarded,
		}, nil, nil},
		{"guarded reload of another recipe after a drop-in", map[string]string{
			"pipelines/site.yaml":           "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: hardening\n      - recipe: ssh\n",
			"recipes/hardening/recipe.yaml": "steps:\n  - file:\n      path: /etc/ssh/sshd_config.d/hardening.conf\n      content: \"PermitRootLogin no\\n\"\n",
			"recipes/ssh/recipe.yaml":       guarded,
		}, nil, nil},
		{"guarded reload that the change notifies", map[string]string{
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/ssh/sshd_config
          content: "UsePAM no\n"
        notify: ssh.reload
      - recipe: ssh
`,
			"recipes/ssh/recipe.yaml": guarded,
		}, nil, nil},
	}
	for _, tt := range tests {
		h := fakehost.New()
		if tt.setup != nil {
			tt.setup(h)
		}
		plan := run.MakePlan(t.Context(), loadWeb1(t, tt.files), h.Connector(), run.Options{})
		if len(plan.Failed) > 0 {
			t.Fatalf("%s: plan failed: %v", tt.name, plan.Failed)
		}
		var got []string
		for _, w := range plan.Warnings {
			got = append(got, w.Error())
		}
		if !slices.Equal(got, tt.warnings) {
			t.Errorf("%s: warnings %q, want %q", tt.name, got, tt.warnings)
		}
	}
}

// spec: Running a pipeline/Lockout protection (a reboot, an upgrade of
// openssh-server, a start or restart of ssh.socket, and a guarded start during
// a switch load sshd)
func TestSSHDLoads(t *testing.T) {
	const (
		loaded   = "sshd loads a changed config without an access check; reload it in a service handler with confirm_access: true"
		untested = "sshd's config changes, and no step reloads sshd with confirm_access: true; the new config loads untested at the next restart"
		// Steps of the pipeline start at line 5.
		head = "stages:\n  - name: base\n    hosts: all\n    steps:\n"
		// conf takes lines 5 to 7, and change lines 5 to 8.
		conf   = "      - file:\n          path: /etc/ssh/sshd_config\n          content: \"UsePAM no\\n\"\n"
		dropIn = "      - file:\n          path: /etc/ssh/sshd_config.d/local.conf\n          content: \"UsePAM no\\n\"\n"
		change = conf + "        notify: reload\n"
		reload = "    handlers:\n      reload:\n        - service:\n            name: ssh\n            reloaded: true\n          confirm_access: true\n"
		reboot = "      - reboot:\n          if_required: false\n"
		safe   = "      - upgrade:\n          mode: safe\n"
		socket = "      - service:\n          name: ssh.socket\n          running: true\n          enabled: true\n"
		sshOn  = "      - service:\n          name: ssh\n          running: true\n          enabled: true\n"
		off    = "      - service:\n          name: ssh.socket\n          running: false\n          enabled: false\n"
		guard  = "        confirm_access: true\n"
	)
	at := func(pos, msg string) string { return "pipelines/site.yaml:" + pos + ": " + msg }
	upgrades := func(line string) func(h *fakehost.Hosts) {
		return func(h *fakehost.Hosts) {
			h.SetResult("web1", "safe", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{line}})
		}
	}
	socketChanges := func(h *fakehost.Hosts, changes ...string) {
		h.SetResult("web1", "ssh.socket", module.Result{Status: module.Change, Action: module.Modify, Changes: changes})
	}
	socketOff := func(h *fakehost.Hosts) { socketChanges(h, "disable", "stop") }
	sshUp := func(h *fakehost.Hosts) {
		socketOff(h)
		h.SetResult("web1", "ssh", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"enable"}})
	}
	socketUp := func(h *fakehost.Hosts) { h.SetResult("web1", "ssh.socket", module.Result{Status: module.OK}) }
	for _, tt := range []struct {
		name, pipeline string
		setup          func(h *fakehost.Hosts)
		want           []string
	}{
		{"reboot before the guarded reload", change + reboot + reload, nil, []string{at("9:9", loaded)}},
		{"reboot if required before the guarded reload", change + "      - reboot:\n          if_required: true\n" + reload, nil, []string{at("9:9", loaded)}},
		{"reboot without a reload", conf + reboot, nil, []string{at("8:9", loaded)}},
		{"reboot before the change", reboot + change + reload, nil, nil},
		{"reboot after the guarded reload", change + reload + "  - name: late\n    hosts: all\n    steps:\n" + reboot, nil, nil},
		{"reboot after a restart of ssh.socket under the access check", conf + reboot, func(h *fakehost.Hosts) {
			h.SetResult("web1", "/etc/ssh/sshd_config", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{module.SSHSocketRestart}})
		}, nil},
		{"upgrade of openssh-server before the guarded reload", change + safe + reload, upgrades("upgrade openssh-server 1:10.0p1-7 → 1:10.0p1-8"), []string{at("9:9", loaded)}},
		{"upgrade of another package", change + safe + reload, upgrades("upgrade openssh-sftp-server 1:10.0p1-7 → 1:10.0p1-8"), nil},
		{"upgrade that changes nothing", change + safe + reload, nil, nil},
		{"guarded start of ssh.socket", conf + socket + guard, nil, nil},
		{"start of ssh.socket", conf + socket, nil, []string{at("8:9", loaded)}},
		{"guarded step of a running ssh.socket", conf + socket + guard, socketUp, []string{at("5:9", untested)}},
		{"guarded start during a switch", off + dropIn + sshOn + guard, socketOff, nil},
		{"guarded start after a stop of ssh.socket", off + conf + sshOn + guard, func(h *fakehost.Hosts) { socketChanges(h, "stop") }, nil},
		{"guarded start after a disable of ssh.socket", off + conf + sshOn + guard, func(h *fakehost.Hosts) { socketChanges(h, "disable") }, nil},
		{"reboot in a handler", conf + "        notify: reload\n    handlers:\n      reload:\n        - reboot:\n            if_required: false\n", nil, []string{at("11:11", loaded)}},
		{"guarded start of ssh.socket in a handler, which the plan does not check", conf + "        notify: reload\n    handlers:\n      reload:\n        - service:\n            name: ssh.socket\n            running: true\n          confirm_access: true\n", nil, []string{at("5:9", untested)}},
		{"start during a switch", off + conf + sshOn, socketOff, []string{at("9:9", untested)}},
		{"guarded start before the stop of ssh.socket", conf + sshOn + guard + off, socketOff, []string{at("5:9", untested)}},
		{"guarded start without a switch", conf + "      - service:\n          name: ssh\n          running: true\n" + guard, nil, []string{at("5:9", untested)}},
		{"guarded step of a running ssh during a switch", off + conf + sshOn + guard, sshUp, []string{at("9:9", untested)}},
	} {
		h := fakehost.New()
		if tt.setup != nil {
			tt.setup(h)
		}
		plan := run.MakePlan(t.Context(), loadWeb1(t, map[string]string{"pipelines/site.yaml": head + tt.pipeline}), h.Connector(), run.Options{})
		if len(plan.Failed) > 0 {
			t.Fatalf("%s: plan failed: %v", tt.name, plan.Failed)
		}
		var got []string
		for _, w := range plan.Warnings {
			got = append(got, w.Error())
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: warnings %q, want %q", tt.name, got, tt.want)
		}
	}
	const stage2 = "  - name: late\n    hosts: all\n    steps:\n"
	for _, tt := range []struct {
		name, pipeline string
		want           []string
	}{
		{"reboot on one of two hosts", "stages:\n  - name: base\n    hosts: all\n    steps:\n" + conf + "  - name: late\n    hosts: web1\n    steps:\n" + reboot,
			[]string{at("11:9", loaded), at("5:9", untested)}},
		{"switch on one of two hosts", "stages:\n  - name: base\n    hosts: web1\n    steps:\n" + off + stage2 + conf + sshOn + guard,
			[]string{at("12:9", untested)}},
	} {
		h := fakehost.New()
		socketOff(h)
		p := loadWeb1(t, map[string]string{"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n", "pipelines/site.yaml": tt.pipeline})
		plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
		if len(plan.Failed) > 0 {
			t.Fatalf("%s: plan failed: %v", tt.name, plan.Failed)
		}
		var got []string
		for _, w := range plan.Warnings {
			got = append(got, w.Error())
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: warnings %q, want %q", tt.name, got, tt.want)
		}
	}
}

// spec: Running a pipeline/Lockout protection (a step that changes sshd's
// config saves in the store of each later step with confirm_access that
// reloads or restarts sshd)
func TestSSHDStores(t *testing.T) {
	const dropIn = "/etc/ssh/sshd_config.d/hardening.conf"
	const hardening = "steps:\n  - file:\n      path: " + dropIn + "\n      content: \"PermitRootLogin no\\n\"\n"
	// ssh returns a recipe whose handler runs service with the lines svc.
	ssh := func(svc string) string {
		return "steps:\n  - file:\n      path: /etc/motd\n      content: hi\n    notify: reload\nhandlers:\n  reload:\n    - service:\n" + svc
	}
	const reload = "        name: ssh\n        reloaded: true\n      confirm_access: true\n"
	const stageHandler = "    steps:\n      - file:\n          path: /etc/issue\n          content: hi\n        notify: reload\n    handlers:\n      reload:\n        - service:\n            name: ssh\n            restarted: true\n          confirm_access: true\n"
	const both = "  - name: base\n    hosts: all\n    steps:\n      - recipe: hardening\n      - recipe: ssh\n"
	for _, tt := range []struct {
		name, pipeline string
		recipes        map[string]string
		want           protocol.Guard
	}{
		{"handler of a later recipe", both, map[string]string{"ssh": ssh(reload)}, protocol.Guard{Store: "hardening", SSHD: []string{"ssh"}}},
		{"restart of sshd.service", both, map[string]string{"ssh": ssh("        name: sshd.service\n        restarted: true\n      confirm_access: true\n")}, protocol.Guard{Store: "hardening", SSHD: []string{"ssh"}}},
		{"handler in a later stage", "  - name: base\n    hosts: all\n    steps:\n      - recipe: hardening\n  - name: ssh\n    hosts: all\n    steps:\n      - recipe: ssh\n",
			map[string]string{"ssh": ssh(reload)}, protocol.Guard{Store: "hardening", SSHD: []string{"ssh"}}},
		{"handler of a stage", "  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: " + dropIn + "\n          content: hi\n  - name: ssh\n    hosts: all\n" + stageHandler,
			nil, protocol.Guard{Store: "site\tbase", SSHD: []string{"site\tssh"}}},
		{"two later stores", both + "  - name: late\n    hosts: all\n" + stageHandler, map[string]string{"ssh": ssh(reload)}, protocol.Guard{Store: "hardening", SSHD: []string{"site\tlate", "ssh"}}},
		{"handler before the change", "  - name: base\n    hosts: all\n    steps:\n      - recipe: ssh\n      - recipe: hardening\n",
			map[string]string{"ssh": ssh(reload)}, protocol.Guard{Store: "hardening"}},
		{"handler without confirm_access", both, map[string]string{"ssh": ssh("        name: ssh\n        reloaded: true\n")}, protocol.Guard{Store: "hardening"}},
		{"handler that does not run", both, map[string]string{"ssh": strings.Replace(ssh(reload), "content: hi", "content: same", 1)}, protocol.Guard{Store: "hardening"}},
		{"handler of another unit", both, map[string]string{"ssh": ssh("        name: nginx\n        reloaded: true\n      confirm_access: true\n")}, protocol.Guard{Store: "hardening"}},
		{"handler of the same recipe", "  - name: base\n    hosts: all\n    steps:\n      - recipe: hardening\n",
			map[string]string{"hardening": hardening + "  - file:\n      path: /etc/motd\n      content: hi\n    notify: reload\nhandlers:\n  reload:\n    - service:\n" + reload}, protocol.Guard{Store: "hardening", Save: true, SSHD: []string{"hardening"}}},
		{"notified handler", both, map[string]string{"hardening": hardening + "    notify: ssh.reload\n", "ssh": ssh(reload)}, protocol.Guard{Store: "hardening", Handlers: []string{"ssh.reload"}, SSHD: []string{"ssh"}}},
		{"guarded start of ssh.socket", both, map[string]string{"ssh": "steps:\n  - service:\n      name: ssh.socket\n      running: true\n    confirm_access: true\n"}, protocol.Guard{Store: "hardening", SSHD: []string{"ssh"}}},
		{"guarded restart of ssh.socket", both, map[string]string{"ssh": ssh("        name: ssh.socket\n        restarted: true\n      confirm_access: true\n")}, protocol.Guard{Store: "hardening", SSHD: []string{"ssh"}}},
	} {
		files := map[string]string{"pipelines/site.yaml": "stages:\n" + tt.pipeline, "recipes/hardening/recipe.yaml": hardening}
		for name, r := range tt.recipes {
			files["recipes/"+name+"/recipe.yaml"] = r
		}
		h := fakehost.New()
		// A handler notified by a step that writes "same" does not run.
		h.SetFile("web1", "/etc/motd", "same")
		if _, o := applyWeb1(t, loadWeb1(t, files), h); !o.OK() {
			t.Fatalf("%s: apply failed: %v", tt.name, o.Failed)
		}
		if g := h.Guards["web1 "+dropIn]; !reflect.DeepEqual(g, tt.want) {
			t.Errorf("%s: guard = %+v, want %+v", tt.name, g, tt.want)
		}
	}
}

// spec: Running a pipeline/Lockout protection (a restart or reload with
// confirm_access tests the sshd files of its store)
func TestSSHDGuardLoads(t *testing.T) {
	const (
		head = "stages:\n  - name: base\n    hosts: all\n    steps:\n"
		off  = "      - service:\n          name: ssh.socket\n          running: false\n          enabled: false\n"
		on   = "      - service:\n          name: ssh\n          running: true\n          enabled: true\n        confirm_access: true\n"
	)
	socketOff := func(h *fakehost.Hosts) {
		h.SetResult("web1", "ssh.socket", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"disable", "stop"}})
	}
	for _, tt := range []struct {
		name, pipeline, step string
		setup                func(h *fakehost.Hosts)
		want                 bool
	}{
		{"guarded start of ssh.socket", "      - service:\n          name: ssh.socket\n          running: true\n        confirm_access: true\n", "ssh.socket", nil, true},
		{"guarded start during a switch", off + on, "ssh", socketOff, true},
		{"guarded start without a switch", on, "ssh", nil, false},
	} {
		h := fakehost.New()
		if tt.setup != nil {
			tt.setup(h)
		}
		if _, o := applyWeb1(t, loadWeb1(t, map[string]string{"pipelines/site.yaml": head + tt.pipeline}), h); !o.OK() {
			t.Fatalf("%s: apply failed: %v", tt.name, o.Failed)
		}
		if got := h.Guards["web1 "+tt.step].LoadsSSHD; got != tt.want {
			t.Errorf("%s: LoadsSSHD = %t, want %t", tt.name, got, tt.want)
		}
	}

	// The plan expects no handler, but the file changes before apply.
	h := fakehost.New()
	h.SetFile("web1", "/etc/motd", "hi")
	p := loadWeb1(t, map[string]string{"pipelines/site.yaml": head + "      - file:\n          path: /etc/issue\n          content: hi\n      - file:\n          path: /etc/motd\n          content: hi\n        notify: reload\n    handlers:\n      reload:\n        - service:\n            name: ssh\n            reloaded: true\n          confirm_access: true\n"})
	plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
	h.SetFile("web1", "/etc/motd", "other")
	var out bytes.Buffer
	if o := run.Apply(t.Context(), plan, h.Connector(), run.Text(plain(&out), plain(&out))); !o.OK() {
		t.Fatalf("apply failed: %v", o.Failed)
	}
	if !h.Guards["web1 ssh"].LoadsSSHD {
		t.Errorf("handler that the plan does not expect: LoadsSSHD = false, want true\n%s", out.String())
	}
}

// spec: Running a pipeline/Lockout protection (the plan fails a step that
// notifies a handler with confirm_access in a stage that --stages leaves out)
func TestConfirmAccessHandlerLeftOut(t *testing.T) {
	files := map[string]string{
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - recipe: ssh
  - name: mail
    hosts: all
    steps:
      - file:
          path: /etc/ssh/sshd_config.d/10-mail.conf
          content: "PasswordAuthentication no\n"
        notify: ssh.NOTIFY
`,
		"recipes/ssh/recipe.yaml": `steps:
  - pkg:
      name: openssh-server
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
      confirm_access: true
  restart:
    - service:
        name: ssh
        restarted: true
`,
	}
	const leftOut = "mail: file /etc/ssh/sshd_config.d/10-mail.conf: the confirm_access handler ssh.reload runs in stage base, which --stages leaves out"
	for _, tt := range []struct {
		name, stages, notify string
		same                 bool
		want                 string
	}{
		{"all stages", "", "reload", false, ""},
		{"both stages", "base,mail", "reload", false, ""},
		{"the stage of the handler left out", "mail", "reload", false, leftOut},
		{"no change", "mail", "reload", true, ""},
		{"a handler without confirm_access", "mail", "restart", false, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := loadWeb1(t, map[string]string{
				"pipelines/site.yaml":     strings.Replace(files["pipelines/site.yaml"], "NOTIFY", tt.notify, 1),
				"recipes/ssh/recipe.yaml": files["recipes/ssh/recipe.yaml"],
			})
			if tt.stages != "" {
				if err := p.Select(project.Selection{Stages: tt.stages}); err != nil {
					t.Fatal(err)
				}
			}
			h := fakehost.New()
			if tt.same {
				h.SetFile("web1", "/etc/ssh/sshd_config.d/10-mail.conf", "PasswordAuthentication no\n")
			}
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			got := ""
			if err := plan.Failed["web1"]; err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (a timer whose process is gone
// does not run on its own: the plan shows its rollback as the first change of
// the host, and apply runs it first)
func TestDueRollback(t *testing.T) {
	h := fakehost.New()
	h.SetDue("web1", "put back /etc/nftables.conf", "service nftables: reload")
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: hi\n",
	})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	want := `web1
  ! rollback of an earlier run
      put back /etc/nftables.conf
      service nftables: reload
  base
    + file /etc/motd
`
	if !strings.HasPrefix(out.String(), want) || !strings.Contains(out.String(), "1 host: 1 to change, 0 unchanged, 0 unknown\n") {
		t.Errorf("plan:\n%s\nwant it to start with:\n%s", out.String(), want)
	}
	if slices.Contains(h.Log["web1"], "due") {
		t.Errorf("the plan ran the rollback: log %q", h.Log["web1"])
	}
	out.Reset()
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if !o.OK() {
		t.Fatalf("apply failed: %v", o.Failed)
	}
	if log := h.Log["web1"]; len(log) == 0 || log[0] != "due" {
		t.Errorf("log %q, want the rollback first", log)
	}
	if !strings.HasPrefix(out.String(), "web1: ! rollback of an earlier run\nweb1: base: + file /etc/motd\n") {
		t.Errorf("apply:\n%s", out.String())
	}
}

// spec: Running a pipeline/Lockout protection (the rollback of an earlier
// run is a change of the host)
func TestDueRollbackOnly(t *testing.T) {
	h := fakehost.New()
	h.SetDue("web1", "put back /etc/nftables.conf")
	h.SetFile("web1", "/etc/motd", "hi")
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: hi\n",
	})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	if change, _, _, _ := plan.Counts(); change != 1 {
		t.Errorf("hosts to change: %d, want 1", change)
	}
	var out, errOut bytes.Buffer
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if !o.OK() || !o.Changed["web1"] {
		t.Fatalf("apply: failed %v, changed %v", o.Failed, o.Changed)
	}
	if want := []string{"due", "access"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
}

// spec: Running a pipeline/Lockout protection (a failed rollback of an
// earlier run fails the host before its steps)
func TestDueRollbackFails(t *testing.T) {
	h := fakehost.New()
	h.SetDue("web1", "put back /etc/nftables.conf")
	h.FailRollback(errors.New("put back /etc/nftables.conf: no space left on device"))
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: hi\n",
	})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if o.OK() {
		t.Fatal("apply succeeded")
	}
	if want := "web1: failed: rollback of an earlier run: put back /etc/nftables.conf: no space left on device\n"; errOut.String() != want {
		t.Errorf("errors %q, want %q", errOut.String(), want)
	}
	if want := []string{"due"}; !slices.Equal(h.Log["web1"], want) {
		t.Errorf("log %q, want %q", h.Log["web1"], want)
	}
}

// spec: Running a pipeline/Lockout protection (apply runs the rollback of an
// earlier run once, before the first stage of the host)
func TestDueRollbackRunsOnce(t *testing.T) {
	h := fakehost.New()
	h.SetDue("web1", "put back /etc/nftables.conf")
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: hi\n  - name: web\n    hosts: all\n    steps:\n      - file:\n          path: /etc/issue\n          content: hi\n",
	})
	_, o := applyWeb1(t, p, h)
	if !o.OK() {
		t.Fatalf("apply failed: %v", o.Failed)
	}
	n := 0
	for _, e := range h.Log["web1"] {
		if e == "due" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("log %q, want one rollback", h.Log["web1"])
	}
}

// spec: Running a pipeline/Lockout protection; JSON output (the rollback of
// an earlier run is a planned event of the host)
func TestDueRollbackJSON(t *testing.T) {
	h := fakehost.New()
	h.SetDue("web1", "put back /etc/nftables.conf")
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: hi\n",
	})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out bytes.Buffer
	plan.WriteJSON(run.NewEvents(plain(&out), func() time.Time { return time.Time{} }))
	want := `{"type":"planned","time":"0001-01-01T00:00:00Z","host":"web1","address":"web1:rollback","stage":"","step":"rollback of an earlier run","status":"change","changes":["put back /etc/nftables.conf"]}`
	if first, _, _ := strings.Cut(out.String(), "\n"); first != want {
		t.Errorf("first event:\n%s\nwant:\n%s", first, want)
	}
}

// spec: Running a pipeline/Lockout protection (a host that fails in the plan
// does not run the rollback of an earlier run)
func TestDueRollbackFailedHost(t *testing.T) {
	h := fakehost.New()
	h.SetDue("web1", "put back /etc/nftables.conf")
	h.FailCheck("web1")
	p := loadWeb1(t, map[string]string{
		"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: hi\n",
	})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if strings.Contains(out.String(), "rollback") || !strings.Contains(out.String(), "1 host: 0 to change, 0 unchanged, 0 unknown, 1 failed\n") {
		t.Errorf("plan:\n%s", out.String())
	}
	run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut)))
	if slices.Contains(h.Log["web1"], "due") {
		t.Errorf("apply ran the rollback of a failed host: log %q", h.Log["web1"])
	}
}
