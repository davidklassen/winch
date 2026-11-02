package run_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

// ageKey writes a new age identity and returns its path and its recipient.
// The key and the ciphertexts of the test are the same in each run: the plan
// hash in the golden files covers the ciphertexts.
func ageKey(t *testing.T) (string, *age.X25519Recipient) {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 1)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(identity, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return identity, id.Recipient()
}

// secretProject loads a project whose recipe reads the secret hunter2, and
// returns the filter that knows its secrets.
func secretProject(t *testing.T) (*project.Project, *secret.Filter) {
	t.Helper()
	identity, recipient := ageKey(t)
	rec := []age.Recipient{recipient}
	text, err := secret.Encrypt("hunter2", rec)
	if err != nil {
		t.Fatal(err)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      monit_password: !secret " + text + "\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: monit\n",
		"recipes/monit/recipe.yaml": `vars:
  monit_user: admin
  monit_m: {hunter2: found}
steps:
  - file:
      path: /etc/monit/conf.d/settings
      template: settings.tmpl
      mode: "0600"
  - name: Key file
    file:
      path: !tpl "/etc/monit/{{ .vars.monit_password }}.key"
      content: "k\n"
    then: !tpl "monit-passwd {{ .vars.monit_password }}"
  - file:
      path: /etc/monit/hidden
      content: !tpl "{{ index .vars.monit_m .vars.monit_password }}\n"
`,
		"recipes/monit/templates/settings.tmpl": "set httpd port 2812\n  allow {{ .vars.monit_user }}:{{ .vars.monit_password }}\n# {{ title .vars.monit_password }}\n",
	})
	filter := secret.NewFilter()
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	return p, filter
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecrets(t *testing.T) {
	p, _ := secretProject(t)
	h := fakehost.New()
	h.SetFile("web1", "/etc/monit/conf.d/settings", "set httpd port 2812\n  allow admin:old-pass\n# Old-Pass\n")
	h.SetThen("web1", protocol.Then{Recipe: "monit", Module: "file", Mains: []string{"/etc/monit/hunter2.key"}})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "secrets", "plan.golden"), output(&out, &errOut))
	out.Reset()
	errOut.Reset()
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatalf("apply failed: %s", errOut.String())
	}
	golden.Assert(t, filepath.Join("testdata", "secrets", "apply.golden"), applyOutput(&out, &errOut))
	if c, _ := h.File("web1", "/etc/monit/conf.d/settings"); !strings.Contains(c, "allow admin:hunter2\n# Hunter2\n") {
		t.Errorf("settings = %q; the host needs the real values", c)
	}
	if c, ok := h.File("web1", "/etc/monit/hunter2.key"); !ok || c != "k\n" {
		t.Errorf("the key file at the real path: %q, %v", c, ok)
	}
	if log := strings.Join(h.Log["web1"], "\n"); !strings.Contains(log, "command monit-passwd hunter2") {
		t.Errorf("the host log %q has no then with the real value", log)
	}
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecretThen(t *testing.T) {
	p, _ := secretProject(t)
	plan := run.MakePlan(context.Background(), p, fakehost.New().Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "secrets", "plan-then.golden"), output(&out, &errOut))
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecretsFailedStep(t *testing.T) {
	p, _ := secretProject(t)
	h := fakehost.New()
	h.FailApply("web1 /etc/monit/hunter2.key")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	if run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatal("apply did not fail")
	}
	// The label and the error text of the host mask the path.
	golden.Assert(t, filepath.Join("testdata", "secrets", "apply-fails.golden"), applyOutput(&out, &errOut))
}

// spec: Variables/Secrets in output; Modules/debconf
func TestSecretAnswer(t *testing.T) {
	identity, recipient := ageKey(t)
	rec := []age.Recipient{recipient}
	text, err := secret.Encrypt("new-token", rec)
	if err != nil {
		t.Fatal(err)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      token: !secret " + text + "\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - debconf:
          package: app
          question: app/token
          type: string
          value: !expr vars.token
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	// The host has the old token.
	h.SetAnswer("web1", "app/token", "old-token")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if !strings.Contains(out.String(), "    ~ debconf app/token\n        answer → \"(secret)\"\n") {
		t.Errorf("plan:\n%s%s", out.String(), errOut.String())
	}
	for _, s := range []string{"old-token", "new-token"} {
		if strings.Contains(out.String()+errOut.String(), s) {
			t.Errorf("the plan shows %q", s)
		}
	}
	applied := applyJSON(t, plan, h)
	if !strings.Contains(applied, `"changes":["answer → \"(secret)\""]`) || strings.Contains(applied, "old-token") || strings.Contains(applied, "new-token") {
		t.Errorf("applied events:\n%s", applied)
	}
}

// applyJSON applies plan on h and returns the JSON events of apply.
func applyJSON(t *testing.T, plan *run.Plan, h *fakehost.Hosts) string {
	t.Helper()
	var out bytes.Buffer
	if !run.Apply(context.Background(), plan, h.Connector(), run.NewEvents(plain(&out), time.Now)).OK() {
		t.Fatalf("apply failed:\n%s", out.String())
	}
	return out.String()
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecretContentReasons(t *testing.T) {
	identity, recipient := ageKey(t)
	rec := []age.Recipient{recipient}
	key, err := secret.Encrypt("0\x82\x00\x01\xff", rec)
	if err != nil {
		t.Fatal(err)
	}
	big, err := secret.Encrypt(strings.Repeat("s", 1<<20+1), rec)
	if err != nil {
		t.Fatal(err)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      tls_key: !secret " + key + "\n      big: !secret " + big + "\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/ssl/key.der
          content: !expr vars.tls_key
      - file:
          path: /etc/big
          content: !expr vars.big
      - file:
          path: /etc/big.conf
          content: !tpl "key: {{ .vars.big }}\n"
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	plan := run.MakePlan(context.Background(), p, fakehost.New().Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "secrets", "content-reasons.golden"), output(&out, &errOut))
}

// spec: Variables/Secrets in output; CLI/Output
func TestOldContentReasons(t *testing.T) {
	identity, recipient := ageKey(t)
	key, err := secret.Encrypt("new-key", []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      tls_key: !secret " + key + "\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/ssl/key.der
          content: !expr vars.tls_key
      - file:
          path: /etc/app.conf
          content: !tpl "key: {{ .vars.tls_key }}\n"
      - file:
          path: /etc/blob
          content: "text\n"
      - file:
          path: /etc/latin1.conf
          content: "text\n"
      - file:
          path: /etc/big.txt
          content: "text\n"
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetFile("web1", "/etc/ssl/key.der", "0\x82\x00\x01\xff")
	h.SetFile("web1", "/etc/app.conf", "key: \xff\n")
	h.SetFile("web1", "/etc/blob", "a\x00b")
	h.SetFile("web1", "/etc/latin1.conf", "caf\xe9\n")
	h.SetFile("web1", "/etc/big.txt", strings.Repeat("a", 1<<20+1))
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "secrets", "old-content-reasons.golden"), output(&out, &errOut))
}

// spec: Modules/line; Variables/Secrets in output
func TestPlanLine(t *testing.T) {
	identity, recipient := ageKey(t)
	text, err := secret.Encrypt("hunter2", []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      redis_password: !secret " + text + "\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - recipe: redis\n",
		"recipes/redis/recipe.yaml": `steps:
  - line:
      path: /etc/redis/redis.conf
      line: port 6380
      match: "^port "
  - line:
      path: /etc/redis/redis.conf
      line: !tpl "requirepass {{ .vars.redis_password }}"
      match: "^requirepass "
  - line:
      path: /etc/redis/redis.conf
      match: "^save "
      absent: true
  - line:
      path: /etc/redis/redis.conf
      line: maxmemory 256mb
      match: "^maxmemory "
  - line:
      path: /etc/redis/redis.conf
      line: !tpl "masterauth {{ .vars.redis_password }}"
      match: "^masterauth "
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetResult("web1", "^port ", module.Result{Status: module.Change, Action: module.Modify, Old: new("port 6379\n")})
	h.SetResult("web1", "^requirepass ", module.Result{Status: module.Change, Action: module.Modify, Old: new("requirepass old-pass\n")})
	h.SetResult("web1", "^save ", module.Result{Status: module.Change, Action: module.Modify, Old: new("save 900 1\nsave 300 10\n")})
	h.SetResult("web1", "^maxmemory ", module.Result{Status: module.Change, Action: module.Modify, Old: new("")})
	h.SetResult("web1", "^masterauth ", module.Result{Status: module.Change, Action: module.Modify, Old: new("")})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	golden.Assert(t, filepath.Join("testdata", "plan", "line.golden"), output(&out, &errOut))
}

// spec: Variables/Secrets in output; CLI/Output (a command of several lines)
func TestSecretCommands(t *testing.T) {
	identity, recipient := ageKey(t)
	text, err := secret.Encrypt("new-token", []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      token: !secret " + text + "\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - cmd:
          command: !tpl "true\nnotify --token {{ .vars.token }}"
      - cmd:
          command: app login
          unless: !tpl "app ping --token {{ .vars.token }}"
      - file:
          path: /etc/app.conf
          content: "a\n"
          validate: !tpl "true\napp check --token {{ .vars.token }}"
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.FailCommand("web1", "app ping --token new-token")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	plan.WriteJSON(run.NewEvents(plain(&out), func() time.Time { return time.Time{} }))
	for _, want := range []string{
		"    ? cmd\n        true\n        notify --token (secret)\n",
		"        validate:\n          true\n          app check --token (secret)\n",
		"    ~ cmd app login\n        unless: app ping --token (secret)\n",
		`"step":"cmd true\nnotify --token (secret)"`,
		`"validate":"true\napp check --token (secret)"`,
		`"unless":"app ping --token (secret)"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the plan has no %q:\n%s%s", want, out.String(), errOut.String())
		}
	}
	if strings.Contains(out.String()+errOut.String(), "new-token") {
		t.Errorf("the plan shows the secret:\n%s", out.String())
	}
}

// spec: Variables/Secrets in output (a failed placeholder variant); Modules/cmd
func TestSecretCmdUser(t *testing.T) {
	identity, recipient := ageKey(t)
	text, err := secret.Encrypt("app-deploy", []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      account: !secret " + text + "\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - cmd:
          command: app migrate
          user: !expr 'trimPrefix(vars.account, "app-")'
          dir: !expr '"/srv/" + trimPrefix(vars.account, "app-")'
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetUser("web1", "deploy")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if want := "    ? cmd app migrate\n        user: (secret)\n        dir: /srv/(secret)\n"; !strings.Contains(out.String(), want) {
		t.Errorf("the plan has no %q:\n%s%s", want, out.String(), errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), "deploy") {
		t.Errorf("the plan shows the secret:\n%s%s", out.String(), errOut.String())
	}
}

// spec: Variables/Secrets in output; Modules/cmd
func TestSecretCmdMissing(t *testing.T) {
	const cmdUser = "      - cmd:\n          command: make install\n          user: !expr '\"u-\" + vars.pw'\n"
	const cmdDir = cmdUser + "          dir: !expr '\"/srv/\" + trimPrefix(vars.pw, \"hun\")'\n"
	noDir := func(h *fakehost.Hosts) {
		h.SetUser("web1", "u-hunter2")
		h.RemoveDir("web1", "/srv/ter2")
	}
	for _, tt := range []struct {
		name, steps string
		host        func(h *fakehost.Hosts)
		want        string
	}{
		{"a missing user", cmdUser, func(*fakehost.Hosts) {}, "web1: warning: user u-(secret) does not exist yet and no user step creates it\n"},
		{"a missing dir", cmdDir, noDir, "web1: warning: dir /srv/(secret) does not exist yet and no dir step creates it\n"},
		{"a user that a later step creates", cmdUser + "      - user:\n          name: !expr '\"u-\" + vars.pw'\n", func(*fakehost.Hosts) {},
			"this step creates user u-(secret), which an earlier step needs: s#1 cmd make install; move this step before it\n"},
		{"a dir that a later step creates", cmdDir + "      - dir:\n          path: !expr '\"/srv/\" + trimPrefix(vars.pw, \"hun\")'\n          owner: !expr '\"u-\" + vars.pw'\n", noDir,
			"this step creates dir /srv/(secret), which an earlier step needs: s#1 cmd make install; move this step before it\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			identity, recipient := ageKey(t)
			text, err := secret.Encrypt("hunter2", []age.Recipient{recipient})
			if err != nil {
				t.Fatal(err)
			}
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
				"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret " + text + "\n",
				"pipelines/site.yaml":   steps(tt.steps),
			})
			filter := secret.NewFilter()
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: filter})
			if err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			tt.host(h)
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			plan.Write(color.NewWriter(&out, filter.Parts, false), color.NewWriter(&errOut, filter.Parts, false))
			if !strings.HasSuffix(errOut.String(), tt.want) {
				t.Errorf("stderr = %q, want the end %q", errOut.String(), tt.want)
			}
			if strings.Contains(out.String()+errOut.String(), "ter2") {
				t.Errorf("the plan shows a value from the secret:\n%s%s", out.String(), errOut.String())
			}
		})
	}
}

// spec: Steps (the record of a then); Variables/Secrets in output
func TestSecretThenRecord(t *testing.T) {
	sum := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return hex.EncodeToString(h[:])
	}
	tests := []struct {
		name, step string
		// ok makes the step check as ok.
		ok func(h *fakehost.Hosts)
		// legacy is the record of winch 0.1.0 for the step.
		legacy protocol.Then
	}{
		{name: "cmd", step: "      - cmd:\n          command: !tpl \"setpw {{ .vars.pw }}\"\n          creates: /srv/done\n        then: echo done\n",
			ok:     func(h *fakehost.Hosts) { h.SetFile("web1", "/srv/done", "") },
			legacy: protocol.Then{Pipeline: "site", Stage: "base", Module: "cmd", Mains: []string{sum("setpw hunter2")}}},
		{name: "file", step: "      - file:\n          path: !tpl \"/etc/{{ .vars.pw }}.key\"\n          content: \"k\\n\"\n        then: echo done\n",
			ok:     func(h *fakehost.Hosts) { h.SetFile("web1", "/etc/hunter2.key", "k\n") },
			legacy: protocol.Then{Pipeline: "site", Stage: "base", Module: "file", Mains: []string{"/etc/hunter2.key"}}},
		// The placeholder in enabled is not true or false.
		{name: "a failed placeholder variant", step: "      - service:\n          name: !tpl \"app-{{ .vars.pw }}\"\n          running: true\n          enabled: !expr 'vars.pw == \"hunter2\" || int(vars.pw) > 0'\n        then: echo done\n",
			ok:     func(h *fakehost.Hosts) { h.SetResult("web1", "app-hunter2", module.Result{Status: module.OK}) },
			legacy: protocol.Then{Pipeline: "site", Stage: "base", Module: "service", Mains: []string{"app-hunter2"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ran := func(h *fakehost.Hosts) int {
				return strings.Count(strings.Join(h.Log["web1"], "\n"), "command echo done")
			}
			h := fakehost.New()
			h.FailCommand("web1", "echo done")
			p, _ := hashSecretProject(t, "hunter2", stage+tt.step, "", nil, nil)
			if ok, got := applyAll(t, p, h); ok {
				t.Fatalf("apply passed:\n%s", got)
			}
			recs := h.ThenOf("web1")
			b, err := json.Marshal(recs)
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != 1 || strings.Contains(string(b), "hunter2") || strings.Contains(string(b), sum("setpw hunter2")) {
				t.Errorf("then records = %s, want one record without the secret", b)
			}
			// A step above moves the step; its then still runs once.
			h.Fix("web1 echo done")
			tt.ok(h)
			moved := stage + "      - file:\n          path: /etc/other\n          content: \"o\\n\"\n" + tt.step
			p, _ = hashSecretProject(t, "hunter2", moved, "", nil, nil)
			if ok, got := applyAll(t, p, h); !ok {
				t.Fatalf("apply failed:\n%s", got)
			}
			if got := ran(h); got != 2 {
				t.Errorf("the then ran %d times, want 2:\n%s", got, strings.Join(h.Log["web1"], "\n"))
			}
			if got := h.ThenOf("web1"); len(got) != 0 {
				t.Errorf("then records after the then ran = %+v", got)
			}

			// A pending record of winch 0.1.0 runs the then of the ok step once.
			h = fakehost.New()
			tt.ok(h)
			h.SetThen("web1", tt.legacy)
			p, _ = hashSecretProject(t, "hunter2", stage+tt.step, "", nil, nil)
			plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
				t.Fatalf("apply failed:\n%s", errOut.String())
			}
			if got := ran(h); got != 1 {
				t.Errorf("the then ran %d times, want 1:\n%s", got, strings.Join(h.Log["web1"], "\n"))
			}
			if got := h.ThenOf("web1"); len(got) != 0 {
				t.Errorf("then records after the then ran = %+v", got)
			}
		})
	}
}

// spec: Variables/Secrets in output
func TestSecretNameMessages(t *testing.T) {
	const name = `!expr 'trimPrefix(vars.pw, "hun")'`
	const later = "      - user:\n          name: " + name + "\n"
	for _, tt := range []struct {
		name, steps string
		host        func(h *fakehost.Hosts)
		want        string
	}{
		{"a file owner", "      - file:\n          path: /a\n          content: x\n          owner: " + name + "\n" + later, func(*fakehost.Hosts) {},
			"this step creates user (secret), which an earlier step needs: s#1 file /a; move this step before it\n"},
		{"a dir owner", "      - dir:\n          path: /a\n          owner: " + name + "\n" + later, func(h *fakehost.Hosts) { h.RemoveDir("web1", "/a") },
			"this step creates user (secret), which an earlier step needs: s#1 dir /a; move this step before it\n"},
		{"a download owner", "      - download:\n          url: https://example.com/a\n          sha256: \"" + strings.Repeat("a", 64) + "\"\n          path: /a\n          owner: " + name + "\n" + later, func(*fakehost.Hosts) {},
			"this step creates user (secret), which an earlier step needs: s#1 download /a; move this step before it\n"},
		{"a group of a user", "      - user:\n          name: app\n          groups: [" + name + "]\n      - group:\n          name: " + name + "\n", func(*fakehost.Hosts) {},
			"this step creates group (secret), which an earlier step needs: s#1 user app; move this step before it\n"},
		{"a short name", "      - file:\n          path: /a\n          content: x\n          owner: !expr 'trimPrefix(vars.pw, \"hunte\")'\n      - user:\n          name: !expr 'trimPrefix(vars.pw, \"hunte\")'\n", func(*fakehost.Hosts) {},
			"this step creates user (secret), which an earlier step needs: s#1 file /a; move this step before it\n"},
		{"a short cmd user", "      - cmd:\n          command: make\n          user: !expr 'trimPrefix(vars.pw, \"hunte\")'\n      - user:\n          name: !expr 'trimPrefix(vars.pw, \"hunte\")'\n", func(*fakehost.Hosts) {},
			"this step creates user (secret), which an earlier step needs: s#1 cmd make; move this step before it\n"},
		{"a short group in groups", "      - user:\n          name: app\n          groups: [wheel, !expr 'trimPrefix(vars.pw, \"hunte\")']\n      - group:\n          name: !expr 'trimPrefix(vars.pw, \"hunte\")'\n", func(*fakehost.Hosts) {},
			"this step creates group (secret), which an earlier step needs: s#1 user app; move this step before it\n"},
		{"a change line from the host", "      - dir:\n          path: /a\n          owner: " + name + "\n", func(h *fakehost.Hosts) {
			h.SetResult("web1", "/a", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner root → ter2; user ter2 does not exist yet"}})
		}, "        owner → (secret); user (secret) does not exist yet\n\n1 host: 1 to change, 0 unchanged, 0 unknown\nplan "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, filter := hashSecretProject(t, "hunter2", steps(tt.steps), "", nil, nil)
			h := fakehost.New()
			tt.host(h)
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			plan.Write(color.NewWriter(&out, filter.Parts, false), color.NewWriter(&errOut, filter.Parts, false))
			if all := out.String() + errOut.String(); !strings.Contains(all, tt.want) || strings.Contains(all, "ter2") {
				t.Errorf("output = %q, want %q and no ter2", all, tt.want)
			}
		})
	}
}

// spec: Variables/Secrets in output
func TestSecretHostText(t *testing.T) {
	// The parts are ter2, er2, and the short part r2.
	const part4, part3, part2 = `!expr 'trimPrefix(vars.pw, "hun")'`, `!expr 'trimPrefix(vars.pw, "hunt")'`, `!expr 'trimPrefix(vars.pw, "hunte")'`
	dir := func(owner string) string { return "      - dir:\n          path: /a\n          owner: " + owner + "\n" }
	change := func(lines ...string) func(h *fakehost.Hosts) {
		return func(h *fakehost.Hosts) {
			h.SetResult("web1", "/a", module.Result{Status: module.Change, Action: module.Modify, Changes: lines})
		}
	}
	for _, tt := range []struct {
		name, steps string
		host        func(h *fakehost.Hosts)
		apply       bool
		want, not   string
	}{
		{"a plain new value keeps the old value", dir(part4), change("mode 0755 → 0700"), false, "        mode 0755 → 0700\n", "ter2"},
		{"a field of two words", "      - hostname:\n          name: !expr '\"h-\" + trimPrefix(vars.pw, \"hun\")'\n",
			func(h *fakehost.Hosts) {
				h.SetResult("web1", "h-ter2", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"static name old → h-ter2"}})
			}, false, "        static name → h-(secret)\n", "ter2"},
		{"a quoted old value", dir(part4), change(`comment "old one" → "ter2"`), false, "        comment → \"(secret)\"\n", "old one"},
		{"a part of 3 characters", dir(part3), change("owner root → er2; user er2 does not exist yet"), false,
			"        owner → (secret); user (secret) does not exist yet\n", "er2"},
		{"a short part", dir(part2), change("mode 0755 → 0700"), false, "    ~ dir /a\n        (secret)\n", "0755"},
		{"a link from the host", dir(part3), func(h *fakehost.Hosts) {
			h.SetResult("web1", "/a", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"mode 0755 → 0700"}, Link: "/srv/er2"})
		}, false, "    ~ dir /a (link to /srv/(secret))\n", "er2"},
		{"no link", dir(part2), change("mode 0755 → 0700"), false, "    ~ dir /a\n", "link to"},
		{"a diff with a short part", "      - file:\n          path: /a\n          content: \"a\\n\"\n          owner: " + part2 + "\n",
			func(h *fakehost.Hosts) { h.SetFile("web1", "/a", "xr2\n") }, false, "        (secret)\n", "xr2"},
		{"a check error with a short part", "      - file:\n          path: !expr '\"/srv/\" + trimPrefix(vars.pw, \"hunte\")'\n          content: a\n",
			func(h *fakehost.Hosts) { h.FailCheck("web1 /srv/r2") }, false, "web1: s: file /srv/(secret): (secret)\n", "permission denied"},
		{"a failed rollback with a short part", "      - hostname:\n          name: !expr '\"h-\" + trimPrefix(vars.pw, \"hunte\")'\n",
			func(h *fakehost.Hosts) {
				h.SetTimer(-time.Second)
				h.FailRollback(errors.New("restore /etc/hostname: no space left on device"))
				h.SetResult("web1", "h-r2", module.Result{Status: module.Change, Action: module.Modify, Guard: true})
			}, true, "the rollback timer ended first; the rollback failed: restore /etc/hostname: no space left on device", "r2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, filter := hashSecretProject(t, "hunter2", steps(tt.steps), "", nil, nil)
			h := fakehost.New()
			tt.host(h)
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			var out, errOut bytes.Buffer
			w, ew := color.NewWriter(&out, filter.Parts, false), color.NewWriter(&errOut, filter.Parts, false)
			plan.Write(w, ew)
			if tt.apply {
				run.Apply(t.Context(), plan, h.Connector(), run.Text(w, ew))
			}
			if all := out.String() + errOut.String(); !strings.Contains(all, tt.want) || strings.Contains(all, tt.not) {
				t.Errorf("output = %q, want %q and no %q", all, tt.want, tt.not)
			}
		})
	}
}

// spec: Variables/Secrets in output
func TestSecretStepMask(t *testing.T) {
	// The output has no text filter, so only the step mask hides the parts.
	const part = `!expr 'trimPrefix(vars.pw, "hun")'`
	dir := "      - dir:\n          path: /a\n          owner: " + part + "\n"
	change := func(line string) func(h *fakehost.Hosts) {
		return func(h *fakehost.Hosts) {
			h.SetResult("web1", "/a", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{line}})
		}
	}
	validate := "      - file:\n          path: /a\n          content: \"a\\n\"\n          validate: !expr '\"check \" + vars.pw'\n"
	// jsonPart is the part nt<er2 as JSON escapes it.
	const jsonPart = "nt" + `\` + "u003cer2"
	for _, tt := range []struct {
		name, value, steps string
		host               func(h *fakehost.Hosts)
		want, not          string
	}{
		{"a note", "hunter2", "      - pkg:\n          name: !expr '\"lib\" + trimPrefix(vars.pw, \"hun\")'\n",
			func(h *fakehost.Hosts) { h.SetNote("web1", "libter2", "apt does not know libter2", false) },
			"web1: note: apt does not know lib(secret)\n", "ter2"},
		{"a warning", "hunter2", "      - pkg:\n          name: !expr '\"lib\" + trimPrefix(vars.pw, \"hun\")'\n",
			func(h *fakehost.Hosts) { h.SetNote("web1", "libter2", "libter2 is held", true) },
			"web1: warning: lib(secret) is held\n", "ter2"},
		{"a gone then record", "hunter2", "      - file:\n          path: !expr '\"/srv/f-\" + trimPrefix(vars.pw, \"hun\")'\n          content: \"a\\n\"\n",
			func(h *fakehost.Hosts) {
				h.SetFile("web1", "/srv/f-ter2", "a\n")
				h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "s", Module: "file", Mains: []string{"/srv/f-ter2"}})
			}, "a pending then of a file step in stage s matches no step", "ter2"},
		// A record of winch 0.1.0 holds the plain main argument of a step
		// that is gone, so no part of a checked step covers it.
		{"a gone then record of a deleted step", "hunter2", "      - pkg:\n          name: !expr '\"lib\" + vars.pw[0:3]'\n",
			func(h *fakehost.Hosts) {
				h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "s", Module: "file", Mains: []string{"/srv/hunter2"}})
			}, "web1: note: a pending then of a file step in stage s matches no step and will not run\n", "hunter2"},
		{"a base64 part", "hunter2", dir, change("key dGVyMg"), "        key (secret)\n", "dGVyMg"},
		{"a JSON-escaped part", "hunt<er2", strings.ReplaceAll(validate, "vars.pw", `trimPrefix(vars.pw, "hu")`), change(`body {"a":"` + jsonPart + `"}`),
			`        body {"a":"(secret)"}` + "\n", jsonPart},
		{"a URL-encoded part", "hunt<er2", strings.ReplaceAll(validate, "vars.pw", `trimPrefix(vars.pw, "hu")`), change("url https://example.com/?q=nt%3Cer2"),
			"        url https://example.com/?q=(secret)\n", "nt%3Cer2"},
		{"a line of a multi-line part", "line-one\nline-two", validate, change("validate check line-one"),
			"        validate check (secret)\n", "line-one"},
		{"a line of plain project text", "[Peer]\nline-two", validate + "      - file:\n          path: /b\n          content: |\n            [Peer]\n",
			change("validate check [Peer]; line-two"), "        validate check [Peer]; (secret)\n", "line-two"},
		{"a short line", "ab\nline-two", validate, change("validate check ab; line-two"),
			"        validate check ab; (secret)\n", "line-two"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := hashSecretProject(t, tt.value, steps(tt.steps), "", nil, nil)
			h := fakehost.New()
			tt.host(h)
			var out, errOut bytes.Buffer
			w, ew := plain(&out), plain(&errOut)
			plan := run.MakePlan(t.Context(), p, h.ConnectorFor(false, func(n run.Note) { run.WriteNote(ew, n) }), run.Options{})
			plan.Write(w, ew)
			if all := out.String() + errOut.String(); !strings.Contains(all, tt.want) || strings.Contains(all, tt.not) {
				t.Errorf("output = %q, want %q and no %q", all, tt.want, tt.not)
			}
			// A note during apply passes the mask too.
			out.Reset()
			errOut.Reset()
			run.Apply(t.Context(), plan, h.ConnectorFor(false, func(n run.Note) { run.WriteNote(ew, n) }), run.Text(w, ew))
			if all := out.String() + errOut.String(); strings.Contains(all, tt.not) {
				t.Errorf("apply output = %q, want no %q", all, tt.not)
			}
		})
	}
}

// spec: Variables/Secrets in output (text filter)
func TestSecretBranchValue(t *testing.T) {
	p, filter := hashSecretProject(t, "hunter2", steps(`      - dir:
          path: !expr 'vars.pw == "hunter2" ? "/srv/data" : "/srv/x"'
      - file:
          path: /srv/data/plain.txt
          content: "a\n"
`), "", nil, nil)
	h := fakehost.New()
	h.RemoveDir("web1", "/srv/data")
	plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(color.NewWriter(&out, filter.Parts, false), color.NewWriter(&errOut, filter.Parts, false))
	if all := out.String() + errOut.String(); !strings.Contains(all, "    + dir /srv/(secret)\n") || !strings.Contains(all, "    + file /srv/data/plain.txt\n") {
		t.Errorf("output = %q, want the masked branch value and the plain path of the second step", all)
	}
}
