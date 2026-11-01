package run_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"filippo.io/age"

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
	// The label masks the path; the error text of the host passes only the
	// filter of the CLI.
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
	if !strings.Contains(out.String(), "    ~ debconf app/token\n        answer (secret)\n") {
		t.Errorf("plan:\n%s%s", out.String(), errOut.String())
	}
	for _, s := range []string{"old-token", "new-token"} {
		if strings.Contains(out.String()+errOut.String(), s) {
			t.Errorf("the plan shows %q", s)
		}
	}
	applied := applyJSON(t, plan, h)
	if !strings.Contains(applied, `"changes":["answer (secret)"]`) || strings.Contains(applied, "old-token") || strings.Contains(applied, "new-token") {
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
		// The service module rejects the placeholder in a unit name.
		{name: "a failed placeholder variant", step: "      - service:\n          name: !tpl \"app-{{ .vars.pw }}\"\n          running: true\n        then: echo done\n",
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
			if ok, got := applyAll(t, hashSecretProject(t, "hunter2", stage+tt.step, "", nil, nil), h); ok {
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
			if ok, got := applyAll(t, hashSecretProject(t, "hunter2", moved, "", nil, nil), h); !ok {
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
			p := hashSecretProject(t, "hunter2", stage+tt.step, "", nil, nil)
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
