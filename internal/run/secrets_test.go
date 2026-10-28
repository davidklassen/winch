package run_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
func ageKey(t *testing.T) (string, *age.X25519Recipient) {
	t.Helper()
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
	h.SetThen("web1", protocol.Then{Recipe: "monit", Step: 2, Module: "file", Main: "/etc/monit/hunter2.key"})
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

// spec: Variables/Secrets in output; Modules/certbot (the old hook on the
// host can hold an older secret)
func TestSecretHook(t *testing.T) {
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
      - certbot:
          name: example.com
          domains: [example.com]
          email: admin@example.com
          deploy_hook: !tpl "notify --token {{ .vars.token }}"
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetResult("web1", "example.com", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{
		"deploy_hook notify --token old-token → notify --token new-token",
		"issue the certificate again, with a new key",
	}})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if !strings.Contains(out.String(), "    ~ certbot example.com\n        deploy_hook (secret)\n        issue the certificate again, with a new key\n") {
		t.Errorf("plan:\n%s%s", out.String(), errOut.String())
	}
	for _, s := range []string{"old-token", "new-token"} {
		if strings.Contains(out.String()+errOut.String(), s) {
			t.Errorf("the plan shows %q", s)
		}
	}
}
