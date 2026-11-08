package run_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/facts"
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
      path: !tpl "/etc/monit/{{ vars.monit_password }}.key"
      content: "k\n"
    then: !tpl "monit-passwd {{ vars.monit_password }}"
  - file:
      path: /etc/monit/hidden
      content: !tpl "{{ vars.monit_m[vars.monit_password] }}\n"
`,
		"recipes/monit/templates/settings.tmpl": "set httpd port 2812\n  allow {{ vars.monit_user }}:{{ vars.monit_password }}\n# {{ upper(vars.monit_password[:1]) + vars.monit_password[1:] }}\n",
	})
	filter := secret.NewFilter()
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	return p, filter
}

// spec: Variables/Secrets in output (file diffs)
func TestSecretRecord(t *testing.T) {
	p, _ := secretProject(t)
	h := fakehost.New()
	const path = "/etc/monit/conf.d/settings"
	h.SetFile("web1", path, "old line\n")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if !strings.Contains(out.String(), "-(line hidden: may hold a secret)\n") {
		t.Errorf("a file with no record:\n%s", out.String())
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatalf("apply: %s", errOut.String())
	}
	h.SetFile("web1", path, "set httpd port 2812\n  allow admin:old-pass\n# Old-Pass\n")
	out.Reset()
	plan = run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	plan.Write(plain(&out), plain(&errOut))
	for _, want := range []string{"-  allow admin:(secret)\n", "+  allow admin:(secret) (secret value changed)\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("after an apply, the plan lacks %q:\n%s", want, out.String())
		}
	}
}

// spec: Variables/Secrets in output (file diffs)
func TestSecretRecordOfAPlainStep(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/pw\n          content: \"pw=plain\\n\"\n",
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetFile("web1", "/etc/pw", "pw=old-secret\n")
	h.SetMasked("web1", "/etc/pw", "pw=(secret)\n")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if s := out.String(); !strings.Contains(s, "-pw=(secret)\n") || !strings.Contains(s, "+pw=plain\n") || strings.Contains(s, "old-secret") {
		t.Errorf("a variable made plain:\n%s", s)
	}
	if !run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))).OK() {
		t.Fatalf("apply: %s", errOut.String())
	}
	h.SetFile("web1", "/etc/pw", "pw=other\n")
	out.Reset()
	plan = run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	plan.Write(plain(&out), plain(&errOut))
	if s := out.String(); !strings.Contains(s, "-pw=other\n") {
		t.Errorf("the record stays after a write without a secret:\n%s", s)
	}
}

// spec: Variables/Secrets in output (file diffs)
func TestSecretRecordOfAPlainLineStep(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - line:\n          path: /etc/app.conf\n          line: workers 3\n          match: \"^workers \"\n      - line:\n          path: /etc/app.conf\n          line: pw open\n          match: \"^pw \"\n",
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetResult("web1", "^workers ", module.Result{Status: module.Change, Action: module.Modify, Old: new("workers 2\n"), Masked: new("pw (secret)\n")})
	h.SetResult("web1", "^pw ", module.Result{Status: module.Change, Action: module.Modify, Old: new("pw old-secret\n"), Masked: new("pw (secret)\n")})
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	s := out.String()
	for _, want := range []string{"-workers 2\n", "+workers 3\n", "-pw (secret)\n", "+pw open\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("the plan lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "old-secret") {
		t.Errorf("the plan shows the old secret:\n%s", s)
	}
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecrets(t *testing.T) {
	p, _ := secretProject(t)
	h := fakehost.New()
	h.SetFile("web1", "/etc/monit/conf.d/settings", "set httpd port 2812\n  allow admin:old-pass\n# Old-Pass\n")
	h.SetMasked("web1", "/etc/monit/conf.d/settings", "set httpd port 2812\n  allow admin:(secret)\n# (secret)\n")
	h.SetReact("web1", protocol.React{Recipe: "monit", Module: "file", Mains: mains("/etc/monit/hunter2.key"), Then: true})
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
          content: !tpl "key: {{ vars.big }}\n"
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
          content: !tpl "key: {{ vars.tls_key }}\n"
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
      line: !tpl "requirepass {{ vars.redis_password }}"
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
      line: !tpl "masterauth {{ vars.redis_password }}"
      match: "^masterauth "
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.SetResult("web1", "^port ", module.Result{Status: module.Change, Action: module.Modify, Old: new("port 6379\n")})
	h.SetResult("web1", "^requirepass ", module.Result{Status: module.Change, Action: module.Modify, Old: new("requirepass old-pass\n"), Masked: new("requirepass (secret)\n")})
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
          command: !tpl "true\nnotify --token {{ vars.token }}"
      - cmd:
          command: app login
          unless: !tpl "app ping --token {{ vars.token }}"
      - file:
          path: /etc/app.conf
          content: "a\n"
          validate: !tpl "true\napp check --token {{ vars.token }}"
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.FailCommandWith("web1", "app ping --token new-token", "token new-token is not valid")
	plan := run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	plan.WriteJSON(run.NewEvents(plain(&out), func() time.Time { return time.Time{} }))
	for _, want := range []string{
		"    ? cmd\n        true\n        notify --token (secret)\n",
		"        validate:\n          true\n          app check --token (secret)\n",
		"    ~ cmd app login\n        unless: app ping --token (secret)\n        stderr:\n          token (secret) is not valid\n",
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
		{"a missing owner from the host", cmdDir + "      - file: {path: /etc/a, stock: true}\n", func(h *fakehost.Hosts) {
			h.SetUser("web1", "u-hunter2")
			h.SetResult("web1", "/etc/a", module.Result{Status: module.Change, Action: module.Create, Missing: []string{"user ter2"}})
		}, "web1: warning: user (secret) does not exist yet and no user step creates it\n"},
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
	tests := []struct {
		name, step string
		// ok makes the step check as ok.
		ok func(h *fakehost.Hosts)
	}{
		{name: "cmd", step: "      - cmd:\n          command: !tpl \"setpw {{ vars.pw }}\"\n          creates: /srv/done\n        then: echo done\n",
			ok: func(h *fakehost.Hosts) { h.SetFile("web1", "/srv/done", "") }},
		{name: "file", step: "      - file:\n          path: !tpl \"/etc/{{ vars.pw }}.key\"\n          content: \"k\\n\"\n        then: echo done\n",
			ok: func(h *fakehost.Hosts) { h.SetFile("web1", "/etc/hunter2.key", "k\n") }},
		// The placeholder in enabled is not true or false.
		{name: "a failed placeholder variant", step: "      - file:\n          path: !tpl \"/etc/{{ vars.pw }}.k\"\n          content: \"k\\n\"\n          mode: !expr 'vars.pw == \"hunter2\" || int(vars.pw) > 0 ? \"0600\" : \"0644\"'\n        then: echo done\n",
			ok: func(h *fakehost.Hosts) { h.SetFile("web1", "/etc/hunter2.k", "k\n") }},
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
			recs := h.ReactOf("web1")
			b, err := json.Marshal(recs)
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != 1 || strings.Contains(string(b), "hunter2") {
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
			if got := h.ReactOf("web1"); len(got) != 0 {
				t.Errorf("records after the then ran = %+v", got)
			}
		})
	}
}

// spec: Steps
func TestThenRecordHash(t *testing.T) {
	record := func(t *testing.T, secrets map[string]string, step string) protocol.React {
		t.Helper()
		h := fakehost.New()
		h.FailCommand("web1", "echo done")
		p, _ := secretsProject(t, secrets, stage+step, "", nil, nil)
		if ok, got := applyAll(t, p, h); ok {
			t.Fatalf("apply passed:\n%s", got)
		}
		recs := h.ReactOf("web1")
		if len(recs) != 1 {
			t.Fatalf("then records = %+v, want one", recs)
		}
		return recs[0]
	}
	file := func(path string) string {
		return "      - file:\n          path: " + path + "\n          content: \"k\\n\"\n        then: echo done\n"
	}
	one := map[string]string{"pw": "hunter2"}
	pw := record(t, one, file(`!tpl "/etc/app/{{ vars.pw }}.key"`))
	pw2 := record(t, map[string]string{"pw2": "hunter3"}, file(`!tpl "/etc/app/{{ vars.pw2 }}.key"`))
	if pw.Matches(pw2) {
		t.Errorf("the pw and pw2 steps have records that match: %+v and %+v", pw, pw2)
	}
	if want := (protocol.React{Pipeline: "site", Stage: "base", Module: "file", Mains: mains("/etc/app/hunter2.key"), Then: true}); !reflect.DeepEqual(pw, want) {
		t.Errorf("record of the pw step = %+v, want %+v", pw, want)
	}
	changed := record(t, map[string]string{"pw": "hunter4"}, file(`!tpl "/etc/app/{{ vars.pw }}.key"`))
	if pw.Matches(changed) {
		t.Errorf("the record did not change with the secret: %+v", changed)
	}
	plain := record(t, one, file("/etc/motd")+file(`!tpl "/etc/app/{{ vars.pw }}.key"`))
	if want := mains("/etc/motd"); !reflect.DeepEqual(plain.Mains, want) {
		t.Errorf("main arguments of a plain step = %q, want %q", plain.Mains, want)
	}
	cmd := record(t, one, "      - cmd:\n          command: !tpl \"setpw {{ vars.pw }}\"\n          creates: /srv/done\n        then: echo done\n")
	if want := mains("setpw hunter2"); !reflect.DeepEqual(cmd.Mains, want) {
		t.Errorf("main arguments of a cmd step = %q, want %q", cmd.Mains, want)
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
				h.SetReact("web1", protocol.React{Pipeline: "site", Stage: "s", Module: "file", Mains: []string{"/srv/f-ter2"}, Then: true})
			}, "a pending then of a file step of stage s matches no step", "ter2"},
		// A record of winch 0.1.0 holds the plain main argument of a step
		// that is gone, so no part of a checked step covers it.
		{"a gone then record of a deleted step", "hunter2", "      - pkg:\n          name: !expr '\"lib\" + vars.pw[0:3]'\n",
			func(h *fakehost.Hosts) {
				h.SetReact("web1", protocol.React{Pipeline: "site", Stage: "s", Module: "file", Mains: []string{"/srv/hunter2"}, Then: true})
			}, "web1: note: a pending then of a file step of stage s matches no step and will not run\n", "hunter2"},
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
			plan := run.MakePlan(t.Context(), p, h.ConnectorFor("", false, func(n run.Note) { run.WriteNote(ew, n) }), run.Options{})
			plan.Write(w, ew)
			if all := out.String() + errOut.String(); !strings.Contains(all, tt.want) || strings.Contains(all, tt.not) {
				t.Errorf("output = %q, want %q and no %q", all, tt.want, tt.not)
			}
			// A note during apply passes the mask too.
			out.Reset()
			errOut.Reset()
			run.Apply(t.Context(), plan, h.ConnectorFor("", false, func(n run.Note) { run.WriteNote(ew, n) }), run.Text(w, ew))
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

// spec: Variables/Secrets; Templates and expressions/Data
func TestSecretOfOtherHost(t *testing.T) {
	tests := []struct {
		name, vars, stepVars string
		secret               bool
	}{
		{"an expression default", `  app_set: !expr 'match("db1")[0].vars.pw != ""'` + "\n", "", true},
		{"a template default", `  app_set: !tpl '{{ for h in hosts }}{{ if h.name == "db1" }}{{ h.vars.pw != "" }}{{ end }}{{ end }}'` + "\n", "", true},
		{"a secret default of the other host", "  app_pw_set: !expr 'vars.pw != \"\"'\n  app_set: !expr 'match(\"db1\")[0].vars.app_pw_set != nil'\n", "", true},
		{"a value of a recipe step", "  app_set: x\n", "        vars:\n          app_set: !expr 'match(\"db1\")[0].vars.pw != \"\"'\n", true},
		{"a plain variable", "  app_name: x\n  app_set: !expr 'match(\"db1\")[0].vars.app_name != \"\"'\n", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, recipient := ageKey(t)
			text, err := secret.Encrypt("hunter2", []age.Recipient{recipient})
			if err != nil {
				t.Fatal(err)
			}
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
				"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: plain-pw\n  db1:\n    vars:\n      pw: !secret " + text + "\n",
				"pipelines/site.yaml":   "stages:\n  - name: s\n    hosts: web1\n    steps:\n      - recipe: app\n" + tt.stepVars,
				"recipes/app/recipe.yaml": "vars:\n" + tt.vars + "steps:\n  - dir:\n      path: !tpl \"/srv/{{ vars.app_set }}\"\n" +
					"  - dir:\n      path: /srv/pw\n    when: !expr 'vars.pw != \"\"'\n",
			})
			filter := secret.NewFilter()
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: filter})
			if err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			h.RemoveDir("web1", "/srv/true")
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			var out, errOut, events bytes.Buffer
			plan.Write(color.NewWriter(&out, filter.Parts, false), color.NewWriter(&errOut, filter.Parts, false))
			plan.WriteJSON(run.NewEvents(color.NewWriter(&events, filter.Parts, false), func() time.Time { return time.Time{} }))
			for _, got := range []string{out.String(), events.String()} {
				if strings.Contains(got, "/srv/(secret)") != tt.secret || strings.Contains(got, "/srv/true") == tt.secret {
					t.Errorf("output = %q, want the path secret: %v%s", got, tt.secret, errOut.String())
				}
			}
		})
	}
}

// spec: Variables/Secrets in output (three evaluations)
func TestSecretOfWholeHost(t *testing.T) {
	const setStep = "  - cmd:\n      command: !tpl \"echo /srv/{{ vars.app_set }}/x\"\n"
	const peers = `app_peers: !expr 'match("db")'`
	tests := []struct {
		name, stepVars, defaults, step string
		// secret is in the output when db1 has the secret, and leak is not;
		// plain is in the output when db1 has the value as plain text.
		secret, leak, plain string
	}{
		{"json of hosts", `app_set: !expr 'json(hosts) contains "hunter2"'`, "", setStep, "/srv/(secret)/x", "/srv/true/x", ""},
		{"json of a host of match", `app_set: !expr 'json(match("db1")[0]) contains "hunter2"'`, "", setStep, "/srv/(secret)/x", "/srv/true/x", "/srv/true/x"},
		{"a read by name", `app_set: !expr 'match("db1")[0].vars.pw contains "hunter2"'`, "", setStep, "/srv/(secret)/x", "/srv/true/x", ""},
		{"a variable that holds hosts", peers, "", "  - cmd:\n      command: !expr '\"echo /srv/\" + upper(replace(json(vars.app_peers[0]), `\"`, \"\"))'\n", "PW:(secret)}", "HUNTER2", "PW:HUNTER2}"},
		{"names from a variable that holds hosts", peers, "  app_names: !expr 'join(map(vars.app_peers, .name), \"-\")'\n", "  - cmd:\n      command: !tpl \"echo /srv/{{ vars.app_names }}/y\"\n", "/srv/db1/y", "", "/srv/db1/y"},
		{"json of a loop item", "", "", "  - cmd:\n      command: !expr '\"echo /srv/\" + upper(replace(json(item), `\"`, \"\"))'\n    loop: !expr 'match(\"db\")'\n", "PW:(secret)}", "HUNTER2", "PW:HUNTER2}"},
	}
	for _, tt := range tests {
		for _, secretOnDB := range []bool{true, false} {
			if !secretOnDB && tt.plain == "" {
				continue
			}
			t.Run(fmt.Sprintf("%s/secret %v", tt.name, secretOnDB), func(t *testing.T) {
				identity, recipient := ageKey(t)
				// Without the secret on db1, the project keeps a secret on web1,
				// which the reads of db1 do not reach.
				value, web, want, leak := "hunter2", "pw: plain-pw", tt.secret, tt.leak
				if !secretOnDB {
					value, web, want, leak = "kwzqxjqz", "", tt.plain, ""
				}
				text, err := secret.Encrypt(value, []age.Recipient{recipient})
				if err != nil {
					t.Fatal(err)
				}
				db := "pw: !secret " + text
				if !secretOnDB {
					web, db = db, "pw: hunter2"
				}
				dir := vmtest.WriteProject(t, map[string]string{
					"winch.yaml":              "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\nvars:\n  pw: \"\"\n",
					"inventories/test.yaml":   "hosts:\n  web1:\n    vars:\n      " + web + "\n  db1:\n    vars:\n      " + db + "\ngroups:\n  db:\n    hosts: [db1]\n",
					"pipelines/site.yaml":     "stages:\n  - name: s\n    hosts: web1\n    steps:\n      - recipe: app\n        vars:\n          app_name: x\n          " + tt.stepVars + "\n",
					"recipes/app/recipe.yaml": "vars:\n  app_name: x\n  app_set: x\n  app_peers: []\n" + tt.defaults + "steps:\n" + tt.step,
				})
				filter := secret.NewFilter()
				p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: filter})
				if err != nil {
					t.Fatal(err)
				}
				plan := run.MakePlan(t.Context(), p, fakehost.New().Connector(), run.Options{})
				var out, errOut, events bytes.Buffer
				plan.Write(color.NewWriter(&out, filter.Parts, false), color.NewWriter(&errOut, filter.Parts, false))
				plan.WriteJSON(run.NewEvents(color.NewWriter(&events, filter.Parts, false), func() time.Time { return time.Time{} }))
				if errOut.Len() > 0 {
					t.Fatalf("errors: %s", errOut.String())
				}
				for _, got := range []string{out.String(), events.String()} {
					if !strings.Contains(got, want) || leak != "" && strings.Contains(got, leak) {
						t.Errorf("output = %q, want %q and no %q", got, want, leak)
					}
				}
			})
		}
	}
}

// spec: Variables/Secrets in output (text filter)
func TestSecretPartsOfHost(t *testing.T) {
	// The steps that read no secret are in the stage before the steps that
	// build values from the secret. The dir step has a part of 2 characters,
	// which hides only the host text of that step.
	p, filter := hashSecretProject(t, "kwzqxjqz", `stages:
  - name: a
    hosts: all
    steps:
      - file:
          path: /srv/plain
          content: "a\n"
          owner: root
      - file:
          path: /srv/conf
          content: "token new\n"
      - link:
          path: /srv/current
          target: /srv/app
  - name: b
    hosts: all
    steps:
      - user:
          name: !expr '"u" + vars.pw[2:6]'
      - dir:
          path: /srv/d
          owner: !expr 'vars.pw[6:]'
`, "", nil, nil)
	h := fakehost.New()
	h.SetResult("web1", "/srv/plain", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner uzqxj → root", "mode 0644 → 0600"}})
	h.SetFile("web1", "/srv/conf", "token uzqxj\n")
	h.SetResult("web1", "/srv/current", module.Result{Status: module.Change, Action: module.Modify, Link: "/srv/uzqxj", Changes: []string{"target /srv/old → /srv/app"}})
	plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	w, ew := color.NewWriter(&out, filter.Parts, false), color.NewWriter(&errOut, filter.Parts, false)
	plan.Write(w, ew)
	plan.WriteJSON(run.NewEvents(w, func() time.Time { return time.Time{} }))
	all := out.String() + errOut.String()
	for _, want := range []string{
		"        owner u(secret) → root\n        mode 0644 → 0600\n",
		"        -token u(secret)\n",
		"(link to /srv/u(secret))\n        target /srv/old → /srv/app\n",
		`"changes":["owner u(secret) → root","mode 0644 → 0600"]`,
		`"-token u(secret)"`,
		`"link":"/srv/u(secret)"`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the plan has no %q:\n%s", want, all)
		}
	}
	if applied := applyJSON(t, plan, h); strings.Contains(all+applied, "zqxj") {
		t.Errorf("the output shows the part zqxj:\n%s%s", all, applied)
	}
}

// spec: Variables/Secrets in output; Modules/line; Modules/user; Modules/debconf
func TestSecretPublicFile(t *testing.T) {
	const (
		line    = "the file holds a secret and others can read it; write the secret to a file with mode 0600 in a file step"
		comment = "the user comment holds a secret, and every user of the host can read /etc/passwd"
		answer  = "debconf keeps the answer in /var/cache/debconf/config.dat, which every user of the host can read; only a password answer goes to a root-only file"
	)
	identity, recipient := ageKey(t)
	var texts []string
	for _, v := range []string{"hunter2", "$6$aaa$alicehash"} {
		text, err := secret.Encrypt(v, []age.Recipient{recipient})
		if err != nil {
			t.Fatal(err)
		}
		texts = append(texts, text)
	}
	lineStep := func(l, match string) string {
		return "      - line:\n          path: /etc/environment\n          line: " + l + "\n          match: " + match + "\n"
	}
	userStep := func(c string) string {
		return "      - user:\n          name: !expr item.name\n          password: !expr item.hash\n          comment: " + c + "\n        loop: !expr vars.users\n"
	}
	debconfStep := func(typ, v string) string {
		return "      - debconf:\n          package: app\n          question: app/token\n          type: " + typ + "\n          value: " + v + "\n"
	}
	secretLine := lineStep(`!tpl "TOKEN={{ vars.token }}"`, "^TOKEN=")
	for _, tt := range []struct {
		name, steps string
		// later are steps after the token file.
		later string
		res   *module.Result
		want  []string
	}{
		{name: "line change", steps: secretLine, res: &module.Result{Status: module.Change, Action: module.Modify, OthersRead: true}, want: []string{"5:9: " + line}},
		{name: "line ok", steps: secretLine, res: &module.Result{Status: module.OK, OthersRead: true}, want: []string{"5:9: " + line}},
		{name: "line into a file with mode 0600", steps: secretLine, res: &module.Result{Status: module.OK}},
		{name: "plain line", steps: lineStep("TOKEN=x", "^TOKEN="), res: &module.Result{Status: module.OK, OthersRead: true}},
		{name: "secret only in match", steps: lineStep("TOKEN=x", `!tpl "^TOKEN={{ vars.token }}|^TOKEN="`), res: &module.Result{Status: module.OK, OthersRead: true}},
		{name: "line in a loop", steps: lineStep(`!tpl "{{ item }}={{ vars.token }}"`, `!tpl "^{{ item }}="`) + "        loop: [A, B]\n", res: &module.Result{Status: module.OK, OthersRead: true}, want: []string{"5:9: " + line}},
		{name: "comment", steps: userStep(`!tpl "{{ item.name }} {{ vars.token }}"`), want: []string{"5:9: " + comment}},
		{name: "plain field in a loop over secret fields", steps: userStep("!expr item.name")},
		{name: "secret field in a comment", steps: userStep("!expr item.hash"), want: []string{"5:9: " + comment}},
		{name: "string answer", steps: debconfStep("string", "!expr vars.token"), want: []string{"5:9: " + answer}},
		{name: "computed string type", steps: debconfStep(`!expr '"string"'`, "!expr vars.token"), want: []string{"5:9: " + answer}},
		{name: "password answer", steps: debconfStep("password", "!expr vars.token")},
		{name: "computed password type", steps: debconfStep(`!expr '"password"'`, "!expr vars.token")},
		{name: "plain answer", steps: debconfStep("string", "x")},
		{name: "step with on_change", steps: "      - file:\n          path: /etc/a\n          content: x\n", later: "      - debconf:\n          package: app\n          question: app/token\n          type: string\n          value: !expr vars.token\n        on_change: [/etc/a]\n", want: []string{"12:9: " + answer}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml": "name: acme\ninventory: test\nrecipients: [" + recipient.String() + "]\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\ngroups:\n  all:\n    vars:\n      token: !secret " + texts[0] +
					"\n      users:\n        - name: alice\n          hash: !secret " + texts[1] + "\n",
				"pipelines/site.yaml": "stages:\n  - name: base\n    hosts: all\n    steps:\n" + tt.steps +
					"      - file:\n          path: /etc/app/token\n          content: !tpl \"{{ vars.token }}{{ for user in vars.users }}{{ user.hash }}{{ end }}\"\n          mode: \"0600\"\n" + tt.later,
			})
			p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
			if err != nil {
				t.Fatal(err)
			}
			h := fakehost.New()
			if tt.res != nil {
				for _, host := range []string{"web1", "web2"} {
					for _, m := range []string{"^TOKEN=", "^A=", "^B="} {
						h.SetResult(host, m, *tt.res)
					}
				}
			}
			plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
			if len(plan.Failed) > 0 {
				t.Fatalf("plan failed: %v", plan.Failed)
			}
			var got, want []string
			for _, w := range plan.Warnings {
				got = append(got, w.Error())
			}
			for _, w := range tt.want {
				want = append(want, "pipelines/site.yaml:"+w)
			}
			if g, w := strings.Join(got, "\n"), strings.Join(want, "\n"); g != w {
				t.Errorf("warnings:\n%s\nwant:\n%s", g, w)
			}
		})
	}
}

// spec: Variables/Secrets in output (text filter)
func TestSecretHostTextOutsideStep(t *testing.T) {
	// The output has no text filter, so only the masks hide the part zqxj.
	// The note comes during the check of stage a, before the check of stage
	// b, whose step builds the part. The health gate and its warning come
	// outside a step.
	p, _ := hashSecretProject(t, "kwzqxjqz", `stages:
  - name: a
    hosts: all
    health:
      command: probe
    steps:
      - file:
          path: /srv/plain
          content: "a\n"
  - name: b
    hosts: all
    steps:
      - user:
          name: !expr '"u" + vars.pw[2:6]'
`, "", nil, nil)
	h := fakehost.New()
	h.SetNote("web1", "/srv/plain", "the user uzqxj reads /srv/plain", false)
	h.FailCommandWith("web1", "probe", "user uzqxj is locked")
	h.SetNote("web1", "probe", "probe runs as uzqxj", true)
	var out, errOut bytes.Buffer
	w, ew := plain(&out), plain(&errOut)
	var shown []string
	connect := h.ConnectorFor("", false, func(n run.Note) {
		shown = append(shown, n.Text)
		run.WriteNote(ew, n)
	})
	plan := run.MakePlan(t.Context(), p, connect, run.Options{})
	if len(shown) != 1 || len(plan.Stages) != 2 {
		t.Fatalf("the note did not come during the plan of both stages: notes %q, stages %d", shown, len(plan.Stages))
	}
	plan.Write(w, ew)
	run.Apply(t.Context(), plan, connect, run.Text(w, ew))
	all := out.String() + errOut.String()
	for _, want := range []string{"web1: note: the user u(secret) reads /srv/plain\n", "user u(secret) is locked", "web1: warning: probe runs as u(secret)\n"} {
		if !strings.Contains(all, want) {
			t.Errorf("the output has no %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "zqxj") {
		t.Errorf("the output shows the part zqxj:\n%s", all)
	}
}

// spec: Variables/Secrets in output (text filter)
func TestSecretErrorsOutsideStep(t *testing.T) {
	// The output has no text filter, so only the masks hide the part zqxj.
	user := steps(`      - user:
          name: !expr '"u" + vars.pw[2:6]'
`)
	// dir is a step without a change: every directory exists on the fake
	// host.
	dir := steps(`      - dir:
          path: !expr '"/srv/d-" + vars.pw[2:6]'
`)
	failClose := func(h *fakehost.Hosts) { h.FailCloseWith("web1", "helper: no user uzqxj") }
	for _, tt := range []struct {
		name, pipeline string
		// plan runs before the plan, and apply, when set, before apply. Apply
		// runs once in text and once in JSON.
		plan, apply func(h *fakehost.Hosts)
		keep        bool
		want        []string
	}{
		{"a reboot note", user + `      - reboot:
          if_required: false
`, func(h *fakehost.Hosts) {
			h.SetBoot("web1", protocol.Boot{State: "degraded", Failed: []string{"app-uzqxj.service"}})
		}, func(*fakehost.Hosts) {}, false, []string{"(rebooted with failed units: app-u(secret).service)", `"note":"rebooted with failed units: app-u(secret).service"`}},
		{"a plan close error", user, failClose, nil, false, []string{"web1: helper: no user u(secret)"}},
		{"an apply close error", user, func(*fakehost.Hosts) {}, failClose, false, []string{"web1: helper: no user u(secret)", `"error":"helper: no user u(secret)"`}},
		{name: "an idle close error with keep", pipeline: dir, plan: failClose, keep: true, want: []string{"web1: helper: no user u(secret)"}},
		{"a close error of a host that apply only clears", dir, func(h *fakehost.Hosts) {
			h.SetReact("web1", protocol.React{Pipeline: "site", Stage: "s", Module: "file", Mains: []string{"/srv/gone"}, Then: true})
		}, failClose, false, []string{"web1: helper: no user u(secret)"}},
		{"a pending call error", user, func(h *fakehost.Hosts) {
			h.FailPendingWith("web1", "restore /home/uzqxj/x: no space left on device")
		}, nil, false, []string{"web1: restore /home/u(secret)/x: no space left on device"}},
		{"a rollback line of an earlier run", user, func(h *fakehost.Hosts) {
			h.SetDue("web1", "put back /home/uzqxj/.ssh/authorized_keys")
		}, func(*fakehost.Hosts) {}, false, []string{"put back /home/u(secret)/.ssh/authorized_keys", `"changes":["put back /home/u(secret)/.ssh/authorized_keys"]`}},
		{"a reboot error", user + `      - reboot:
          if_required: false
`, func(h *fakehost.Hosts) {
			h.SetFacts("web1", facts.Facts{OS: facts.OS{ID: "debian", Version: "13", Codename: "trixie", Arch: "amd64"}})
			h.SetBoot("web1", protocol.Boot{Packages: []string{"app-uzqxj"}})
		}, func(*fakehost.Hosts) {}, false, []string{"/run/reboot-required lists the packages app-u(secret)"}},
		{"a health warning before any step", `stages:
  - name: gate
    hosts: all
    health:
      command: probe
    steps: []
  - name: s
    hosts: all
    steps:
      - dir:
          path: !expr '"/srv/d-" + vars.pw[2:6]'
`, func(h *fakehost.Hosts) {
			h.Pend("web1", protocol.Check{Pipeline: "site", Stage: "gate"})
			h.SetNote("web1", "probe", "probe runs as uzqxj", true)
		}, func(*fakehost.Hosts) {}, false, []string{"web1: warning: probe runs as u(secret)\n"}},
		{"a failed rollback of an earlier run", user, func(h *fakehost.Hosts) {
			h.SetDue("web1", "~ user u(secret)")
			h.FailRollback(errors.New("restore /home/uzqxj: no space left on device"))
		}, func(*fakehost.Hosts) {}, false, []string{"restore /home/u(secret): no space left on device", `"error":"restore /home/u(secret): no space left on device"`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := hashSecretProject(t, "kwzqxjqz", tt.pipeline, "", nil, nil)
			h := fakehost.New()
			tt.plan(h)
			var out, errOut bytes.Buffer
			w, ew := plain(&out), plain(&errOut)
			connect := h.ConnectorFor("", false, func(n run.Note) { run.WriteNote(ew, n) })
			plan := run.MakePlan(t.Context(), p, connect, run.Options{Keep: tt.keep})
			plan.Write(w, ew)
			if tt.apply != nil {
				tt.apply(h)
				run.Apply(t.Context(), plan, connect, run.Text(w, ew))
				run.Apply(t.Context(), plan, connect, run.NewEvents(w, func() time.Time { return time.Time{} }))
			}
			all := out.String() + errOut.String()
			for _, want := range tt.want {
				if !strings.Contains(all, want) {
					t.Errorf("the output has no %q:\n%s", want, all)
				}
			}
			if strings.Contains(all, "zqxj") {
				t.Errorf("the output shows the part zqxj:\n%s", all)
			}
		})
	}
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecretCopyFrom(t *testing.T) {
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
      - file:
          path: /etc/app/env
          content: !expr vars.token
      - file:
          path: /etc/app/env.copy
          copy_from: /etc/app/env
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	// The copy on the host holds the old token.
	h.SetResult("web1", "/etc/app/env.copy", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"content from /etc/app/env"},
		Old: new("old-token"), SourceSHA256: "348e9df2a42bd6e3c6356ca9c95c5f1fe9a6b3e5cd25f4ae58df0f09049c3209"})
	plan := run.MakePlan(t.Context(), p, h.Connector(), run.Options{})
	var out, errOut bytes.Buffer
	plan.Write(plain(&out), plain(&errOut))
	if want := "    ~ file /etc/app/env.copy\n        content from /etc/app/env\n        (secret)\n"; !strings.Contains(out.String(), want) {
		t.Errorf("plan = %q, want %q", out.String(), want)
	}
	for _, s := range []string{"old-token", "new-token"} {
		if strings.Contains(out.String()+errOut.String(), s) {
			t.Errorf("the plan shows %q", s)
		}
	}
}
