package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

func fakeSecret(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "fake_secrets", name))
	if err != nil {
		t.Fatalf("read fake secret: %v", err)
	}
	return strings.TrimSuffix(string(b), "\n")
}

// testKey is an age identity in a file, for tests with secrets.
type testKey struct {
	path string
	id   *age.X25519Identity
}

func newKey(t *testing.T) testKey {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return testKey{path, id}
}

func (k testKey) encrypt(t *testing.T, plain string) string {
	t.Helper()
	rec, err := secret.ParseRecipients([]string{k.id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	text, err := secret.Encrypt(plain, rec)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// sealFiles replaces each {{secret:<value>}} in the files with !secret and
// the value encrypted for k.
func (k testKey) sealFiles(t *testing.T, files map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, text := range files {
		for {
			i := strings.Index(text, "{{secret:")
			if i < 0 {
				break
			}
			j := strings.Index(text[i:], "}}")
			plain := strings.ReplaceAll(text[i+len("{{secret:"):i+j], `\n`, "\n")
			text = text[:i] + "!secret " + k.encrypt(t, plain) + text[i+j+2:]
		}
		out[name] = text
	}
	return out
}

func (k testKey) keys() Keys {
	return Keys{Identity: secret.Identity{Path: k.path}, Filter: secret.NewFilter()}
}

var secretProject = map[string]string{
	"winch.yaml": `name: acme
inventory: inventories/test.yaml
recipients: [RECIPIENT]
vars:
  pw:
  token: {{secret:winch-yaml-token}}
  users: {}
  line: !tpl "user:{{ .vars.pw }}"
  has_pw: !expr 'vars.pw != ""'
  short: x
`,
	"inventories/test.yaml": `hosts:
  web1:
    address: 192.0.2.1
    vars:
      pw: {{secret:hunter2}}
groups:
  all:
    vars:
      users:
        alice: {{secret:$6$aaa$alicehash}}
        bob: plain-bob
`,
	"pipelines/site.yaml": stage("      - recipe: r\n"),
}

// loadSecrets loads secretProject with the recipe steps and extra files.
func loadSecrets(t *testing.T, k testKey, steps string, files map[string]string) (*Project, Keys, error) {
	t.Helper()
	all := with(secretProject, files)
	all["winch.yaml"] = strings.Replace(all["winch.yaml"], "RECIPIENT", k.id.Recipient().String(), 1)
	if _, ok := files["recipes/r/recipe.yaml"]; !ok {
		all["recipes/r/recipe.yaml"] = recipe(steps)
	}
	keys := k.keys()
	p, err := Load(t.Context(), writeProject(t, k.sealFiles(t, all)), "", "site", nil, keys)
	return p, keys, err
}

// evalSecret returns the evaluated steps of the recipe on web1.
func evalSecret(t *testing.T, steps string, files map[string]string) ([]Step, Keys, error) {
	t.Helper()
	k := newKey(t)
	p, keys, err := loadSecrets(t, k, steps, files)
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.Start(p.Inventory.Hosts[0], debian13)
	if err != nil {
		return nil, keys, err
	}
	var out []Step
	for _, st := range p.Pipeline.Stages[0].Steps[0].Recipe.Steps {
		s, err := st.Eval(env)
		if err != nil {
			return nil, keys, err
		}
		out = append(out, s...)
	}
	return out, keys, nil
}

func shownLines(st Step) string {
	if st.Shown == nil {
		return "no shown"
	}
	if st.Shown.Hidden {
		return "hidden"
	}
	var b strings.Builder
	for _, l := range st.Shown.Lines {
		b.WriteString(l.Show)
	}
	return b.String()
}

// spec: Variables/Secrets; Variables/Secrets in output
func TestEvalSecrets(t *testing.T) {
	tests := []struct {
		name string
		step string
		// data is the content for the host, lines the content as shown.
		data, lines string
		main, then  string
	}{
		{name: "content reads a secret", step: "  - file:\n      path: /a\n      content: !tpl \"pw={{ .vars.pw }}\\n\"\n",
			data: "pw=hunter2\n", lines: "pw=(secret)\n", main: "/a"},
		{name: "a default that reads a secret is secret", step: "  - file:\n      path: /a\n      content: !tpl \"{{ .vars.line }}\\n\"\n",
			data: "user:hunter2\n", lines: "user:(secret)\n", main: "/a"},
		{name: "a derived value that the secret does not change", step: "  - file:\n      path: /a\n      content: !tpl \"set={{ .vars.has_pw }}\\n\"\n",
			data: "set=true\n", lines: "set=(secret)\n", main: "/a"},
		{name: "a map value is secret, its key is not", step: "  - file:\n      path: /a\n      template: users.tmpl\n",
			data: "alice:$6$aaa$alicehash\nbob:plain-bob\n", lines: "alice:(secret)\nbob:plain-bob\n", main: "/a"},
		{name: "a secret from winch.yaml", step: "  - file:\n      path: /a\n      content: !expr 'vars.token + \"\\n\"'\n",
			data: "winch-yaml-token\n", lines: "(secret)\n", main: "/a"},
		{name: "upper of a secret", step: "  - file:\n      path: /a\n      content: !expr 'upper(vars.pw) + \"\\n\"'\n",
			data: "HUNTER2\n", lines: "(secret)\n", main: "/a"},
		{name: "a path that reads a secret", step: "  - file:\n      path: !tpl \"/etc/{{ .vars.pw }}.conf\"\n      content: x\n",
			data: "x", lines: "", main: "/etc/(secret).conf"},
		{name: "a then that reads a secret", step: "  - file:\n      path: /a\n      content: x\n    then: !tpl \"echo {{ .vars.pw }} | chpasswd\"\n",
			data: "x", lines: "", main: "/a", then: "echo (secret) | chpasswd"},
		{name: "a loop over secrets", step: "  - file:\n      path: /a\n      content: !tpl \"{{ .item }}\\n\"\n    loop: !expr 'values(vars.users)'\n",
			data: "$6$aaa$alicehash\n", lines: "(secret)\n", main: "/a"},
		{name: "no secret", step: "  - file:\n      path: /a\n      content: !tpl \"{{ .vars.short }}\\n\"\n",
			data: "x\n", lines: "no shown", main: "/a"},
	}
	files := map[string]string{"recipes/r/templates/users.tmpl": "{{ range $u, $h := .vars.users }}{{ $u }}:{{ $h }}\n{{ end }}"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			steps, _, err := evalSecret(t, tt.step, files)
			if err != nil {
				t.Fatal(err)
			}
			st := steps[0]
			if got := string(st.Args.(*module.File).Data); got != tt.data {
				t.Errorf("data = %q, want %q", got, tt.data)
			}
			if got := shownLines(st); got != tt.lines {
				t.Errorf("shown lines = %q, want %q", got, tt.lines)
			}
			if got := st.ShownMain(); got != tt.main {
				t.Errorf("shown main = %q, want %q", got, tt.main)
			}
			if got := st.ShownThen(); got != tt.then {
				t.Errorf("shown then = %q, want %q", got, tt.then)
			}
		})
	}
}

// spec: Variables/Secrets in output (two evaluations)
func TestSecretContentFailsWithPlaceholders(t *testing.T) {
	files := map[string]string{
		"recipes/r/recipe.yaml":      "vars:\n  r_m: {hunter2: found}\nsteps:\n  - file:\n      path: !tpl \"/etc/{{ .vars.short }}\"\n      template: t.tmpl\n",
		"recipes/r/templates/t.tmpl": "{{ index .vars.r_m .vars.pw }}\n",
	}
	steps, _, err := evalSecret(t, "", files)
	if err != nil {
		t.Fatal(err)
	}
	st := steps[0]
	if got := string(st.Args.(*module.File).Data); got != "found\n" {
		t.Errorf("data = %q", got)
	}
	if got := shownLines(st); got != "hidden" {
		t.Errorf("shown lines = %q, want hidden", got)
	}
	if got := st.ShownMain(); got != "/etc/x" {
		t.Errorf("shown main = %q", got)
	}
}

// spec: Variables/Secrets in output (two evaluations, text filter)
func TestSecretFilterLearns(t *testing.T) {
	_, keys, err := evalSecret(t, "  - file:\n      path: /a\n      content: !expr 'upper(vars.pw) + \"\\n\" + vars.line'\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	in := "hunter2 HUNTER2 user:hunter2 $6$aaa$alicehash winch-yaml-token plain-bob"
	if got, want := keys.Filter.Text(in), "(secret) (secret) user:(secret) (secret) (secret) plain-bob"; got != want {
		t.Errorf("filter: %q, want %q", got, want)
	}
}

// spec: Variables/Secrets in output (two evaluations); CLI/Errors
func TestSecretErrors(t *testing.T) {
	tests := []struct {
		name  string
		step  string
		files map[string]string
		want  string
	}{
		{name: "expr error that holds the value", step: "  - file:\n      path: /a\n      content: !expr 'string(int(vars.pw))'\n",
			want: `recipes/r/recipe.yaml:4:16: content: invalid operation: int((secret))`},
		{name: "expr error that holds a changed value", step: "  - file:\n      path: /a\n      content: !expr 'string(int(upper(vars.pw)))'\n",
			want: `recipes/r/recipe.yaml:4:16: content: invalid operation: int((secret))`},
		{name: "template error that holds the value", step: "  - file:\n      path: /a\n      template: t.tmpl\n",
			files: map[string]string{"recipes/r/templates/t.tmpl": "{{ index .vars.users .vars.pw }}"},
			want:  `error calling index: map has no entry for key "(secret)"`},
		{name: "a type error that shows the value", step: "  - file:\n      path: /a\n      content: x\n    when: !expr vars.pw\n",
			want: `recipes/r/recipe.yaml:5:11: when: must be true or false, got the string "(secret)"`},
		{name: "an error that the placeholders do not have", step: "  - file:\n      path: /a\n      content: !expr 'vars.pw == \"hunter2\" ? string(int(vars.pw)) : \"ok\"'\n",
			want: `recipes/r/recipe.yaml:4:16: (secret)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := evalSecret(t, tt.step, tt.files)
			if err == nil {
				t.Fatal("no error")
			}
			if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "HUNTER2") {
				t.Errorf("the error shows the secret: %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q, want it to hold %q", err, tt.want)
			}
		})
	}
}

// spec: Variables/Secrets; YAML; Inventory
func TestLoadSecretErrors(t *testing.T) {
	k := newKey(t)
	tests := []struct {
		name  string
		files map[string]string
		set   []string
		want  string
	}{
		{name: "in a step argument", files: map[string]string{"pipelines/site.yaml": stage("      - file:\n          path: /a\n          content: {{secret:x}}\n")},
			want: "pipelines/site.yaml:7:20: content: !secret is allowed only in variable values; declare a variable"},
		{name: "in a recipe step argument", files: map[string]string{"recipes/r/recipe.yaml": recipe("  - file:\n      path: /a\n      content: {{secret:x}}\n")},
			want: "recipes/r/recipe.yaml:4:16: content: !secret is allowed only in variable values; declare a variable"},
		{name: "in when", files: map[string]string{"recipes/r/recipe.yaml": recipe("  - file:\n      path: /a\n      content: x\n    when: {{secret:true}}\n")},
			want: "recipes/r/recipe.yaml:5:11: when: use an expression with the !expr tag"},
		{name: "in a stage", files: map[string]string{"pipelines/site.yaml": "stages:\n  - name: web\n    hosts: {{secret:all}}\n    steps: []\n"},
			want: "pipelines/site.yaml:3:12: hosts: !secret is not allowed here"},
		{name: "in an address", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    address: {{secret:192.0.2.1}}\n"},
			want: "inventories/test.yaml:3:14: address: !secret is not allowed here"},
		{name: "on a map", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret {a: b}\n"},
			want: "inventories/test.yaml:4:11: the !secret tag needs a string, got a map"},
		{name: "not base64", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret PLACE*HOLDER\n"},
			want: "inventories/test.yaml:4:11: !secret: the value is not base64"},
		{name: "not age", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret aGVsbG8=\n"},
			want: "inventories/test.yaml:4:11: !secret: the value is not an age file"},
		{name: "bad recipient", files: map[string]string{"winch.yaml": "name: acme\ninventory: inventories/test.yaml\nrecipients: [age1nope]\nvars:\n  pw:\n"},
			want: "winch.yaml:3:13: recipients: "},
		{name: "set gives a secret", set: []string{"vars.pw=!secret abc"},
			want: "--set vars.pw=!secret abc: --set gives no !secret values"},
		{name: "wrong identity", files: map[string]string{"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret " + newKey(t).encrypt(t, "x") + "\n"},
			want: "inventories/test.yaml:4:11: !secret: the identity in " + k.path + " is not a recipient"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			all := with(secretProject, map[string]string{"recipes/r/recipe.yaml": recipe("  - file:\n      path: /a\n      content: x\n")})
			all = with(all, tt.files)
			all["winch.yaml"] = strings.Replace(all["winch.yaml"], "RECIPIENT", k.id.Recipient().String(), 1)
			_, err := Load(t.Context(), writeProject(t, k.sealFiles(t, all)), "", "site", tt.set, k.keys())
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("error %v, want it to start with %q", err, tt.want)
			}
		})
	}
}

// spec: Variables/Secrets
func TestLoadSecretIdentity(t *testing.T) {
	k := newKey(t)
	all := with(secretProject, map[string]string{"recipes/r/recipe.yaml": recipe("  - file:\n      path: /a\n      content: x\n")})
	all["winch.yaml"] = strings.Replace(all["winch.yaml"], "RECIPIENT", k.id.Recipient().String(), 1)
	dir := writeProject(t, k.sealFiles(t, all))
	missing := filepath.Join(t.TempDir(), "age.key")
	_, err := Load(t.Context(), dir, "", "site", nil, Keys{Identity: secret.Identity{Path: missing}, Filter: secret.NewFilter()})
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("Load without the identity: %v, want an error that names %s", err, missing)
	}
	// validate checks the form of each secret and needs no identity.
	if _, err := Validate(dir, "", nil); err != nil {
		t.Errorf("Validate: %v", err)
	}
	// A project without secrets needs no identity.
	plain := writeProject(t, nil)
	if _, err := Load(t.Context(), plain, "", "site", nil, Keys{Identity: secret.Identity{Path: missing}, Filter: secret.NewFilter()}); err != nil {
		t.Errorf("Load of a project without secrets: %v", err)
	}
}

// spec: Variables/Secrets in output (the load warning)
func TestLoadWarnings(t *testing.T) {
	k := newKey(t)
	line := fakeSecret(t, "key_line.txt")
	slack := fakeSecret(t, "slack_bot.txt")
	key := "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat(line+"\n", 3) + "-----END PRIVATE KEY-----\n"
	files := map[string]string{
		"inventories/test.yaml":          "hosts:\n  web1:\n    vars:\n      pw: {{secret:" + strings.ReplaceAll(key, "\n", `\n`) + "}}\n      token: " + fakeSecret(t, "ghp.txt") + "\n      users: {k: \"-----BEGIN PRIVATE KEY-----\\n" + strings.Repeat(line, 3) + "\\n-----END PRIVATE KEY-----\"}\n",
		"recipes/r/recipe.yaml":          recipe("  - file:\n      path: /a\n      template: t.tmpl\n  - file:\n      path: /b\n      source: k.pem\n"),
		"recipes/r/templates/t.tmpl":     "id {{ .vars.short }}\naws " + fakeSecret(t, "aws.txt") + "\nexample " + fakeSecret(t, "aws_example.txt") + "\n",
		"recipes/r/files/k.pem":          key,
		"recipes/r/files/unused.pem":     key,
		"pipelines/other.yaml":           "# " + slack + "\nstages:\n  - {name: a, hosts: all, steps: []}\n",
		"recipes/r/templates/stub.tmpl":  "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
		"recipes/r/files/public.pem":     strings.ReplaceAll(key, "PRIVATE", "PUBLIC"),
		"inventories/production.yaml":    "hosts:\n  web1:\n    vars:\n      pw: !secret YWdl\n",
		"recipes/r/templates/note.tmpl":  "nothing\n",
		"recipes/r/files/sub/deeper.key": "x\n" + key,
		"recipes/r/templates/key.tmpl":   "# {{ .vars.short }}\n" + key,
	}
	want := []string{
		"inventories/test.yaml:5:14: this looks like a GitHub token; use !secret",
		"inventories/test.yaml:6:19: this looks like a private key; use !secret",
		"pipelines/other.yaml:1:3: this looks like a Slack token; use !secret",
		"recipes/r/files/k.pem:1:1: this looks like a private key; use !secret",
		"recipes/r/files/sub/deeper.key:2:1: this looks like a private key; use !secret",
		"recipes/r/files/unused.pem:1:1: this looks like a private key; use !secret",
		"recipes/r/templates/key.tmpl:2:1: this looks like a private key; use !secret",
		"recipes/r/templates/t.tmpl:2:5: this looks like an AWS access key ID; use !secret",
		"winch.yaml:11:3: this looks like a Slack token; use !secret",
	}
	all := with(secretProject, files)
	all["winch.yaml"] = strings.Replace(all["winch.yaml"], "RECIPIENT", k.id.Recipient().String(), 1) + "# " + slack + "\n"
	dir := writeProject(t, k.sealFiles(t, all))
	p, err := Load(t.Context(), dir, "", "site", nil, k.keys())
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string, warnings []*yamlx.Error) {
		var got []string
		for _, w := range warnings {
			got = append(got, w.Error())
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s warnings:\n%s\nwant:\n%s", what, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	check("Load", p.Warnings)
	warnings, err := Validate(dir, "inventories/test.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	check("Validate", warnings)
}

// spec: Variables/Secrets (winch secret rekey)
func TestRekey(t *testing.T) {
	oldKey, newKey2 := newKey(t), newKey(t)
	files := oldKey.sealFiles(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients:\n  - NEW # the new key\nvars:\n  pw:\n  token: {{secret:winch-token}}\n",
		"inventories/test.yaml": "# comment\nhosts:\n  web1:\n    vars:\n      pw: &a {{secret:hunter2}}   # trailing\n      list: [{{secret:one}}, \"x\"]\n",
		"recipes/r/recipe.yaml": "vars:\n  r_key: {{secret:line1\\nline2\\n}}\n  r_quoted: !secret \"QUOTED\"\nsteps: []\n",
	})
	quoted := oldKey.encrypt(t, "quoted")
	files["recipes/r/recipe.yaml"] = strings.Replace(files["recipes/r/recipe.yaml"], "QUOTED", quoted, 1)
	files["winch.yaml"] = strings.Replace(files["winch.yaml"], "NEW", newKey2.id.Recipient().String(), 1)
	files["pipelines/site.yaml"] = "stages:\n  - {name: a, hosts: all, steps: []}\n"
	dir := writeProject(t, files)

	n, nfiles, err := Rekey(t.Context(), dir, secret.Identity{Path: oldKey.path})
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || nfiles != 3 {
		t.Errorf("Rekey = %d secrets in %d files, want 5 in 3", n, nfiles)
	}
	plain := map[string][]string{
		"winch.yaml":            {"winch-token"},
		"inventories/test.yaml": {"hunter2", "one"},
		"recipes/r/recipe.yaml": {"line1\nline2\n", "quoted"},
	}
	for name, want := range plain {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		texts := secretTexts(string(data))
		if len(texts) != len(want) {
			t.Fatalf("%s: %d secrets after rekey, want %d:\n%s", name, len(texts), len(want), data)
		}
		for i, text := range texts {
			got, err := secret.Decrypt(text, []age.Identity{newKey2.id})
			if err != nil || got != want[i] {
				t.Errorf("%s: secret %d = %q, %v; want %q for the new key", name, i, got, err, want[i])
			}
			if _, err := secret.Decrypt(text, []age.Identity{oldKey.id}); err == nil {
				t.Errorf("%s: secret %d still decrypts with the old key", name, i)
			}
		}
		// Only the secret texts change.
		old := files[name]
		for _, text := range secretTexts(old) {
			old = strings.Replace(old, text, "S", 1)
		}
		now := string(data)
		for _, text := range texts {
			now = strings.Replace(now, text, "S", 1)
		}
		if now != old {
			t.Errorf("%s changed outside its secrets:\n%s\nwas:\n%s", name, now, old)
		}
	}
}

// spec: Variables/Secrets (winch secret rekey)
func TestRekeyFailsWhole(t *testing.T) {
	k, other := newKey(t), newKey(t)
	files := k.sealFiles(t, map[string]string{
		"winch.yaml":            "name: acme\nrecipients: [" + k.id.Recipient().String() + "]\nvars:\n  pw:\n  token: {{secret:winch-token}}\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret " + other.encrypt(t, "x") + "\n",
	})
	dir := writeProject(t, files)
	_, _, err := Rekey(t.Context(), dir, secret.Identity{Path: k.path})
	if err == nil || !strings.HasPrefix(err.Error(), "inventories/test.yaml:4:11: !secret: the identity in "+k.path+" is not a recipient") {
		t.Errorf("Rekey = %v", err)
	}
	for name, want := range files {
		if data, _ := os.ReadFile(filepath.Join(dir, name)); string(data) != want {
			t.Errorf("%s changed", name)
		}
	}
}

// spec: Variables/Secrets (winch secret rekey)
func TestRekeyWritesThroughLink(t *testing.T) {
	k, next := newKey(t), newKey(t)
	dir := writeProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients: [" + next.id.Recipient().String() + "]\nvars:\n  pw:\n",
		"inventories/test.yaml": "",
		"pipelines/site.yaml":   "stages:\n  - {name: a, hosts: all, steps: []}\n",
		"shared/hosts.yaml":     "hosts:\n  web1:\n    vars:\n      pw: !secret " + k.encrypt(t, "hunter2") + "\n",
	})
	shared := filepath.Join(dir, "shared", "hosts.yaml")
	if err := os.Chmod(shared, 0o640); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"shared/alias.yaml":     "hosts.yaml",
		"inventories/test.yaml": "../shared/alias.yaml",
		"inventories/prod.yaml": "../shared/hosts.yaml",
	}
	if err := os.MkdirAll(filepath.Join(dir, "inventories"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	if n, files, err := Rekey(t.Context(), dir, secret.Identity{Path: k.path}); err != nil || n != 1 || files != 1 {
		t.Fatalf("Rekey = %d secrets in %d files, %v; want 1 in 1", n, files, err)
	}
	for link, target := range links {
		if got, err := os.Readlink(filepath.Join(dir, link)); err != nil || got != target {
			t.Errorf("%s = %q, %v; want a link to %s", link, got, err, target)
		}
	}
	info, err := os.Stat(shared)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("target mode = %v, want 0640", info.Mode().Perm())
	}
	data, err := os.ReadFile(shared)
	if err != nil {
		t.Fatal(err)
	}
	texts := secretTexts(string(data))
	if len(texts) != 1 {
		t.Fatalf("target has %d secrets:\n%s", len(texts), data)
	}
	if got, err := secret.Decrypt(texts[0], []age.Identity{next.id}); err != nil || got != "hunter2" {
		t.Errorf("target secret = %q, %v; want it for the new key", got, err)
	}
}

// secretTexts returns the base64 texts after !secret in a file, in order.
func secretTexts(s string) []string {
	var out []string
	for {
		i := strings.Index(s, "!secret ")
		if i < 0 {
			return out
		}
		s = strings.TrimLeft(s[i+len("!secret "):], `"`)
		end := strings.IndexAny(s, "\" ,]\n")
		out = append(out, s[:end])
		s = s[end:]
	}
}

// spec: YAML (anchors and aliases); Variables/Secrets
func TestSecretAlias(t *testing.T) {
	k := newKey(t)
	text := k.encrypt(t, "hunter2")
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients: [" + k.id.Recipient().String() + "]\nvars:\n  pw:\n  users: {}\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: &pw !secret " + text + "\ngroups:\n  all:\n    vars:\n      users:\n        alice: *pw\n",
		"pipelines/site.yaml":   stage("      - file:\n          path: /a\n          content: !tpl \"{{ .vars.pw }} {{ .vars.users.alice }}\\n\"\n"),
	}
	dir := writeProject(t, files)
	if _, err := Validate(dir, "", nil); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	p, err := Load(t.Context(), dir, "", "site", nil, k.keys())
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.Start(p.Inventory.Hosts[0], debian13)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := p.Pipeline.Stages[0].Steps[0].Eval(env)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(steps[0].Args.(*module.File).Data); got != "hunter2 hunter2\n" {
		t.Errorf("data = %q", got)
	}
	if got := shownLines(steps[0]); got != "(secret)\n" {
		t.Errorf("shown = %q", got)
	}
}

// spec: Variables/Secrets (winch secret rekey); Inventory
func TestRekeyKeepsEqualValuesEqual(t *testing.T) {
	k := newKey(t)
	text := k.encrypt(t, "hunter2")
	inv := "hosts:\n  web1: {}\ngroups:\n  a:\n    hosts: [web1]\n    vars:\n      pw: !secret " + text + "\n  b:\n    hosts: [web1]\n    vars:\n      pw: !secret " + text + "\n"
	dir := writeProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients: [" + k.id.Recipient().String() + "]\nvars:\n  pw:\n",
		"inventories/test.yaml": inv,
		"pipelines/site.yaml":   "stages:\n  - {name: a, hosts: all, steps: []}\n",
	})
	if _, err := Load(t.Context(), dir, "", "site", nil, k.keys()); err != nil {
		t.Fatalf("Load before rekey: %v", err)
	}
	if _, _, err := Rekey(t.Context(), dir, secret.Identity{Path: k.path}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(t.Context(), dir, "", "site", nil, k.keys()); err != nil {
		t.Errorf("Load after rekey: %v", err)
	}
}

// spec: Variables/Secrets (winch secret rekey, the load warning); Inventory
func TestInventoryOutsideInventories(t *testing.T) {
	k, next := newKey(t), newKey(t)
	dir := writeProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: prod.yaml\nrecipients: [" + next.id.Recipient().String() + "]\nvars:\n  pw:\n  token:\n",
		"prod.yaml":             "hosts:\n  web1:\n    vars:\n      pw: !secret " + k.encrypt(t, "hunter2") + "\n      token: " + fakeSecret(t, "ghp.txt") + "\n",
		"inventories/test.yaml": "",
		"pipelines/site.yaml":   "stages:\n  - {name: a, hosts: all, steps: []}\n",
	})
	n, _, err := Rekey(t.Context(), dir, secret.Identity{Path: k.path})
	if err != nil || n != 1 {
		t.Errorf("Rekey = %d, %v; want the secret of prod.yaml", n, err)
	}
	warnings, err := Validate(dir, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || warnings[0].Pos.File != "prod.yaml" {
		t.Errorf("warnings = %v, want one in prod.yaml", warnings)
	}
}

// spec: Variables/Secrets; CLI (winch validate)
func TestValidateChecksSecretForm(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nvars:\n  pw:\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret YWdl\n",
		"pipelines/site.yaml":   "stages:\n  - {name: a, hosts: all, steps: []}\n",
	})
	if _, err := Validate(dir, "", nil); err == nil || err.Error() != "inventories/test.yaml:4:11: !secret: the value is not an age file" {
		t.Errorf("Validate = %q", err)
	}
}

// spec: Variables/Secrets in output (two evaluations); Variables
func TestSecretPlaces(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{name: "a list in the inventory", files: map[string]string{
			"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: x\n      users: {list: [{{secret:first-secret}}, plain]}\n",
			"recipes/r/recipe.yaml": recipe("  - file:\n      path: /a\n      content: !tpl \"{{ index .vars.users.list 0 }} {{ index .vars.users.list 1 }}\\n\"\n"),
		}, want: "(secret) plain\n"},
		{name: "a recipe default", files: map[string]string{
			"recipes/r/recipe.yaml": "vars:\n  r_key: {{secret:recipe-secret}}\nsteps:\n  - file:\n      path: /a\n      content: !tpl \"k={{ .vars.r_key }}\\n\"\n",
		}, want: "k=(secret)\n"},
		{name: "a loop whose length depends on a secret", files: map[string]string{
			"recipes/r/recipe.yaml": recipe("  - file:\n      path: /a\n      content: !tpl \"{{ .item }}\\n\"\n    loop: !expr 'split(vars.pw, \"t\")'\n"),
		}, want: "(secret)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			steps, _, err := evalSecret(t, "", tt.files)
			if err != nil {
				t.Fatal(err)
			}
			if got := shownLines(steps[0]); got != tt.want {
				t.Errorf("shown = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Variables/Secrets in output (two evaluations: a failed placeholder
// evaluation shows the whole argument)
func TestSecretArgumentFailsWithPlaceholders(t *testing.T) {
	files := map[string]string{
		"recipes/r/recipe.yaml": "vars:\n  r_m: {hunter2: found}\nsteps:\n  - file:\n      path: !tpl \"/etc/{{ index .vars.r_m .vars.pw }}\"\n      content: x\n",
	}
	steps, _, err := evalSecret(t, "", files)
	if err != nil {
		t.Fatal(err)
	}
	if got := steps[0].Args.Main(); got != "/etc/found" {
		t.Errorf("path = %q", got)
	}
	if got := steps[0].ShownMain(); got != "(secret)" {
		t.Errorf("shown main = %q, want (secret)", got)
	}
}

// spec: Variables/Secrets in output (two evaluations); CLI/Errors
func TestSecretDefaultError(t *testing.T) {
	files := map[string]string{
		"recipes/r/recipe.yaml": "vars:\n  r_n: !expr 'string(int(vars.pw))'\nsteps:\n  - file:\n      path: /a\n      content: !expr vars.r_n\n",
	}
	_, _, err := evalSecret(t, "", files)
	if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), `variable "r_n": invalid operation: int((secret))`) {
		t.Errorf("error = %v", err)
	}
}
