package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

func fakeSecret(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "fake_secrets", name))
	if err != nil {
		t.Fatalf("read fake secret: %v", err)
	}
	return strings.TrimSuffix(string(b), "\n")
}

// newIdentity writes an age identity file and returns its path and the
// identity.
func newIdentity(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, id
}

const secretPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/pw
          content: !tpl "pw={{ .vars.pw }}\n"
        then: !tpl "echo {{ .vars.pw }} | chpasswd"
`

// secretProject writes a project with the recipient of id and the variable
// pw, and returns its directory.
func secretProject(t *testing.T, id *age.X25519Identity) string {
	t.Helper()
	return vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients:\n  - " + id.Recipient().String() + "\nvars:\n  pw:\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: PW\n",
		"pipelines/site.yaml":   secretPipeline,
	})
}

// encrypt runs winch secret encrypt and returns its stdout.
func encrypt(t *testing.T, dir, value string) string {
	t.Helper()
	r := winch(t, dir, fakehost.New(), false, value, "secret", "encrypt")
	if r.code != exitOK || !strings.HasPrefix(r.out, "!secret ") || !strings.HasSuffix(r.out, "\n") || strings.Count(r.out, "\n") != 1 {
		t.Fatalf("secret encrypt: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	return strings.TrimSuffix(r.out, "\n")
}

func setPassword(t *testing.T, dir, tagged string) {
	t.Helper()
	path := filepath.Join(dir, "inventories/test.yaml")
	if err := os.WriteFile(path, []byte("hosts:\n  web1:\n    vars:\n      pw: "+tagged+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// spec: Variables/Secrets; CLI
func TestSecretEncrypt(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	for in, want := range map[string]string{
		"hunter2\n":   "hunter2",
		"hunter2\r\n": "hunter2",
		"a\nb\n":      "a\nb\n",
	} {
		text := strings.TrimPrefix(encrypt(t, dir, in), "!secret ")
		got, err := secret.Decrypt(text, []age.Identity{id})
		if err != nil || got != want {
			t.Errorf("encrypt %q: decrypts to %q, %v; want %q", in, got, err, want)
		}
	}
	r := winch(t, dir, fakehost.New(), false, "", "secret", "encrypt")
	if r.code != exitInvalid || !strings.Contains(r.err, "the value is empty") {
		t.Errorf("empty value: exit %d, stderr %q", r.code, r.err)
	}
	none := writeProject(t, motd)
	r = winch(t, none, fakehost.New(), false, "x", "secret", "encrypt")
	if r.code != exitInvalid || !strings.Contains(r.err, "winch.yaml has no recipients") {
		t.Errorf("no recipients: exit %d, stderr %q", r.code, r.err)
	}
	r = winchWith(t, dir, "", identity, fakehost.New(), false, "", "secret", "nope")
	if r.code != exitInvalid || !strings.Contains(r.err, `unknown secret command "nope"`) {
		t.Errorf("unknown command: exit %d, stderr %q", r.code, r.err)
	}
	r = winchWith(t, dir, "", identity, fakehost.New(), false, "", "secret", "encrypt", "extra")
	if r.code != exitInvalid || !strings.Contains(r.err, "secret encrypt takes no arguments") {
		t.Errorf("argument: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecretPlan(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2\n"))
	h := fakehost.New()
	h.SetFile("web1", "/etc/pw", "pw=old-password\n")
	r := winchWith(t, dir, "", identity, h, false, "", "plan", "site")
	if r.code != exitOK || !strings.Contains(r.out, "-pw=(secret)\n") || !strings.Contains(r.out, "+pw=(secret) (secret value changed)\n") {
		t.Errorf("plan: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	h.FailCommand("web1", "echo hunter2 | chpasswd")
	r = winchWith(t, dir, "", identity, h, false, "", "apply", "site", "--yes")
	if r.code != exitFailed || !strings.Contains(r.err, "then: echo (secret) | chpasswd: exit status 1") {
		t.Errorf("apply: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	if c, _ := h.File("web1", "/etc/pw"); c != "pw=hunter2\n" {
		t.Errorf("/etc/pw = %q; the host needs the real value", c)
	}
	for _, out := range []string{r.out, r.err} {
		if strings.Contains(out, "hunter2") || strings.Contains(out, "old-password") {
			t.Errorf("the output shows a secret:\n%s", out)
		}
	}
	r = winch(t, dir, h, false, "", "plan", "site")
	if r.code != exitInvalid || !strings.Contains(r.err, "read the age identity: ") {
		t.Errorf("plan without an identity: exit %d, stderr %q", r.code, r.err)
	}
	r = winch(t, dir, h, false, "", "validate")
	if r.code != exitOK {
		t.Errorf("validate without an identity: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Variables/Secrets (winch secret rekey)
func TestSecretRekey(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2"))
	_, next := newIdentity(t)
	cfg := filepath.Join(dir, "winch.yaml")
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte(strings.Replace(string(data), id.Recipient().String(), next.Recipient().String(), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	r := winchWith(t, dir, "", identity, fakehost.New(), false, "", "secret", "rekey")
	if r.code != exitOK || r.out != "rekeyed 1 secret in 1 file\n" {
		t.Errorf("rekey: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	inv, err := os.ReadFile(filepath.Join(dir, "inventories/test.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSpace(strings.SplitAfter(string(inv), "!secret ")[1])
	if got, err := secret.Decrypt(text, []age.Identity{next}); err != nil || got != "hunter2" {
		t.Errorf("after rekey: %q, %v", got, err)
	}
	r = winchWith(t, dir, "", identity, fakehost.New(), false, "", "secret", "rekey")
	if r.code != exitInvalid || !strings.Contains(r.err, "inventories/test.yaml:4:11: !secret: the identity in "+identity+" is not a recipient") {
		t.Errorf("rekey with an old identity: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Variables/Secrets in output (the load warning)
func TestLoadWarning(t *testing.T) {
	token := fakeSecret(t, "ghp.txt")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nvars:\n  token:\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      token: " + token + "\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/token\n          content: !expr vars.token\n",
	})
	want := "inventories/test.yaml:4:14: warning: this looks like a GitHub token; use !secret\n"
	for _, args := range [][]string{{"validate"}, {"plan", "site"}} {
		r := winch(t, dir, fakehost.New(), false, "", args...)
		if r.code != exitOK || !strings.HasPrefix(r.err, want) {
			t.Errorf("%v: exit %d, stderr %q, want %q", args, r.code, r.err, want)
		}
		if strings.Contains(r.out+r.err, token[:8]) {
			t.Errorf("%v: the output shows the token", args)
		}
	}
}

// spec: Variables/Secrets (WINCH_AGE_KEY)
func TestAgeKey(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2\n"))
	key := id.String() + "\n"
	if err := os.WriteFile(filepath.Join(dir, "demo.key"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	home := vmtest.WriteProject(t, map[string]string{".config/winch/age.key": key})
	missing := filepath.Join(t.TempDir(), "missing.key")
	tests := []struct {
		name, home, ageKey string
		wantCode           int
		wantErr            string
	}{
		{"absolute path", "", identity, exitOK, ""},
		{"path relative to the current directory", "", "demo.key", exitOK, ""},
		{"home directory", home, "", exitOK, ""},
		{"the variable before the home directory", home, missing, exitInvalid, "read the age identity: open " + missing + ": no such file"},
		{"missing relative path", "", "missing.key", exitInvalid, "read the age identity: open " + filepath.Join(dir, "missing.key") + ": no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := winchWith(t, dir, tt.home, tt.ageKey, fakehost.New(), false, "", "plan", "site")
			if r.code != tt.wantCode || !strings.Contains(r.err, tt.wantErr) {
				t.Errorf("exit %d, stderr %q; want exit %d and %q", r.code, r.err, tt.wantCode, tt.wantErr)
			}
		})
	}
}
