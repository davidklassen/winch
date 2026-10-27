package cli

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
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
	r = winchWith(t, dir, "", identity, "", fakehost.New(), false, "", "secret", "nope")
	if r.code != exitInvalid || !strings.Contains(r.err, `unknown secret command "nope"`) {
		t.Errorf("unknown command: exit %d, stderr %q", r.code, r.err)
	}
	r = winchWith(t, dir, "", identity, "", fakehost.New(), false, "", "secret", "encrypt", "extra")
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
	r := winchWith(t, dir, "", identity, "", h, false, "", "plan", "site")
	if r.code != exitOK || !strings.Contains(r.out, "-pw=(secret)\n") || !strings.Contains(r.out, "+pw=(secret) (secret value changed)\n") {
		t.Errorf("plan: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	h.FailCommand("web1", "echo hunter2 | chpasswd")
	r = winchWith(t, dir, "", identity, "", h, false, "", "apply", "site", "--yes")
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
	if r.code != exitInvalid || !strings.Contains(r.err, "no age key: the home directory is not known; ") {
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
	r := winchWith(t, dir, "", identity, "", fakehost.New(), false, "", "secret", "rekey")
	if r.code != exitOK || r.out != "rekeyed 1 secret in 1 file\n  inventories/test.yaml\n" {
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
	r = winchWith(t, dir, "", identity, "", fakehost.New(), false, "", "secret", "rekey")
	if r.code != exitInvalid || !strings.Contains(r.err, "inventories/test.yaml:4:11: !secret: the identity in "+identity+" is not a recipient") {
		t.Errorf("rekey with an old identity: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Variables/Secrets (winch secret rekey, --inventory)
func TestSecretRekeyInventory(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2"))
	prod := filepath.Join(dir, "envs", "prod.yaml")
	if err := os.MkdirAll(filepath.Dir(prod), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prod, []byte("hosts:\n  web2:\n    vars:\n      pw: "+encrypt(t, dir, "prod-pw")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := winchWith(t, dir, "", identity, "", fakehost.New(), false, "", "secret", "rekey", "--inventory", "envs/prod.yaml")
	if want := "rekeyed 2 secrets in 2 files\n  envs/prod.yaml\n  inventories/test.yaml\n"; r.code != exitOK || r.out != want {
		t.Errorf("rekey: exit %d, stdout %q, stderr %q; want %q", r.code, r.out, r.err, want)
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
		{"the variable before the home directory", home, missing, exitInvalid, "no age key in " + missing + "\n"},
		{"missing relative path", "", "missing.key", exitInvalid, "no age key in " + filepath.Join(dir, "missing.key") + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := winchWith(t, dir, tt.home, tt.ageKey, "", fakehost.New(), false, "", "plan", "site")
			if r.code != tt.wantCode || !strings.Contains(r.err, tt.wantErr) {
				t.Errorf("exit %d, stderr %q; want exit %d and %q", r.code, r.err, tt.wantCode, tt.wantErr)
			}
		})
	}
}

// spec: Variables/Secrets (no key)
func TestMissingAgeKey(t *testing.T) {
	_, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2\n"))
	home := t.TempDir()
	text := winchWith(t, dir, home, "", "", fakehost.New(), false, "", "plan", "site")
	js := winchWith(t, dir, home, "", "", fakehost.New(), false, "", "plan", "site", "--json")
	got := strings.ReplaceAll("text:\n"+text.err+"json:\n"+js.out, home, "HOME")
	golden.Assert(t, filepath.Join("testdata", "errors", "missing-age-key.golden"), []byte(got))
}

// spec: Variables/Secrets (no key)
func TestUnknownHome(t *testing.T) {
	_, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2\n"))
	want := "no age key: the home directory is not known; set WINCH_AGE_KEY or WINCH_AGE_IDENTITY_CMD\n"
	for _, args := range [][]string{{"plan", "site"}, {"secret", "init"}, {"secret", "rekey"}} {
		r := winchWith(t, dir, "", "", "", fakehost.New(), false, "", args...)
		if r.code != exitInvalid || !strings.HasSuffix(r.err, want) {
			t.Errorf("%v: exit %d, stderr %q; want exit %d and %q", args, r.code, r.err, exitInvalid, want)
		}
	}
}

// spec: Variables/Secrets (WINCH_AGE_IDENTITY_CMD)
func TestAgeIdentityCmd(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2\n"))
	if err := os.WriteFile(filepath.Join(dir, "demo.key"), []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, _ := newIdentity(t)
	fail := "echo locked >&2; exit 3"
	tests := []struct {
		name, ageKey, ageCmd string
		args                 []string
		wantCode             int
		wantErr              string
	}{
		{"plan", "", "cat demo.key", []string{"plan", "site"}, exitOK, ""},
		{"rekey", "", "cat demo.key", []string{"secret", "rekey"}, exitOK, ""},
		{"a failing command", "", fail, []string{"plan", "site"}, exitInvalid, "read the age identity: " + fail + ": exit status 3: locked\n"},
		{"not a recipient", "", "cat " + other, []string{"plan", "site"}, exitInvalid, "!secret: the identity from cat " + other + " is not a recipient"},
		{"both variables", identity, "cat demo.key", []string{"plan", "site"}, exitInvalid, "WINCH_AGE_IDENTITY_CMD and WINCH_AGE_KEY are both set"},
		{"both variables in rekey", identity, "cat demo.key", []string{"secret", "rekey"}, exitInvalid, "WINCH_AGE_IDENTITY_CMD and WINCH_AGE_KEY are both set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := winchWith(t, dir, "", tt.ageKey, tt.ageCmd, fakehost.New(), false, "", tt.args...)
			if r.code != tt.wantCode || !strings.Contains(r.err, tt.wantErr) {
				t.Errorf("exit %d, stderr %q; want exit %d and %q", r.code, r.err, tt.wantCode, tt.wantErr)
			}
		})
	}
	t.Run("the command before the home directory", func(t *testing.T) {
		_, wrong := newIdentity(t)
		home := vmtest.WriteProject(t, map[string]string{".config/winch/age.key": wrong.String() + "\n"})
		r := winchWith(t, dir, home, "", "cat demo.key", fakehost.New(), false, "", "plan", "site")
		if r.code != exitOK {
			t.Errorf("exit %d, stderr %q", r.code, r.err)
		}
	})
	t.Run("no command without secrets", func(t *testing.T) {
		plain := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients:\n  - " + id.Recipient().String() + "\n",
			"inventories/test.yaml": "hosts:\n  web1:\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/a\n          content: a\n",
		})
		for _, args := range [][]string{{"plan", "site"}, {"secret", "rekey"}} {
			r := winchWith(t, plain, "", "", "touch ran", fakehost.New(), false, "", args...)
			if r.code != exitOK {
				t.Errorf("%v: exit %d, stderr %q", args, r.code, r.err)
			}
			if _, err := os.Stat(filepath.Join(plain, "ran")); err == nil {
				t.Errorf("%v: the command ran", args)
			}
			r = winchWith(t, plain, "", "missing.key", "touch ran", fakehost.New(), false, "", args...)
			if r.code != exitInvalid || !strings.Contains(r.err, "both set") {
				t.Errorf("%v with both variables: exit %d, stderr %q", args, r.code, r.err)
			}
		}
	})
}

// spec: Variables/Secrets (winch secret init)
func TestSecretInit(t *testing.T) {
	_, other := newIdentity(t)
	cfg := "name: acme # the project\nrecipients:\n  # Alice\n  - " + other.Recipient().String() + "\n\n# Variables.\nvars: {}\n"
	read := func(t *testing.T, path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mode := func(t *testing.T, path string) os.FileMode {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm()
	}

	t.Run("a new key", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": cfg})
		home := t.TempDir()
		key := filepath.Join(home, ".config", "winch", "age.key")
		r := winchWith(t, dir, home, "", "", fakehost.New(), false, "", "secret", "init")
		if r.code != exitOK {
			t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		ids, err := secret.Identity{Path: key}.Read(context.Background())
		if err != nil || len(ids) != 1 {
			t.Fatalf("read the new key: %v", err)
		}
		pub := ids[0].(*age.X25519Identity).Recipient().String()
		if got := mode(t, key); got != 0o600 {
			t.Errorf("key mode %o; want 600", got)
		}
		if got := mode(t, filepath.Dir(key)); got != 0o700 {
			t.Errorf("key directory mode %o; want 700", got)
		}
		want := "made the age key " + key + "\npublic key: " + pub + "\nadded the public key to recipients in winch.yaml\n"
		if !strings.HasPrefix(r.out, want) {
			t.Errorf("stdout %q; want the prefix %q", r.out, want)
		}
		wantCfg := strings.Replace(cfg, other.Recipient().String()+"\n", other.Recipient().String()+"\n  - "+pub+"\n", 1)
		if got := read(t, filepath.Join(dir, "winch.yaml")); got != wantCfg {
			t.Errorf("winch.yaml:\n%s\nwant:\n%s", got, wantCfg)
		}
		keyData := read(t, key)
		r = winchWith(t, dir, home, "", "", fakehost.New(), false, "", "secret", "init")
		if r.code != exitOK || r.out != "public key: "+pub+"\n" {
			t.Errorf("second run: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		if got := read(t, filepath.Join(dir, "winch.yaml")); got != wantCfg {
			t.Errorf("second run changed winch.yaml:\n%s", got)
		}
		if got := read(t, key); got != keyData {
			t.Errorf("second run changed the key")
		}
	})

	t.Run("an existing key", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": "name: acme\n"})
		path, id := newIdentity(t)
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		before := read(t, path)
		r := winchWith(t, dir, "", path, "", fakehost.New(), false, "", "secret", "init")
		if r.code != exitOK || !strings.HasPrefix(r.out, "public key: "+id.Recipient().String()+"\n") {
			t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		if got := read(t, path); got != before || mode(t, path) != 0o640 {
			t.Errorf("the key file changed")
		}
		want := "name: acme\nrecipients:\n  - " + id.Recipient().String() + "\n"
		if got := read(t, filepath.Join(dir, "winch.yaml")); got != want {
			t.Errorf("winch.yaml %q; want %q", got, want)
		}
	})

	t.Run("WINCH_AGE_IDENTITY_CMD", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": "name: acme\nvars: {}"})
		path, id := newIdentity(t)
		home := t.TempDir()
		r := winchWith(t, dir, home, "", "cat "+path, fakehost.New(), false, "", "secret", "init")
		if r.code != exitOK || r.out != "public key: "+id.Recipient().String()+"\nadded the public key to recipients in winch.yaml\na member who can read the secrets must now run winch secret rekey\n" {
			t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		want := "name: acme\nvars: {}\nrecipients:\n  - " + id.Recipient().String() + "\n"
		if got := read(t, filepath.Join(dir, "winch.yaml")); got != want {
			t.Errorf("winch.yaml %q; want %q", got, want)
		}
		if _, err := os.Stat(filepath.Join(home, ".config")); err == nil {
			t.Errorf("init made a key with WINCH_AGE_IDENTITY_CMD")
		}
	})

	t.Run("a post-quantum key", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": "name: acme\n"})
		id, err := age.GenerateHybridIdentity()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "pq.key")
		if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := winchWith(t, dir, "", path, "", fakehost.New(), false, "", "secret", "init")
		want := "name: acme\nrecipients:\n  - " + id.Recipient().String() + "\n"
		if got := read(t, filepath.Join(dir, "winch.yaml")); r.code != exitOK || got != want {
			t.Errorf("exit %d, stderr %q, winch.yaml %q", r.code, r.err, got)
		}
	})

	t.Run("a flow list", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": "name: acme\nrecipients: []\n"})
		r := winchWith(t, dir, t.TempDir(), "", "", fakehost.New(), false, "", "secret", "init")
		if r.code != exitInvalid || !strings.Contains(r.err, "cannot add the public key to recipients in winch.yaml; add it by hand") {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		if got := read(t, filepath.Join(dir, "winch.yaml")); got != "name: acme\nrecipients: []\n" {
			t.Errorf("winch.yaml changed: %q", got)
		}
	})
}

// spec: Variables/Secrets (winch secret generate); CLI
func TestSecretGenerate(t *testing.T) {
	_, id := newIdentity(t)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients:\n  - " + id.Recipient().String() + "\nvars:\n  pw:\n",
		"inventories/test.yaml": "hosts:\n  web1:\n",
	})
	path := filepath.Join(dir, "inventories", "test.yaml")
	password := regexp.MustCompile(`^[A-Za-z0-9]{32}$`)
	values := func(t *testing.T) []string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, m := range regexp.MustCompile(`!secret (\S+)`).FindAllStringSubmatch(string(data), -1) {
			plain, err := secret.Decrypt(m[1], []age.Identity{id})
			if err != nil {
				t.Fatal(err)
			}
			if !password.MatchString(plain) {
				t.Errorf("password %q; want 32 letters and digits", plain)
			}
			out = append(out, plain)
		}
		return out
	}

	r := winch(t, dir, fakehost.New(), false, "", "secret", "generate", "vars.pw")
	if r.code != exitOK || r.out != "wrote vars.pw into the vars of the group all in inventories/test.yaml\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	all := values(t)
	if len(all) != 1 {
		t.Fatalf("%d secrets; want 1", len(all))
	}
	if strings.Contains(r.out+r.err, all[0]) {
		t.Errorf("the output shows the password")
	}

	r = winch(t, dir, fakehost.New(), false, "", "secret", "generate", "vars.pw")
	if r.code != exitInvalid || !strings.Contains(r.err, `variable "pw" is already in the vars of the group all in inventories/test.yaml`) {
		t.Errorf("second run: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}

	r = winch(t, dir, fakehost.New(), false, "", "secret", "generate", "vars.pw", "--host", "web1")
	if r.code != exitOK || r.out != "wrote vars.pw into the vars of host \"web1\" in inventories/test.yaml\n" {
		t.Fatalf("--host: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "hosts:\n  web1:\n    vars:\n      pw: !secret ") {
		t.Errorf("--host: inventory:\n%s", data)
	}
	if got := values(t); len(got) != 2 || got[0] == got[1] {
		t.Errorf("passwords %q; want two different ones", got)
	}

	r = winch(t, dir, fakehost.New(), false, "", "secret", "generate", "vars.pw", "--host", "")
	if r.code != exitInvalid || !strings.Contains(r.err, "winch secret generate: invalid value \"\" for flag -host: must not be empty") {
		t.Errorf("--host \"\": exit %d, stderr %q", r.code, r.err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "validate", "--host", "web1")
	if r.code != exitInvalid || !strings.Contains(r.err, "flag provided but not defined: -host") {
		t.Errorf("validate --host: exit %d, stderr %q", r.code, r.err)
	}

	for _, args := range [][]string{{}, {"pw"}, {"vars.pw", "vars.x"}, {"vars."}} {
		r = winch(t, dir, fakehost.New(), false, "", append([]string{"secret", "generate"}, args...)...)
		if r.code != exitInvalid || !strings.Contains(r.err, "winch: secret generate needs one variable: vars.<name>") {
			t.Errorf("args %q: exit %d, stderr %q", args, r.code, r.err)
		}
	}
}
