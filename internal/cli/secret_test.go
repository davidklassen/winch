package cli

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

func fakeSecret(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "secret", "testdata", "fake_secrets", name))
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
		"winch.yaml":            "name: acme\ninventory: test\nrecipients:\n  - " + id.Recipient().String() + "\n",
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
	if r.code != exitInvalid || !strings.Contains(r.err, `winch secret: unknown command "nope"`) {
		t.Errorf("unknown command: exit %d, stderr %q", r.code, r.err)
	}
	r = winchWith(t, dir, "", identity, "", fakehost.New(), false, "x", "secret", "encrypt", "vars.pw", "vars.x")
	if r.code != exitInvalid || !strings.Contains(r.err, "winch secret encrypt: takes one path at most") {
		t.Errorf("two paths: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Variables/Secrets (winch secret encrypt); CLI/Prompts
func TestSecretEncryptPrompt(t *testing.T) {
	_, id := newIdentity(t)
	dir := secretProject(t, id)
	path := filepath.Join(dir, "inventories", "test.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := winch(t, dir, fakehost.New(), true, "hunter2\nhunter3\n", "secret", "encrypt", "inventories.test.hosts.web1.vars.pw")
	if r.code != exitInvalid || r.out != "" || r.err != "Secret for inventories.test.hosts.web1.vars.pw: \nConfirm secret: \nwinch secret encrypt: the two values differ\n" {
		t.Errorf("different values: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("a failed encrypt changed the inventory:\n%s", after)
	}
	r = winch(t, dir, fakehost.New(), true, "\n\n", "secret", "encrypt")
	if r.code != exitInvalid || !strings.Contains(r.err, "the value is empty") {
		t.Errorf("empty value: exit %d, stderr %q", r.code, r.err)
	}
	r = winch(t, dir, fakehost.New(), true, "hunter2\r\nhunter2\r\n", "secret", "encrypt")
	if r.code != exitOK || r.err != "Secret: \nConfirm secret: \n" {
		t.Fatalf("equal values: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	got, err := secret.Decrypt(strings.TrimPrefix(strings.TrimSuffix(r.out, "\n"), "!secret "), []age.Identity{id})
	if err != nil || got != "hunter2" {
		t.Errorf("secret = %q, %v; want hunter2", got, err)
	}
	r = winch(t, dir, fakehost.New(), false, "hunter2\n", "secret", "encrypt")
	if r.code != exitOK || r.err != "" {
		t.Errorf("pipe: exit %d, stderr %q; want no prompt", r.code, r.err)
	}
}

// spec: Variables/Secrets (winch secret encrypt); CLI/Prompts
func TestSecretEncryptNoEcho(t *testing.T) {
	_, id := newIdentity(t)
	controller, terminal := vmtest.OpenPTY(t)
	p := startPrompt(t, secretProject(t, id), terminal)
	for range 2 {
		p.waitPrompt(t)
		if _, err := controller.WriteString("hunter2\n"); err != nil {
			t.Fatal(err)
		}
	}
	if c := p.exit(t); c != exitOK || !strings.HasPrefix(p.out.String(), "!secret ") {
		t.Fatalf("exit %d, stdout %q, stderr %q", c, p.out.String(), p.errOut.String())
	}
	// After the prompts, the terminal echoes again.
	if echo := readEcho(t, controller); strings.Contains(echo, "hunter2") {
		t.Errorf("the terminal echoed the value: %q", echo)
	}
}

// spec: Variables/Secrets (winch secret encrypt); CLI/Prompts
func TestSecretEncryptInterrupt(t *testing.T) {
	_, id := newIdentity(t)
	dir := secretProject(t, id)
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			controller, terminal := vmtest.OpenPTY(t)
			p := startPrompt(t, dir, terminal)
			p.waitPrompt(t)
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			if c := p.exit(t); c != exitInvalid || p.out.String() != "" || !strings.HasSuffix(p.errOut.String(), "winch secret encrypt: interrupted; nothing was written\n") {
				t.Fatalf("exit %d, stdout %q, stderr %q", c, p.out.String(), p.errOut.String())
			}
			readEcho(t, controller)
		})
	}
}

// spec: Variables/Secrets (winch secret encrypt); CLI/Prompts
func TestSecretEncryptTerminalWithoutStderr(t *testing.T) {
	_, id := newIdentity(t)
	_, terminal := vmtest.OpenPTY(t)
	var out, errOut strings.Builder
	code := Main(context.Background(), []string{"secret", "encrypt"}, Env{
		Dir: secretProject(t, id), In: terminal, Out: &out, Err: &errOut, Filter: secret.NewFilter(),
	})
	want := "winch secret encrypt: stdin is a terminal, but stderr is not, so winch cannot ask for the secret; pipe the value, or run with stderr on the terminal\n"
	if code != exitInvalid || out.String() != "" || errOut.String() != want {
		t.Errorf("exit %d, stdout %q, stderr %q; want %q", code, out.String(), errOut.String(), want)
	}
}

// prompt is a run of winch secret encrypt on a terminal.
type prompt struct {
	out    strings.Builder
	errOut *promptWriter
	code   chan int
}

func startPrompt(t *testing.T, dir string, terminal *os.File) *prompt {
	t.Helper()
	p := &prompt{errOut: &promptWriter{prompt: make(chan struct{}, 2)}, code: make(chan int, 1)}
	go func() {
		p.code <- Main(context.Background(), []string{"secret", "encrypt"}, Env{
			Dir: dir, In: terminal, Out: &p.out, Err: p.errOut, Terminal: true, Filter: secret.NewFilter(),
		})
	}()
	return p
}

func (p *prompt) waitPrompt(t *testing.T) {
	t.Helper()
	select {
	case <-p.errOut.prompt:
	case c := <-p.code:
		t.Fatalf("exit %d before the prompt, stderr %q", c, p.errOut.String())
	case <-time.After(10 * time.Second):
		t.Fatalf("no prompt, stderr %q", p.errOut.String())
	}
}

func (p *prompt) exit(t *testing.T) int {
	t.Helper()
	select {
	case c := <-p.code:
		return c
	case <-time.After(10 * time.Second):
		t.Fatalf("winch does not end, stderr %q", p.errOut.String())
		return 0
	}
}

// readEcho writes the line end to the terminal and returns what the terminal
// echoed up to the echo of end.
func readEcho(t *testing.T, controller *os.File) string {
	t.Helper()
	if _, err := controller.WriteString("end\n"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	var echo []byte
	go func() {
		buf := make([]byte, 64)
		for !strings.Contains(string(echo), "end\r\n") {
			n, err := controller.Read(buf)
			if err != nil {
				done <- err
				return
			}
			echo = append(echo, buf[:n]...)
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the terminal does not echo")
	}
	return string(echo)
}

// promptWriter sends on prompt each time winch asks for the value.
type promptWriter struct {
	mu     sync.Mutex
	b      strings.Builder
	prompt chan struct{}
}

func (w *promptWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b.Write(p)
	if strings.HasSuffix(string(p), ": ") {
		w.prompt <- struct{}{}
	}
	return len(p), nil
}

func (w *promptWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// spec: Variables/Secrets (winch secret encrypt, paths); CLI
func TestSecretEncryptPath(t *testing.T) {
	_, id := newIdentity(t)
	dir := secretProject(t, id)
	path := filepath.Join(dir, "inventories", "test.yaml")
	r := winch(t, dir, fakehost.New(), false, "hunter2\n", "secret", "encrypt", "inventories.test.hosts.web1.vars.pw")
	if r.code != exitOK || r.out != "replaced inventories.test.hosts.web1.vars.pw in inventories/test.yaml\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`^hosts:\n  web1:\n    vars:\n      pw: !secret (\S+)\n$`).FindStringSubmatch(string(data))
	if m == nil {
		t.Fatalf("inventory:\n%s", data)
	}
	if got, err := secret.Decrypt(m[1], []age.Identity{id}); err != nil || got != "hunter2" {
		t.Errorf("secret = %q, %v; want hunter2", got, err)
	}
	r = winch(t, dir, fakehost.New(), false, "x", "secret", "encrypt", "inventories.test.hosts.web9.vars.pw")
	if r.code != exitInvalid || r.out != "" || !strings.Contains(r.err, "host web9 is not in inventories/test.yaml") {
		t.Errorf("unknown host: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "secret", "encrypt", "inventories.test.hosts.web1.vars.pw")
	if r.code != exitInvalid || !strings.Contains(r.err, "the value is empty") {
		t.Errorf("empty value: exit %d, stderr %q", r.code, r.err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(data) {
		t.Errorf("a failed encrypt changed the inventory:\n%s", after)
	}
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecretPlan(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2\n"))
	h := fakehost.New()
	h.SetFile("web1", "/etc/pw", "pw=old-password\n")
	h.SetMasked("web1", "/etc/pw", "pw=(secret)\n")
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
	if r.code != exitInvalid || !strings.Contains(r.err, "inventories/test.yaml:4:11: the age key "+identity+" is not in recipients; ") {
		t.Errorf("rekey with an old identity: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Variables/Secrets (winch secret rekey)
func TestSecretRekeyInventory(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2"))
	prod := filepath.Join(dir, "inventories", "prod.yaml")
	if err := os.WriteFile(prod, []byte("hosts:\n  web2:\n    vars:\n      pw: "+encrypt(t, dir, "prod-pw")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := winchWith(t, dir, "", identity, "", fakehost.New(), false, "", "secret", "rekey")
	if want := "rekeyed 2 secrets in 2 files\n  inventories/prod.yaml\n  inventories/test.yaml\n"; r.code != exitOK || r.out != want {
		t.Errorf("rekey: exit %d, stdout %q, stderr %q; want %q", r.code, r.out, r.err, want)
	}
}

// spec: Variables/Secrets (winch secret rekey)
func TestSecretRekeyWriteError(t *testing.T) {
	for _, tc := range []struct {
		readOnly, out, err string
	}{
		{"recipes/r", "rewrote 1 of 2 files:\n  inventories/test.yaml\n", "write recipes/r/recipe.yaml: "},
		{"inventories", "", "write inventories/test.yaml: "},
	} {
		t.Run(tc.readOnly, func(t *testing.T) {
			identity, id := newIdentity(t)
			dir := secretProject(t, id)
			setPassword(t, dir, encrypt(t, dir, "hunter2"))
			recipe := filepath.Join(dir, "recipes", "r")
			if err := os.MkdirAll(recipe, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(recipe, "recipe.yaml"), []byte("vars:\n  key: "+encrypt(t, dir, "r-key")+"\nsteps: []\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			readOnly := filepath.Join(dir, tc.readOnly)
			if err := os.Chmod(readOnly, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(readOnly, 0o755); err != nil {
					t.Error(err)
				}
			})
			r := winchWith(t, dir, "", identity, "", fakehost.New(), false, "", "secret", "rekey")
			if r.code != exitInvalid || r.out != tc.out || !strings.Contains(r.err, tc.err) || !strings.Contains(r.err, "permission denied") {
				t.Errorf("rekey: exit %d, stdout %q, stderr %q; want stdout %q and stderr with %q", r.code, r.out, r.err, tc.out, tc.err)
			}
		})
	}
}

// spec: Variables/Secrets in output (the load warning)
func TestLoadWarning(t *testing.T) {
	token := fakeSecret(t, "ghp.txt")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
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

// spec: Variables/Secrets/Secrets in output; CLI/Output
func TestKeyInDiff(t *testing.T) {
	oldKey, newKey := fakeSecret(t, "rsa.txt"), fakeSecret(t, "pkcs8.txt")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/app.key\n          mode: \"0600\"\n          content: |\n            " + strings.ReplaceAll(newKey, "\n", "\n            ") + "\n",
	})
	h := fakehost.New()
	h.SetFile("web1", "/etc/app.key", oldKey+"\n")
	o, n := strings.Split(oldKey, "\n"), strings.Split(newKey, "\n")
	bodies := []string{o[1], n[1], n[2]}
	for _, tt := range []struct {
		args           []string
		added, removed string
	}{
		{[]string{"plan", "site"}, "+(secret)", "-(secret)"},
		{[]string{"plan", "site", "--json"}, `"+(secret)"`, `"-(secret)"`},
	} {
		args := tt.args
		r := winch(t, dir, h, false, "", args...)
		if r.code != exitOK {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", args, r.code, r.out, r.err)
		}
		for _, b := range bodies {
			if strings.Contains(r.out+r.err, b[:16]) {
				t.Errorf("%v: the output shows the key body %q:\n%s", args, b[:16], r.out)
			}
		}
		if strings.Count(r.out, tt.added) != 4 || strings.Count(r.out, tt.removed) != 3 {
			t.Errorf("%v: want 4 lines %s and 3 lines %s:\n%s", args, tt.added, tt.removed, r.out)
		}
		for line := range strings.Lines(r.out) {
			if l := strings.TrimSpace(line); strings.HasPrefix(l, secret.Mark) {
				t.Errorf("%v: a key line lost its sign: %q", args, line)
			}
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
		{"the variable before the home directory", home, missing, exitInvalid, "no age key at " + missing + "\n"},
		{"missing relative path", "", "missing.key", exitInvalid, "no age key at " + filepath.Join(dir, "missing.key") + "\n"},
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

// spec: Variables/Secrets (age key, winch secret init)
func TestAgeKeyDanglingLink(t *testing.T) {
	_, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2\n"))
	tmp := t.TempDir()
	link, target := filepath.Join(tmp, "age.key"), filepath.Join(tmp, "volume", "age.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	msg := "the age key " + link + " links to " + target + ", which does not exist\n"
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"plan", "site"}, msg},
		{[]string{"secret", "init"}, "winch secret init: " + msg},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			r := winchWith(t, dir, "", link, "", fakehost.New(), false, "", tt.args...)
			if r.code != exitInvalid || r.err != tt.want {
				t.Errorf("exit %d, stderr %q; want %q", r.code, r.err, tt.want)
			}
			if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("winch made the target: %v", err)
			}
		})
	}
}

// spec: Variables/Secrets (age key, winch secret init)
func TestAgeKeyDanglingDirLink(t *testing.T) {
	_, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2\n"))
	tmp := t.TempDir()
	link, target := filepath.Join(tmp, "winch"), filepath.Join(tmp, "volume", "winch")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(link, "age.key")
	msg := "the age key " + key + " is in " + link + ", which links to " + target + ", which does not exist\n"
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"plan", "site"}, msg},
		{[]string{"secret", "init"}, "winch secret init: " + msg},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			r := winchWith(t, dir, "", key, "", fakehost.New(), false, "", tt.args...)
			if r.code != exitInvalid || r.err != tt.want {
				t.Errorf("exit %d, stderr %q; want %q", r.code, r.err, tt.want)
			}
			if _, err := os.Lstat(filepath.Dir(target)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("winch made the target: %v", err)
			}
		})
	}
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
		{"a failing command", "", fail, []string{"plan", "site"}, exitInvalid, "WINCH_AGE_IDENTITY_CMD exited with status 3: " + fail + ": locked\n"},
		{"not a recipient", "", "cat " + other, []string{"plan", "site"}, exitInvalid, "inventories/test.yaml:4:11: the age key from WINCH_AGE_IDENTITY_CMD is not in recipients; "},
		{"both variables", identity, "cat demo.key", []string{"plan", "site"}, exitInvalid, "WINCH_AGE_IDENTITY_CMD and WINCH_AGE_KEY are both set; unset one of the two"},
		{"both variables in rekey", identity, "cat demo.key", []string{"secret", "rekey"}, exitInvalid, "WINCH_AGE_IDENTITY_CMD and WINCH_AGE_KEY are both set; unset one of the two"},
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
			"winch.yaml":            "name: acme\ninventory: test\nrecipients:\n  - " + id.Recipient().String() + "\n",
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
		if r.out != want {
			t.Errorf("stdout %q; want %q", r.out, want)
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
		if r.code != exitOK || r.out != "public key: "+id.Recipient().String()+"\nadded the public key to recipients in winch.yaml\n" {
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

	plain := map[string]string{
		"winch.yaml":            "name: acme\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: x\n",
		"recipes/r/recipe.yaml": "steps:\n  - file:\n      path: /a\n      content: !expr '\"x\"'\n",
	}
	for _, c := range []struct{ name, file, text, hint string }{
		{"no secret", "", "", ""},
		{"a secret in winch.yaml", "winch.yaml", "name: acme\nvars:\n  pw: !secret YWdl\n", "a member who can read the secrets must run winch secret rekey\n"},
		{"a secret in an inventory", "inventories/test.yaml", "hosts:\n  web1:\n    vars:\n      pw: !secret YWdl\n", "a member who can read the secrets must run winch secret rekey\n"},
		{"a secret in a recipe", "recipes/r/recipe.yaml", "vars:\n  pw: !secret YWdl\nsteps:\n  - file:\n      path: /a\n      content: x\n", "a member who can read the secrets must run winch secret rekey\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := maps.Clone(plain)
			if c.file != "" {
				files[c.file] = c.text
			}
			dir := vmtest.WriteProject(t, files)
			path, id := newIdentity(t)
			r := winchWith(t, dir, "", path, "", fakehost.New(), false, "", "secret", "init")
			want := "public key: " + id.Recipient().String() + "\nadded the public key to recipients in winch.yaml\n" + c.hint
			if r.code != exitOK || r.out != want {
				t.Errorf("exit %d, stdout %q, stderr %q; want stdout %q", r.code, r.out, r.err, want)
			}
		})
	}

	t.Run("a broken recipe", func(t *testing.T) {
		files := maps.Clone(plain)
		files["recipes/r/recipe.yaml"] = "steps: [\n"
		dir := vmtest.WriteProject(t, files)
		path, _ := newIdentity(t)
		r := winchWith(t, dir, "", path, "", fakehost.New(), false, "", "secret", "init")
		if r.code != exitInvalid || strings.Contains(r.out, "added") || !strings.Contains(r.err, "recipes/r/recipe.yaml") {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		if got := read(t, filepath.Join(dir, "winch.yaml")); got != "name: acme\n" {
			t.Errorf("winch.yaml changed: %q", got)
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
		home := t.TempDir()
		r := winchWith(t, dir, home, "", "", fakehost.New(), false, "", "secret", "init")
		key := filepath.Join(home, ".config", "winch", "age.key")
		if r.code != exitInvalid || !strings.HasPrefix(r.out, "made the age key "+key+"\npublic key: age1") || r.err != "cannot add the public key to recipients in winch.yaml; add it by hand\n" {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		if got := read(t, filepath.Join(dir, "winch.yaml")); got != "name: acme\nrecipients: []\n" {
			t.Errorf("winch.yaml changed: %q", got)
		}
		if _, err := os.Stat(key); err != nil {
			t.Errorf("init made no key: %v", err)
		}
	})

	t.Run("the key cannot be written", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": "name: acme\n"})
		home := t.TempDir()
		keyDir := filepath.Join(home, ".config", "winch")
		if err := os.MkdirAll(keyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keyDir, 0o500); err != nil {
			t.Fatal(err)
		}
		r := winchWith(t, dir, home, "", "", fakehost.New(), false, "", "secret", "init")
		if r.code != exitInvalid || r.out != "" || !strings.Contains(r.err, "make the age key") {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		if got := read(t, filepath.Join(dir, "winch.yaml")); got != "name: acme\n" {
			t.Errorf("winch.yaml changed: %q", got)
		}
	})

	t.Run("the key directory cannot be made", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": "name: acme\n"})
		home := t.TempDir()
		if err := os.Chmod(home, 0o500); err != nil {
			t.Fatal(err)
		}
		r := winchWith(t, dir, home, "", "", fakehost.New(), false, "", "secret", "init")
		if r.code != exitInvalid || r.out != "" || !strings.Contains(r.err, "make the age key") {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
	})

	t.Run("no project", func(t *testing.T) {
		home := t.TempDir()
		r := winchWith(t, t.TempDir(), home, "", "", fakehost.New(), false, "", "secret", "init")
		if r.code != exitInvalid || r.out != "" || !strings.Contains(r.err, "run winch in the project directory") {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		if _, err := os.Stat(filepath.Join(home, ".config")); err == nil {
			t.Errorf("init made a key")
		}
	})
}

// spec: Variables/Secrets (winch secret generate, paths); CLI
func TestSecretGenerate(t *testing.T) {
	_, id := newIdentity(t)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients:\n  - " + id.Recipient().String() + "\n",
		"inventories/test.yaml": "hosts:\n  web1:\n",
		"pipelines/site.yaml":   secretPipeline,
	})
	path := filepath.Join(dir, "inventories", "test.yaml")
	password := regexp.MustCompile(`^[A-Za-z0-9]{32}$`)
	decrypt := func(t *testing.T, text string) string {
		t.Helper()
		plain, err := secret.Decrypt(text, []age.Identity{id})
		if err != nil {
			t.Fatal(err)
		}
		if !password.MatchString(plain) {
			t.Errorf("password %q; want 32 letters and digits", plain)
		}
		return plain
	}
	values := func(t *testing.T) []string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, m := range regexp.MustCompile(`!secret (\S+)`).FindAllStringSubmatch(string(data), -1) {
			out = append(out, decrypt(t, m[1]))
		}
		return out
	}

	r := winch(t, dir, fakehost.New(), false, "", "secret", "generate", "inventories.test.groups.all.vars.pw")
	if r.code != exitOK || r.out != "added inventories.test.groups.all.vars.pw in inventories/test.yaml\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	first := values(t)
	if len(first) != 1 {
		t.Fatalf("%d secrets; want 1", len(first))
	}
	if strings.Contains(r.out+r.err, first[0]) {
		t.Errorf("the output shows the password")
	}

	r = winch(t, dir, fakehost.New(), false, "", "secret", "generate", "inventories.test.groups.all.vars.pw")
	if r.code != exitOK || r.out != "replaced inventories.test.groups.all.vars.pw in inventories/test.yaml\n" {
		t.Fatalf("second run: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	if second := values(t); len(second) != 1 || second[0] == first[0] {
		t.Errorf("passwords %q after %q; want one new password", second, first)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "secret", "generate")
	if r.code != exitOK || !strings.HasPrefix(r.out, "!secret ") || strings.Count(r.out, "\n") != 1 || !strings.HasSuffix(r.out, "\n") {
		t.Fatalf("no path: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	decrypt(t, strings.TrimSuffix(strings.TrimPrefix(r.out, "!secret "), "\n"))
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("no path: the inventory changed:\n%s", after)
	}

	for _, flag := range []string{"--host", "--inventory"} {
		r = winch(t, dir, fakehost.New(), false, "", "secret", "generate", "vars.pw", flag, "web1")
		if want := "winch secret generate: unknown flag " + flag; r.code != exitInvalid || !strings.Contains(r.err, want) {
			t.Errorf("%s: exit %d, stderr %q; want %q", flag, r.code, r.err, want)
		}
		r = winch(t, dir, fakehost.New(), false, "x", "secret", "encrypt", "vars.pw", flag, "web1")
		if want := "winch secret encrypt: unknown flag " + flag; r.code != exitInvalid || !strings.Contains(r.err, want) {
			t.Errorf("encrypt %s: exit %d, stderr %q; want %q", flag, r.code, r.err, want)
		}
	}
	r = winch(t, dir, fakehost.New(), false, "", "secret", "generate", "vars.pw", "vars.x")
	if r.code != exitInvalid || !strings.Contains(r.err, "winch secret generate: takes one path at most") {
		t.Errorf("two paths: exit %d, stderr %q", r.code, r.err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "secret", "generate", "pw")
	if r.code != exitInvalid || !strings.Contains(r.err, `winch secret generate: "pw" is not a path to a variable value`) {
		t.Errorf("bad path: exit %d, stderr %q", r.code, r.err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("a failed generate changed the inventory:\n%s", after)
	}
}

// spec: Variables/Secrets in output (text filter)
func TestSecretBase64Output(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "first-line\nsecond-line\n"))
	// The base64 of the exact value, with its last newline.
	command := "echo Zmlyc3QtbGluZQpzZWNvbmQtbGluZQo= | base64 -d"
	pipeline := `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/pw
          content: !tpl "{{ .vars.pw }}"
          mode: "0600"
        then: "` + command + `"
`
	if err := os.WriteFile(filepath.Join(dir, "pipelines/site.yaml"), []byte(pipeline), 0o644); err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	h.FailCommand("web1", command)
	for _, args := range [][]string{{"apply", "site", "--yes"}, {"apply", "site", "--yes", "--json"}} {
		h.SetFile("web1", "/etc/pw", "old\n")
		r := winchWith(t, dir, "", identity, "", h, false, "", args...)
		if r.code != exitFailed || !strings.Contains(r.out+r.err, "then: echo (secret)= | base64 -d: exit status 1") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, r.code, r.out, r.err)
		}
		if strings.Contains(r.out+r.err, "Zmlyc3Qt") {
			t.Errorf("%v: the output shows the base64 of the secret:\n%s%s", args, r.out, r.err)
		}
	}
}

// spec: Variables/Secrets; CLI/Messages
func TestAgeKeyCannotRead(t *testing.T) {
	_, aliceID := newIdentity(t)
	bob, _ := newIdentity(t)
	carol, _ := newIdentity(t)
	dir := secretProject(t, aliceID)
	pw, token := encrypt(t, dir, "hunter2"), encrypt(t, dir, "token-1")
	if err := os.WriteFile(filepath.Join(dir, "inventories/test.yaml"), []byte("hosts:\n  web1:\n    vars:\n      pw: "+pw+"\n      token: "+token+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pipelines/site.yaml"), []byte(secretPipeline+"      - file:\n          path: /etc/token\n          content: !expr vars.token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := winchWith(t, dir, "", bob, "", fakehost.New(), false, "", "secret", "init"); r.code != exitOK {
		t.Fatalf("secret init: exit %d, stderr %q", r.code, r.err)
	}
	notYet := "inventories/test.yaml:4:11: the secrets are not encrypted for the age key " + bob + " yet; a member who can read them must run winch secret rekey\n"
	notIn := "inventories/test.yaml:4:11: the age key " + carol + " is not in recipients; set WINCH_AGE_KEY to an age key in recipients, or run winch secret init and ask a member to run winch secret rekey\n"
	why := "winch exec needs the age key to hide the secrets of the project in its output\n"
	tests := []struct {
		name, key string
		args      []string
		want      string
	}{
		{"plan, in recipients", bob, []string{"plan", "site"}, notYet},
		{"rekey, in recipients", bob, []string{"secret", "rekey"}, notYet},
		{"exec, in recipients", bob, []string{"exec", "all", "--", "uptime"}, notYet + why},
		{"plan, not in recipients", carol, []string{"plan", "site"}, notIn},
		{"rekey, not in recipients", carol, []string{"secret", "rekey"}, notIn},
		{"exec, not in recipients", carol, []string{"exec", "all", "--", "uptime"}, notIn + why},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := winchWith(t, dir, "", tt.key, "", fakehost.New(), false, "", tt.args...)
			if r.code != exitInvalid || r.err != tt.want {
				t.Errorf("exit %d, stderr %q; want %q", r.code, r.err, tt.want)
			}
		})
	}
	t.Run("a command not in recipients", func(t *testing.T) {
		r := winchWith(t, dir, "", "", "cat "+carol, fakehost.New(), false, "", "plan", "site")
		want := "inventories/test.yaml:4:11: the age key from WINCH_AGE_IDENTITY_CMD is not in recipients; set WINCH_AGE_IDENTITY_CMD to a command that prints an age key in recipients, or run winch secret init and ask a member to run winch secret rekey\n"
		if r.code != exitInvalid || r.err != want {
			t.Errorf("exit %d, stderr %q; want %q", r.code, r.err, want)
		}
	})
	t.Run("exec without an age key", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "age.key")
		r := winchWith(t, dir, "", missing, "", fakehost.New(), false, "", "exec", "all", "--", "uptime")
		if r.code != exitInvalid || !strings.HasPrefix(r.err, "no age key at "+missing+"\n") || !strings.HasSuffix(r.err, why) {
			t.Errorf("exit %d, stderr %q", r.code, r.err)
		}
	})
}

// spec: Variables/Secrets; CLI/Messages (the real project file)
func TestSecretMessagesNameWinchYml(t *testing.T) {
	_, id := newIdentity(t)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yml":             "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1:\n",
		"pipelines/site.yaml":   secretPipeline,
	})
	r := winch(t, dir, fakehost.New(), false, "x", "secret", "encrypt")
	if want := "winch.yml has no recipients; run winch secret init\n"; r.code != exitInvalid || r.err != want {
		t.Errorf("encrypt: exit %d, stderr %q; want %q", r.code, r.err, want)
	}
	home := t.TempDir()
	r = winchWith(t, dir, home, "", "", fakehost.New(), false, "", "secret", "init")
	if r.code != exitOK || !strings.Contains(r.out, "added the public key to recipients in winch.yml\n") {
		t.Errorf("init: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	pw := encrypt(t, dir, "hunter2")
	if err := os.WriteFile(filepath.Join(dir, "inventories/test.yaml"), []byte("hosts:\n  web1:\n    vars:\n      pw: "+pw+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "winch.yml")
	if err := os.WriteFile(cfg, []byte(readFile(t, cfg)+"  - "+id.Recipient().String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "validate")
	want := "inventories/test.yaml:4:11: warning: this secret is encrypted for 1 public key; winch.yml lists 2; a member who can read it must run winch secret rekey\n"
	if r.code != exitOK || !strings.HasSuffix(r.err, want) {
		t.Errorf("validate: exit %d, stderr %q; want %q", r.code, r.err, want)
	}
}

// spec: Variables/Secrets in output (the load warning)
func TestLoadWarningFix(t *testing.T) {
	token := fakeSecret(t, "ghp.txt")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":                   "name: acme\nvars:\n  app_token: " + token + "\n  app_note: |\n    x\n    " + token + "\ninventory: test\n",
		"inventories/test.yaml":        "hosts:\n  web1:\n",
		"pipelines/site.yaml":          "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/token\n          content: " + token + "\n      - recipe: app\n",
		"recipes/app/recipe.yaml":      "steps:\n  - file:\n      path: /etc/a\n      template: a.tmpl\n  - file:\n      path: /etc/b\n      source: b.txt\n",
		"recipes/app/templates/a.tmpl": "token=" + token + "\n",
		"recipes/app/files/b.txt":      "token=" + token + "\n",
	})
	r := winch(t, dir, fakehost.New(), false, "", "validate")
	want := "pipelines/site.yaml:7:20: warning: this looks like a GitHub token; put it in a variable with !secret, and read the variable here\n" +
		"recipes/app/files/b.txt:1:7: warning: this looks like a GitHub token; put it in a variable with !secret, move the file to templates/, and use template in place of source to read it with .vars\n" +
		"recipes/app/templates/a.tmpl:1:7: warning: this looks like a GitHub token; put it in a variable with !secret, and read it with .vars\n" +
		"winch.yaml:3:14: warning: this looks like a GitHub token; use !secret\n" +
		"winch.yaml:6:5: warning: this looks like a GitHub token; use !secret\n"
	if r.code != exitOK || r.err != want {
		t.Errorf("validate: exit %d, stderr %q; want %q", r.code, r.err, want)
	}
}

// spec: Variables/Secrets (winch secret decrypt); CLI
func TestSecretDecrypt(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	pw := encrypt(t, dir, "hunter2")
	token := fakeSecret(t, "ghp.txt")
	setPassword(t, dir, pw)
	cfg := "name: acme\ninventory: test\nrecipients:\n  - " + id.Recipient().String() + "\n" +
		"vars:\n  token: " + encrypt(t, dir, token) + "\n  lines: " + encrypt(t, dir, "a\nb\n") +
		"\n  plain: hello\n  list:\n    - " + pw + "\n  users:\n    alice: " + pw + "\n"
	if err := os.WriteFile(filepath.Join(dir, "winch.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, stdin, path, want string }{
		{"inventory path", "", "inventories.test.hosts.web1.vars.pw", "hunter2"},
		{"map key", "", "vars.users.alice", "hunter2"},
		{"a token", "", "vars.token", token},
		{"more lines", "", "vars.lines", "a\nb\n"},
		{"stdin with the tag", pw + "\n", "", "hunter2"},
		{"stdin without the tag", strings.TrimPrefix(pw, "!secret "), "", "hunter2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"secret", "decrypt"}
			if tt.path != "" {
				args = append(args, tt.path)
			}
			r := winchWith(t, dir, "", identity, "", fakehost.New(), false, tt.stdin, args...)
			if r.code != exitOK || r.out != tt.want || r.err != "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want %q", r.code, r.out, r.err, tt.want)
			}
		})
	}
	for _, tt := range []struct{ name, stdin, path, want string }{
		{"a map", "", "vars.users", "vars.users in winch.yaml is a map, not a !secret; name a key in it"},
		{"a plain value", "", "vars.plain", "vars.plain in winch.yaml is not a !secret"},
		{"a missing key", "", "vars.users.alicee", `vars.users.alicee is not in winch.yaml; did you mean "alice"?`},
		{"a missing variable", "", "vars.nope", "vars.nope is not in winch.yaml"},
		{"a missing host", "", "inventories.test.hosts.web9.vars.pw", "host web9 is not in inventories/test.yaml"},
		{"a bad path", "", "pw", `winch secret decrypt: "pw" is not a path to a variable value`},
		{"a missing key with dots", "", `vars.users["alice.b"]`, `vars.users["alice.b"] is not in winch.yaml; did you mean "alice"?`},
		{"a bracket without its end", "", `vars.users["alice`, `winch secret decrypt: "vars.users[\"alice" is not a path to a variable value; put a key with dots in brackets`},
		{"empty stdin", "\n", "", "winch secret decrypt: stdin holds no !secret value"},
		{"two paths", "", "vars.pw vars.x", "winch secret decrypt: takes one path at most"},
		{"a list item", "", "vars.list.0", "cannot read vars.list.0: vars.list is a list; a path cannot name a list item"},
		{"below a plain value", "", "vars.plain.x", "cannot read vars.plain.x: vars.plain is not a map"},
		{"two values on stdin", pw + "\n" + pw + "\n", "", "winch secret decrypt: stdin holds more than one value; give one !secret value"},
		{"a broken value on stdin", "!secret notbase64", "", "!secret: "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"secret", "decrypt"}, strings.Fields(tt.path)...)
			r := winchWith(t, dir, "", identity, "", fakehost.New(), false, tt.stdin, args...)
			if r.code != exitInvalid || r.out != "" || !strings.Contains(r.err, tt.want) {
				t.Errorf("exit %d, stdout %q, stderr %q; want %q", r.code, r.out, r.err, tt.want)
			}
		})
	}
	r := winchWith(t, dir, t.TempDir(), "", "", fakehost.New(), false, "", "secret", "decrypt", "vars.token")
	if r.code != exitInvalid || r.out != "" || !strings.Contains(r.err, "winch secret init") {
		t.Errorf("no age key: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	other, _ := newIdentity(t)
	r = winchWith(t, dir, "", other, "", fakehost.New(), false, "", "secret", "decrypt", "vars.token")
	if r.code != exitInvalid || r.out != "" || !strings.Contains(r.err, "winch.yaml:6:10: the age key "+other+" is not in recipients") {
		t.Errorf("another age key: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	r = winchWith(t, dir, "", identity, "", fakehost.New(), true, "", "secret", "decrypt")
	if r.code != exitInvalid || r.out != "" || !strings.Contains(r.err, "winch secret decrypt: give a path, or a !secret value on stdin") {
		t.Errorf("a terminal on stdin: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
}

// spec: Variables/Secrets (winch secret decrypt, paths)
func TestSecretDecryptPaths(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	pw := encrypt(t, dir, "hunter2")
	files := map[string]string{
		"winch.yaml": "name: acme\nrecipients:\n  - " + id.Recipient().String() + "\n" +
			"hosts:\n  db1.acme.com:\n    vars:\n      pw: " + pw + "\ngroups:\n  all:\n    vars:\n      pw: " + pw + "\n" +
			"vars:\n  dkim_keys:\n    acme.com: " + pw + "\n",
		"recipes/mail/recipe.yaml": "vars:\n  mail_pw: " + pw + "\nsteps: []\n",
		"pipelines/site.yaml":      "stages: [",
	}
	if err := os.MkdirAll(filepath.Join(dir, "recipes", "mail"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(dir, "inventories")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"hosts.db1.acme.com.vars.pw", "groups.all.vars.pw", "recipes.mail.vars.mail_pw", `vars.dkim_keys["acme.com"]`} {
		r := winchWith(t, dir, "", identity, "", fakehost.New(), false, "", "secret", "decrypt", path)
		if r.code != exitOK || r.out != "hunter2" || r.err != "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", path, r.code, r.out, r.err)
		}
	}
}
