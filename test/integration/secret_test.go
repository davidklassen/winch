package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Variables/Secrets in output (text filter)
func TestSecretInCommandErrors(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "secret")
	pw := "ab'cd\"ef\\gh$ij\nkl'mn\"op\\qr$st"
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(key, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	text, err := secret.Encrypt(pw, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients:\n  - " + id.Recipient().String() + "\n",
		"inventories/test.yaml": "hosts:\n  " + vm.Name + ":\n    vars:\n      pw: !secret " + text + "\n",
		"pipelines/validate.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /tmp/validate
          content: "x\n"
          validate: !tpl "echo {{ quote .vars.pw }}; false {{ quote .vars.pw }}"
`,
		"pipelines/then.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /tmp/then
          content: "x\n"
        then: !tpl "echo {{ quote .vars.pw }}; false {{ quote .vars.pw }}"
`,
	})
	env := []string{"WINCH_AGE_KEY=" + key}
	for _, pipeline := range []string{"validate", "then"} {
		for _, args := range [][]string{{"apply", pipeline, "--yes"}, {"apply", pipeline, "--yes", "--json"}} {
			r := lab.WinchEnv(t, dir, env, args...)
			if r.Code != 1 || !strings.Contains(r.Stdout+r.Stderr, "exit status 1") {
				t.Errorf("winch %s: exit %d; want 1 and the command error", strings.Join(args, " "), r.Code)
			}
			out := r.Stdout + r.Stderr
			if args[len(args)-1] == "--json" {
				out += decoded(t, r.Stdout)
			}
			for _, line := range strings.Split(pw, "\n") {
				for i := range len(line) - 3 {
					if part := line[i : i+4]; strings.Contains(out, part) {
						t.Errorf("winch %s shows %q of the secret", strings.Join(args, " "), part)
					}
				}
			}
		}
	}
}

// spec: Variables/Secrets in output; CLI/Output
func TestSecretBinaryFile(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "secret-binary")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(key, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"WINCH_AGE_KEY=" + key}
	// The host has the files of the first run when winch plans the second.
	blob := []string{`"a\0b"`, `"text\n"`}
	for i, tlsKey := range []string{"0\x82\x00\x01\xff", "0\x82\x00\x02\xfe"} {
		text, err := secret.Encrypt(tlsKey, []age.Recipient{id.Recipient()})
		if err != nil {
			t.Fatal(err)
		}
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: acme\ninventory: test\nrecipients:\n  - " + id.Recipient().String() + "\n",
			"inventories/test.yaml": "hosts:\n  " + vm.Name + ":\n    vars:\n      tls_key: !secret " + text + "\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/ssl/private/key.der
          content: !expr vars.tls_key
          mode: "0600"
      - file:
          path: /tmp/blob
          content: ` + blob[i] + `
`,
		})
		if i == 0 {
			if r := lab.WinchEnv(t, dir, env, "apply", "site", "--yes"); r.Code != 0 {
				t.Fatalf("apply: exit %d", r.Code)
			}
			continue
		}
		r := lab.WinchEnv(t, dir, env, "plan", "site")
		if !strings.Contains(r.Stdout, "~ file /etc/ssl/private/key.der\n        (secret)\n    ~") {
			t.Errorf("the plan shows more than (secret) for the key:\n%s", r.Stdout)
		}
		if !strings.Contains(r.Stdout, "~ file /tmp/blob\n        content (binary)\n") {
			t.Errorf("the plan does not say why the file without a secret has no diff:\n%s", r.Stdout)
		}
	}
}

// spec: Variables/Secrets in output (file diffs); Remote execution/State on
// the host
func TestSecretMaskedRecord(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "secret-masked")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(key, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"WINCH_AGE_KEY=" + key}
	vm.MustRun(t, `printf 'token old\nworkers 2\n' > /etc/line.conf; chmod 600 /etc/line.conf`)
	// password is "" for a project with no secret; the two texts are !tpl
	// strings.
	project := func(password, content, token, workers string) string {
		vars := "{}"
		if password != "" {
			text, err := secret.Encrypt(password, []age.Recipient{id.Recipient()})
			if err != nil {
				t.Fatal(err)
			}
			vars = "\n    vars:\n      pw: !secret " + text
		}
		return vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: acme\ninventory: test\nrecipients:\n  - " + id.Recipient().String() + "\n",
			"inventories/test.yaml": "hosts:\n  " + vm.Name + ": " + vars + "\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/app.conf
          content: !tpl "` + content + `"
          mode: "0600"
      - line:
          path: /etc/line.conf
          line: !tpl "` + token + `"
          match: "^token "
      - line:
          path: /etc/line.conf
          line: ` + workers + `
          match: "^workers "
`,
		})
	}
	records := func() []string {
		return strings.Fields(vm.MustRun(t, "find /var/lib/winch/masked/acme -type f"))
	}
	const old, rotated = "first-password", "second-password"
	const withSecret, tokenSecret = `workers = 2\npassword = {{ .vars.pw }}\nkeep\n`, `token {{ .vars.pw }}`
	dir := project(old, withSecret, tokenSecret, "workers 2")
	if r := lab.WinchEnv(t, dir, env, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d, stderr %q", r.Code, r.Stderr)
	}
	first := records()
	if len(first) != 2 {
		t.Fatalf("records %q, want two: one per file", first)
	}
	shown := map[string]bool{}
	for _, p := range first {
		if got := strings.TrimSpace(vm.MustRun(t, "stat -c %a "+p)); got != "600" {
			t.Errorf("record mode %s, want 600", got)
		}
		shown[vm.MustRun(t, "cat "+p)] = true
	}
	if !shown["workers = 2\npassword = (secret)\nkeep\n"] || !shown["token (secret)\n"] {
		t.Errorf("records = %v", shown)
	}

	// An ok step keeps the record, in an apply that changes another step.
	vm.MustRun(t, "rm "+strings.Join(first, " ")+"; sed -i 's/^workers 2/workers 1/' /etc/line.conf")
	if r := lab.WinchEnv(t, dir, env, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply of an ok step: exit %d, stderr %q", r.Code, r.Stderr)
	}
	if got := records(); len(got) != 2 {
		t.Errorf("records after an apply of an ok step: %q, want two", got)
	}

	next := project(rotated, `workers = 3\npassword = {{ .vars.pw }}\nkeep\n`, tokenSecret, "workers 3")
	r := lab.WinchEnv(t, next, env, "plan", "site")
	for _, want := range []string{
		"-workers = 2\n", "-password = (secret)\n", "+workers = 3\n", "+password = (secret) (secret value changed)\n",
		"-token (secret)\n", "+token (secret) (secret value changed)\n", "-workers 2\n", "+workers 3\n",
	} {
		if r.Code != 0 || !strings.Contains(r.Stdout, want) {
			t.Errorf("plan after a rotation lacks %q: exit %d, stdout %q", want, r.Code, r.Stdout)
		}
	}
	noSecrets(t, "plan after a rotation", r.Stdout+r.Stderr, old, rotated)
	if r := lab.WinchEnv(t, next, env, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply after a rotation: exit %d, stderr %q", r.Code, r.Stderr)
	}

	plain := project("", `workers = 3\npassword = open\nkeep\n`, "token open", "workers 3")
	r = lab.WinchEnv(t, plain, env, "plan", "site")
	for _, want := range []string{"-password = (secret)\n", "+password = open\n", "-token (secret)\n", "+token open\n"} {
		if r.Code != 0 || !strings.Contains(r.Stdout, want) {
			t.Errorf("plan of a variable made plain lacks %q: exit %d, stdout %q", want, r.Code, r.Stdout)
		}
	}
	noSecrets(t, "plan of a variable made plain", r.Stdout+r.Stderr, old, rotated)
	if r := lab.WinchEnv(t, plain, env, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply without a secret: exit %d, stderr %q", r.Code, r.Stderr)
	}
	// The record of the file step goes. A line step cannot tell that the file
	// has no secret left.
	if got := records(); len(got) != 1 || vm.MustRun(t, "cat "+got[0]) != "token (secret)\n" {
		t.Errorf("records after a write without a secret: %q, want the record of the line step", got)
	}
}

// spec: Modules/user and group; Variables/Secrets in output
func TestSecretKeyOptions(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "secret-key")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(key, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"WINCH_AGE_KEY=" + key}
	// The host has the key line of the first run when winch plans the second,
	// with another key.
	keys := []string{fakeKey('a', "deploy"), fakeKey('b', "deploy")}
	for i, token := range []string{"old-token", "new-token"} {
		text, err := secret.Encrypt(`environment="TOKEN=`+token+`" `+keys[i], []age.Recipient{id.Recipient()})
		if err != nil {
			t.Fatal(err)
		}
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: acme\ninventory: test\nrecipients:\n  - " + id.Recipient().String() + "\n",
			"inventories/test.yaml": "hosts:\n  " + vm.Name + ":\n    vars:\n      deploy_key: !secret " + text + "\n",
			"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - user:
          name: wtdeploy
          authorized_keys: [!expr vars.deploy_key]
`,
		})
		want := []string{"add key (secret) " + keyLine(keys[i])}
		args := []string{"apply", "site", "--yes"}
		if i == 1 {
			want = append(want, "remove key (secret) "+keyLine(keys[0]))
			args = []string{"plan", "site"}
		}
		r := lab.WinchEnv(t, dir, env, args...)
		if r.Code != 0 {
			t.Fatalf("winch %s: exit %d\n%s%s", strings.Join(args, " "), r.Code, r.Stdout, r.Stderr)
		}
		for _, w := range want {
			if !strings.Contains(r.Stdout, w) {
				t.Errorf("winch %s does not show %q:\n%s", strings.Join(args, " "), w, r.Stdout)
			}
		}
		if strings.Contains(r.Stdout+r.Stderr, "token") {
			t.Errorf("winch %s shows the token:\n%s%s", strings.Join(args, " "), r.Stdout, r.Stderr)
		}
	}
}

// decoded returns the string values of each JSON event in out.
func decoded(t *testing.T, out string) string {
	t.Helper()
	var b strings.Builder
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("event %q: %v", line, err)
		}
		fmt.Fprintln(&b, ev)
	}
	return b.String()
}
