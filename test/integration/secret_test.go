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
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients:\n  - " + id.Recipient().String() + "\nvars:\n  pw:\n",
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
			"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients:\n  - " + id.Recipient().String() + "\nvars:\n  tls_key:\n",
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
