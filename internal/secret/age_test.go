package secret

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// spec: Variables/Secrets
func TestRoundTrip(t *testing.T) {
	id := newIdentity(t)
	rec, err := ParseRecipients([]string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"hunter2", "line one\nline two\n", "\x00\xff binary"} {
		text, err := Encrypt(plain, rec)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(text, "\n \t") {
			t.Errorf("ciphertext %q is not one line", text)
		}
		if _, err := base64.StdEncoding.DecodeString(text); err != nil {
			t.Errorf("ciphertext is not base64: %v", err)
		}
		if err := CheckForm(text); err != nil {
			t.Errorf("CheckForm: %v", err)
		}
		got, err := Decrypt(text, []age.Identity{id})
		if err != nil {
			t.Fatal(err)
		}
		if got != plain {
			t.Errorf("Decrypt = %q, want %q", got, plain)
		}
	}
}

// spec: Variables/Secrets
func TestDecryptWrongIdentity(t *testing.T) {
	rec, err := ParseRecipients([]string{newIdentity(t).Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	text, err := Encrypt("hunter2", rec)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decrypt(text, []age.Identity{newIdentity(t)})
	if err == nil || !strings.Contains(err.Error(), "the identity is not a recipient") {
		t.Errorf("Decrypt with another identity: %v", err)
	}
}

// spec: Variables/Secrets
func TestRecipients(t *testing.T) {
	two := []string{newIdentity(t).Recipient().String(), newIdentity(t).Recipient().String()}
	if rec, err := ParseRecipients(two); err != nil || len(rec) != 2 {
		t.Errorf("ParseRecipients(two) = %d, %v", len(rec), err)
	}
	for _, bad := range []string{"age1nope", "", "ssh-ed25519 AAAA"} {
		if _, err := ParseRecipients([]string{bad}); err == nil {
			t.Errorf("ParseRecipients(%q): no error", bad)
		}
	}
	if _, err := Encrypt("x", nil); err == nil {
		t.Error("Encrypt without recipients: no error")
	}
}

// spec: Variables/Secrets
func TestIdentityRead(t *testing.T) {
	id := newIdentity(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "age.key")
	if err := os.WriteFile(good, []byte("# created: today\n# public key: x\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.key")
	tests := []struct {
		name    string
		id      Identity
		wantErr string
	}{
		{"file", Identity{Path: good}, ""},
		{"file that is not a key", Identity{Path: bad}, "read the age identity in " + bad + ": "},
		{"missing file", Identity{Path: missing}, "no age key in " + missing + "\nSet WINCH_AGE_KEY"},
		{"no path", Identity{}, "no age key: the home directory is not known; set WINCH_AGE_KEY or WINCH_AGE_IDENTITY_CMD"},
		{"command", Identity{Cmd: "cat age.key", Dir: dir}, ""},
		{"failing command", Identity{Cmd: "echo locked >&2; exit 3"}, "read the age identity: echo locked >&2; exit 3: exit status 3: locked"},
		{"failing command without stderr", Identity{Cmd: "exit 3"}, "read the age identity: exit 3: exit status 3"},
		{"command that prints no key", Identity{Cmd: "echo not a key"}, "read the age identity from echo not a key: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, err := tt.id.Read(t.Context())
			if tt.wantErr == "" {
				if err != nil || len(ids) != 1 {
					t.Errorf("Read = %d, %v; want one identity", len(ids), err)
				}
				return
			}
			if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr) {
				t.Errorf("Read = %v, want an error that starts with %q", err, tt.wantErr)
			}
		})
	}
}

// spec: Variables/Secrets
func TestCheckForm(t *testing.T) {
	split := base64.StdEncoding.EncodeToString([]byte("age-encryption.org/v1\n-> X25519 abc\n"))
	split = split[:20] + "\n" + split[20:]
	for _, text := range []string{"PLACEHOLDER", "", base64.StdEncoding.EncodeToString([]byte("hello")), "YWdl LWVu", split} {
		if err := CheckForm(text); err == nil {
			t.Errorf("CheckForm(%q): no error", text)
		}
	}
}

// spec: Variables/Secrets
func TestOneLine(t *testing.T) {
	tests := []struct {
		in, want string
		err      bool
	}{
		{"hunter2\n", "hunter2", false},
		{"hunter2\r\n", "hunter2", false},
		{"hunter2", "hunter2", false},
		{"hunter2\n\n", "hunter2\n\n", false},
		{"a\nb\n", "a\nb\n", false},
		{"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n", false},
		{"", "", true},
		{"\n", "", true},
	}
	for _, tt := range tests {
		got, err := OneLine(tt.in)
		if (err != nil) != tt.err || got != tt.want {
			t.Errorf("OneLine(%q) = %q, %v; want %q, error %v", tt.in, got, err, tt.want, tt.err)
		}
	}
}

// A child of the command can keep stdout open after the end of ctx.
func TestIdentityReadCanceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (Identity{Cmd: "sleep 30; true"}).Read(ctx); err == nil {
		t.Error("Read after the end of ctx: no error")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("Read returned after %v", d)
	}
}
