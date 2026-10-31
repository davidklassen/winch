// Package secret encrypts secrets with age and keeps them out of the output:
// the masks of the placeholder evaluations, the masked diff, and the text
// filter.
package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// ParseRecipients parses age public keys.
func ParseRecipients(keys []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, k := range keys {
		rec, err := age.ParseRecipients(strings.NewReader(k))
		if err != nil {
			return nil, fmt.Errorf("%q is not an age public key", k)
		}
		if len(rec) != 1 {
			return nil, fmt.Errorf("%q is not one age public key", k)
		}
		out = append(out, rec...)
	}
	return out, nil
}

// Encrypt returns plain encrypted for the recipients, as base64 on one line.
func Encrypt(plain string, recipients []age.Recipient) (string, error) {
	if len(recipients) == 0 {
		return "", errors.New("no recipients")
	}
	var b bytes.Buffer
	w, err := age.Encrypt(&b, recipients...)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(w, plain); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

const passwordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Password returns a random password of 32 letters and digits.
func Password() string {
	var out []byte
	b := make([]byte, 1)
	for len(out) < 32 {
		rand.Read(b)
		// Without the bytes above the last full set of characters, each
		// character is equally likely.
		if int(b[0]) < 256-256%len(passwordChars) {
			out = append(out, passwordChars[int(b[0])%len(passwordChars)])
		}
	}
	return string(out)
}

// Identity is the source of the age identity: the stdout of Cmd when Cmd
// is not empty, else the file Path.
type Identity struct {
	Path string
	// Cmd runs through sh -c in Dir.
	Cmd, Dir string
}

// String names the source for an error message.
func (id Identity) String() string {
	if id.Cmd != "" {
		return "from " + id.Cmd
	}
	return "in " + id.Path
}

const noKeyHelp = "Set WINCH_AGE_KEY to a key file, or WINCH_AGE_IDENTITY_CMD to a command that prints a key.\n" +
	"To make a key, run winch secret init. A member who can read the secrets must then run winch secret rekey"

// Read reads the identities from the source.
func (id Identity) Read(ctx context.Context) ([]age.Identity, error) {
	var data []byte
	if id.Cmd == "" {
		if id.Path == "" {
			return nil, errors.New("no age key: the home directory is not known; set WINCH_AGE_KEY or WINCH_AGE_IDENTITY_CMD")
		}
		var err error
		data, err = os.ReadFile(id.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no age key %s\n%s", id, noKeyHelp)
		}
		if err != nil {
			return nil, fmt.Errorf("read the age identity: %w", err)
		}
	} else {
		cmd := exec.CommandContext(ctx, "sh", "-c", id.Cmd)
		cmd.Dir = id.Dir
		// A child of sh can keep stdout open after ctx ends.
		cmd.WaitDelay = time.Second
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		var err error
		if data, err = cmd.Output(); err != nil {
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				err = fmt.Errorf("%w: %s", err, msg)
			}
			return nil, fmt.Errorf("read the age identity: %s: %w", id.Cmd, err)
		}
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read the age identity %s: %w", id, err)
	}
	return ids, nil
}

// Init returns the public key of the identity. When the source is a file and
// no file is there, it makes a new key and returns it in made; WriteKey
// writes it.
func (id Identity) Init(ctx context.Context) (key string, made *age.X25519Identity, err error) {
	if id.Cmd == "" && id.Path != "" {
		if _, err := os.Stat(id.Path); errors.Is(err, fs.ErrNotExist) {
			made, err := age.GenerateX25519Identity()
			if err != nil {
				return "", nil, fmt.Errorf("make the age key: %w", err)
			}
			return made.Recipient().String(), made, nil
		}
	}
	ids, err := id.Read(ctx)
	if err != nil {
		return "", nil, err
	}
	if len(ids) != 1 {
		return "", nil, fmt.Errorf("the age identity %s holds %d keys; winch needs one", id, len(ids))
	}
	switch i := ids[0].(type) {
	case *age.X25519Identity:
		return i.Recipient().String(), nil, nil
	case *age.HybridIdentity:
		return i.Recipient().String(), nil, nil
	}
	return "", nil, fmt.Errorf("the age identity %s has no public key", id)
}

// WriteKey writes k to the file Path in the format of age-keygen. It fails
// when the file exists.
func (id Identity) WriteKey(k *age.X25519Identity) error {
	if err := writeKey(id.Path, k); err != nil {
		return fmt.Errorf("make the age key: %w", err)
	}
	return nil
}

func writeKey(path string, k *age.X25519Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "# created: %s\n# public key: %s\n%s\n", time.Now().Format(time.RFC3339), k.Recipient(), k)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

const ageHeader = "age-encryption.org/v1\n"

// ErrNotRecipient is the error of Decrypt when no identity can decrypt.
var ErrNotRecipient = errors.New("the identity is not a recipient")

// CheckForm checks that text is base64 of an age file.
func CheckForm(text string) error {
	_, err := decode(text)
	return err
}

func decode(text string) ([]byte, error) {
	data, err := base64.StdEncoding.Strict().DecodeString(text)
	// The decoder skips line breaks; a !secret value is one line.
	if err != nil || text == "" || strings.ContainsAny(text, "\r\n") {
		return nil, errors.New("the value is not base64")
	}
	if !bytes.HasPrefix(data, []byte(ageHeader)) {
		return nil, errors.New("the value is not an age file")
	}
	return data, nil
}

// Decrypt returns the plaintext of text, base64 of an age file.
func Decrypt(text string, ids []age.Identity) (string, error) {
	data, err := decode(text)
	if err != nil {
		return "", err
	}
	r, err := age.Decrypt(bytes.NewReader(data), ids...)
	if _, ok := errors.AsType[*age.NoIdentityMatchError](err); ok {
		return "", ErrNotRecipient
	}
	if err != nil {
		return "", err
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Stanzas returns the number of recipients that text, base64 of an age file,
// is encrypted for. It needs no identity.
func Stanzas(text string) (int, error) {
	data, err := decode(text)
	if err != nil {
		return 0, err
	}
	var c stanzaCounter
	if _, err := age.Decrypt(bytes.NewReader(data), &c); !errors.Is(err, age.ErrIncorrectIdentity) {
		return 0, err
	}
	return c.n, nil
}

// stanzaCounter is an identity that counts the stanzas and unwraps none.
type stanzaCounter struct{ n int }

func (c *stanzaCounter) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	c.n = len(stanzas)
	return nil, age.ErrIncorrectIdentity
}

// OneLine returns the value for winch secret encrypt: a value with no line
// break before its end loses its trailing newline.
func OneLine(value string) (string, error) {
	v, ok := strings.CutSuffix(value, "\n")
	v = strings.TrimSuffix(v, "\r")
	if !ok || strings.Contains(v, "\n") {
		v = value
	}
	if v == "" {
		return "", errors.New("the value is empty")
	}
	return v, nil
}
