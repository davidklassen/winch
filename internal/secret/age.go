// Package secret encrypts secrets with age and keeps them out of the output:
// the masks of the placeholder evaluations, the masked diff, and the text
// filter.
package secret

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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

// ReadIdentities reads an age identity file.
func ReadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read the age identity: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("read the age identity %s: %w", path, err)
	}
	return ids, nil
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
