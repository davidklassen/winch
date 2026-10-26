package module

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var keyTypes = []string{
	"ssh-ed25519", "ssh-rsa", "ssh-dss",
	"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
	"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
}

// authorizedKey is a line of an authorized_keys file.
type authorizedKey struct {
	options, typ, comment string
	blob                  []byte
}

// parseKey reads a line as sshd does: optional options, the key type, the
// base64 key data, and an optional comment.
func parseKey(line string) (authorizedKey, error) {
	var k authorizedKey
	rest := strings.TrimLeft(line, " \t")
	if typ, _ := cutField(rest); !slices.Contains(keyTypes, typ) {
		k.options, rest = cutOptions(rest)
	}
	k.typ, rest = cutField(rest)
	if !slices.Contains(keyTypes, k.typ) {
		return k, errors.New(`no key type such as "ssh-ed25519"`)
	}
	data, rest := cutField(rest)
	if data == "" {
		return k, errors.New("the key data is missing")
	}
	blob, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return k, errors.New("the key data is not base64")
	}
	prefix := append(binary.BigEndian.AppendUint32(nil, uint32(len(k.typ))), k.typ...)
	if !bytes.HasPrefix(blob, prefix) || len(blob) == len(prefix) {
		return k, fmt.Errorf("the key data is not an %s key", k.typ)
	}
	k.blob, k.comment = blob, strings.TrimSpace(rest)
	return k, nil
}

// cutField splits s at the first space or tab, and drops the white space
// that follows.
func cutField(s string) (string, string) {
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}

// cutOptions splits s after its options: the text up to the first white
// space outside double quotes.
func cutOptions(s string) (string, string) {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && quoted && i+1 < len(s):
			i++
		case s[i] == '"':
			quoted = !quoted
		case !quoted && (s[i] == ' ' || s[i] == '\t'):
			return s[:i], strings.TrimLeft(s[i:], " \t")
		}
	}
	return s, ""
}

// fingerprint is the SHA-256 fingerprint of a key, as ssh-keygen -l shows it.
func fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// keyPlan returns the plan form of an authorized_keys line: "key", then the
// line with the key data as its fingerprint.
func keyPlan(line string) string {
	k, err := parseKey(line)
	if err != nil {
		return "a line that is not a key"
	}
	parts := []string{"key", k.typ, fingerprint(k.blob)}
	if k.options != "" {
		parts = slices.Insert(parts, 1, k.options)
	}
	if k.comment != "" {
		parts = append(parts, k.comment)
	}
	return strings.Join(parts, " ")
}

// keyChanges describes how the lines cur of an authorized_keys file become
// the lines want.
func keyChanges(cur, want []string) []string {
	var changes []string
	seen := map[string]bool{}
	for _, w := range want {
		if !slices.Contains(cur, w) && !seen[w] {
			changes = append(changes, "add "+keyPlan(w))
		}
		seen[w] = true
	}
	for _, c := range cur {
		if seen[c] {
			continue
		}
		seen[c] = true
		changes = append(changes, "remove "+keyPlan(c))
	}
	switch {
	case len(changes) > 0, slices.Equal(cur, want):
	case len(cur) != len(want):
		changes = append(changes, "remove a duplicate line")
	default:
		changes = append(changes, "put the keys in order")
	}
	return changes
}
