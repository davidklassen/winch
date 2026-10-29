package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeSecret(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "fake_secrets", name))
	if err != nil {
		t.Fatalf("read fake secret: %v", err)
	}
	return strings.TrimSuffix(string(b), "\n")
}

// spec: Variables/Secrets in output (text filter)
func TestFilter(t *testing.T) {
	fake := func(name string) string { return fakeSecret(t, name) }
	tests := []struct {
		name   string
		values []string
		in     string
		want   string
	}{
		{"plain", []string{"hunter2"}, "password hunter2 here", "password (secret) here"},
		{"twice on a line", []string{"hunter2"}, "hunter2:hunter2", "(secret):(secret)"},
		{"two places", []string{"hunter2"}, "a hunter2 b hunter2 c", "a (secret) b (secret) c"},
		{"json quote", []string{`foo"bar`}, `{"k": "foo\"bar"}`, `{"k": "(secret)"}`},
		{"json backslash", []string{`dir\path-secret`}, `{"k": "dir\\path-secret"}`, `{"k": "(secret)"}`},
		{"json tab", []string{"tab\there"}, `{"k": "tab\there"}`, `{"k": "(secret)"}`},
		{"json html", []string{"a<b&c>d"}, `{"k": "a\u003cb\u0026c\u003ed"}`, `{"k": "(secret)"}`},
		{"json of the printable form", []string{"a<b\x01cdef"}, `{"k": "a\u003cb?cdef"}`, `{"k": "(secret)"}`},
		{"json non-ascii stays", []string{"Zürich-secret\x01"}, `{"k": "Zürich-secret\u0001"}`, `{"k": "(secret)"}`},
		{"lines printable form", []string{"abc\r\nxyz\r\n"}, "e: abc?\nxyz", "e: (secret)\n(secret)"},
		{"json of the lines printable form", []string{"abc\r\nxyz\r\n"}, `{"k": "abc?\nxyz"}`, `{"k": "(secret)"}`},
		{"base64", []string{"topsecret"}, "data: dG9wc2VjcmV0", "data: (secret)"},
		{"base64 with padding", []string{"hunter2"}, "data: aHVudGVyMg==", "data: (secret)=="},
		{"url query", []string{"p@ss word&x"}, "https://h/?p=p%40ss+word%26x", "https://h/?p=(secret)"},
		{"url path", []string{"p@ss word/x"}, "https://h/p@ss%20word%2Fx", "https://h/(secret)"},
		{"longest match", []string{"word", "password"}, "my password here", "my (secret) here"},
		{"short value inside a long one", []string{"SECRET101", "RET"}, "x SECRET101 y", "x (secret) y"},
		{"short value first", []string{"RET1", "SECRET101"}, "x SECRET101 y", "x (secret) y"},
		{"overlap merges", []string{"hunter2", "ter2foo123"}, "start-hunter2foo123-end", "start-(secret)-end"},
		{"adjacent merge", []string{"private", "confiden"}, "privateconfiden", "(secret)"},
		{"repeat merges", []string{"private"}, "privateprivateprivate", "(secret)"},
		{"self overlap", []string{"aaaaaaa"}, "xaaaaaaaaay", "x(secret)y"},
		{"one space keeps two marks", []string{"private", "confiden"}, "private confiden", "(secret) (secret)"},
		{"near miss", []string{"PREFIX12-secret"}, "PREFIX12-public data", "PREFIX12-public data"},
		{"inside a longer token", []string{`test"secret`}, `test"secret2 test"secre`, `(secret)2 test"secre`},
		{"case-sensitive", []string{"private"}, "PRIVATE data", "PRIVATE data"},
		{"regex characters", []string{"a.b*c[d]"}, "a.b*c[d] aXbbcd", "(secret) aXbbcd"},
		{"not utf-8", []string{"nonutf8\xa7"}, "x nonutf8\xa7 y", "x (secret) y"},
		{"unicode", []string{"пароль-секрет"}, "pw: пароль-секрет!", "pw: (secret)!"},
		{"short skipped", []string{"my", "80"}, "These are my secrets on port 80", "These are my secrets on port 80"},
		{"three characters skipped", []string{"abc"}, "abc", "abc"},
		{"four characters masked", []string{"abcd"}, "abcd", "(secret)"},
		{"booleans skipped", []string{"true", "false"}, `{"enabled": true, "x": false}`, `{"enabled": true, "x": false}`},
		{"white space trimmed", []string{"  padded-secret \n"}, "x padded-secret y", "x (secret) y"},
		{"base64 of the exact value with spaces", []string{" hunter2 "}, "data: IGh1bnRlcjIg", "data: (secret)"},
		{"base64 of the exact value with a newline", []string{"hunter2\n"}, "data: aHVudGVyMgo=", "data: (secret)="},
		{"url path of the exact value with spaces", []string{" hunter2 "}, "https://h/%20hunter2%20/x", "https://h/(secret)/x"},
		{"white space only", []string{"   \n\t"}, "a   \n\tb", "a   \n\tb"},
		{"each line of a multi-line secret", []string{"line-one\nline-two\nend"}, "-line-one\n+line-two\nstderr: line-two", "-(secret)\n+(secret)\nstderr: (secret)"},
		{"multi-line secret whole", []string{"line-one\nline-two"}, "x line-one\nline-two y", "x (secret)\n(secret) y"},
		{"multi-line secret in json", []string{"multi\nline\nsecret"}, `{"k": "multi\nline\nsecret"}`, `{"k": "(secret)"}`},
		{"the mark itself", []string{"(secret)"}, "a (secret) b", "a (secret) b"},
		{"inside the mark", []string{"secret"}, "a (secret) secret b", "a (secret) (secret) b"},
		{"pkcs8 key", nil, "key:\n" + fake("pkcs8.txt") + "\nafter", "key:\n(secret)\n(secret)\n(secret)\n(secret)\nafter"},
		{"rsa key", nil, fake("rsa.txt"), "(secret)\n(secret)\n(secret)"},
		{"openssh key", nil, fake("openssh.txt") + "\n", "(secret)\n(secret)\n(secret)\n"},
		{"pgp private block", nil, fake("pgp.txt"), "(secret)\n\n(secret)\n(secret)\n(secret)"},
		{"encrypted key", nil, fake("encrypted.txt"), "(secret)\n(secret)\n(secret)"},
		{"key on one line", nil, "private_key=-----BEGIN RSA PRIVATE KEY----- MIICabc -----END RSA PRIVATE KEY----- rest", "private_key=(secret) rest"},
		{"key with escapes", nil, `"k": "-----BEGIN RSA PRIVATE KEY-----\nMIIC\n-----END RSA PRIVATE KEY-----\n", "n": 1`, `"k": "(secret)\n", "n": 1`},
		{"two keys on one line", nil, "-----BEGIN PRIVATE KEY----- AAA -----END PRIVATE KEY----- keep -----BEGIN PRIVATE KEY----- BBB -----END PRIVATE KEY-----", "(secret) keep (secret)"},
		{"key lines with a prefix", nil, "      +-----BEGIN PRIVATE KEY-----\n      +" + fake("key_line.txt") + "\n      +-----END PRIVATE KEY-----\n      +after", "      +(secret)\n      (secret)\n      (secret)\n      +after"},
		{"cut key", nil, fake("cut_key.txt"), "(secret)\n(secret)\n(secret)"},
		{"public key", nil, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n-----END PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n-----END PUBLIC KEY-----"},
		{"rsa public key", nil, "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA\n-----END RSA PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA\n-----END RSA PUBLIC KEY-----"},
		{"certificate", nil, "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n-----END CERTIFICATE-----"},
		{"certificate request", nil, "-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----", "-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----"},
		{"pgp public block", nil, "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----", "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----"},
		{"pgp signature", nil, "-----BEGIN PGP SIGNATURE-----\niQIzBAEB\n-----END PGP SIGNATURE-----", "-----BEGIN PGP SIGNATURE-----\niQIzBAEB\n-----END PGP SIGNATURE-----"},
		{"dh parameters", nil, "-----BEGIN DH PARAMETERS-----\nMIIBCAKCAQEA\n-----END DH PARAMETERS-----", "-----BEGIN DH PARAMETERS-----\nMIIBCAKCAQEA\n-----END DH PARAMETERS-----"},
		{"ssh public keys", nil, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHWcguvG0Ox4 mac\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 x", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHWcguvG0Ox4 mac\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 x"},
		{"aws key", nil, "aws_access_key_id = AKIA2E0A8F3B244C9986", "aws_access_key_id = AKIA2E0A8F3B244C9986"},
		{"aws key base32", nil, "id: " + fake("aws.txt") + " and " + fake("aws_session.txt") + ".", "id: (secret) and (secret)."},
		{"aws example key", nil, fake("aws_example.txt"), "(secret)"},
		{"aws prefix in a word", nil, fake("aws_in_word.txt"), fake("aws_in_word.txt")},
		{"aws prefix in dna", nil, "CTTCATAGGGACCAGTTTAGGCACCATACCA", "CTTCATAGGGACCAGTTTAGGCACCATACCA"},
		{"aws mixed case", nil, "AKIAs9L8MDKSoeVNZRBq", "AKIAs9L8MDKSoeVNZRBq"},
		{"github tokens", nil, fake("ghp.txt") + " " + fake("gho.txt") + " " + fake("ghs.txt"), "(secret) (secret) (secret)"},
		{"github fine-grained", nil, fake("github_fine_grained.txt") + " x", "(secret) x"},
		{"github short", nil, "ghp_short", "ghp_short"},
		{"git sha", nil, "ref=5f2b6c1d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c", "ref=5f2b6c1d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"},
		{"slack bot", nil, "token: " + fake("slack_bot.txt"), "token: (secret)"},
		{"slack user", nil, fake("slack_user.txt"), "(secret)"},
		{"slack webhook", nil, "url: " + fake("slack_webhook.txt"), "url: (secret)"},
		{"slack negatives", nil, "xoxb-xxxxxxxxx-xxxx xoxb-my-bot-token xoxb-12345-abcd234 XOxE-RROAmw CxOxP-abc", "xoxb-xxxxxxxxx-xxxx xoxb-my-bot-token xoxb-12345-abcd234 XOxE-RROAmw CxOxP-abc"},
		{"no secret", []string{"hunter2"}, "nothing here", "nothing here"},
		{"age identity", nil, "key: " + fake("age_identity.txt") + " end", "key: (secret) end"},
		{"control characters as winch prints them", []string{"pass\x07word"}, "echo pass?word", "echo (secret)"},
		{"format characters as winch prints them", []string{"pass\u200bword"}, "echo pass?word", "echo (secret)"},
		{"url password", nil, "git clone " + fake("url_password.txt") + "/app", "git clone https://deploy:(secret)@git.example.com/app"},
		{"url password without a user", nil, fake("url_password_no_user.txt"), "redis://:(secret)@cache:6379"},
		{"two url passwords", nil, "a=" + fake("url_password.txt") + " b=" + fake("url_password_no_user.txt"), "a=https://deploy:(secret)@git.example.com b=redis://:(secret)@cache:6379"},
		{"url password with an at sign", nil, fake("url_password_at.txt") + "/x", "postgres://app:(secret)@db/x"},
		{"url password with a quote", nil, fake("url_password_quote.txt"), "mysql://app:(secret)@db"},
		{"url password in json", nil, `{"url":"` + fake("url_password.txt") + `","x":"a@b"}`, `{"url":"https://deploy:(secret)@git.example.com","x":"a@b"}`},
		{"url without a password", nil, "https://deploy@git.example.com https://git.example.com:8443/x", "https://deploy@git.example.com https://git.example.com:8443/x"},
		{"url password with an at sign", nil, "postgres://app:p@ss@db/x", "postgres://app:(secret)@db/x"},
		{"url password in json", nil, `{"url":"https://u:pw@h","x":"a@b"}`, `{"url":"https://u:(secret)@h","x":"a@b"}`},
		{"url with a port and an at sign later", nil, "https://h:8443/a@b", "https://h:8443/a@b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFilter()
			for _, v := range tt.values {
				f.Add(v)
			}
			if got := f.Text(tt.in); got != tt.want {
				t.Errorf("Text(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

// spec: Variables/Secrets in output (text filter)
func TestFilterPlainLines(t *testing.T) {
	wg := "[Interface]\nPrivateKey = wg-private-key-1\n\n[Peer]\nPublicKey = wg-public-key-2\nAllowedIPs = 10.0.0.2/32"
	tests := []struct {
		name  string
		plain string
		value string
		in    string
		want  string
	}{
		{"common line shows", "[Peer]\nPublicKey = {{ .vars.key }}\n", wg, " [Peer]\n-PublicKey = old\n+PublicKey = new", " [Peer]\n-PublicKey = old\n+PublicKey = new"},
		{"key line stays hidden", "[Peer]\n", wg, "+PrivateKey = wg-private-key-1", "+(secret)"},
		{"line without a common line stays hidden", "[Peer]\n", wg, "x AllowedIPs = 10.0.0.2/32", "x (secret)"},
		{"whole value stays hidden", "[Interface]\n[Peer]\n", wg, "x " + wg + " y", "x (secret)\n(secret)\n\n(secret)\n(secret)\n(secret) y"},
		{"common line with white space", "env:\n  NODE_ENV=production\n", "NODE_ENV=production\nAPI_TOKEN=tok-123456", "NODE_ENV=production API_TOKEN=tok-123456", "NODE_ENV=production (secret)"},
		{"base64 of a common line shows", "[Peer]\n", wg, "W1BlZXJd", "W1BlZXJd"},
		{"url form of a common line shows", "[Peer]\n", wg, "%5BPeer%5D", "%5BPeer%5D"},
		{"line of binary data stays hidden", "\x00\n[Peer]\n", wg, " [Peer]", " (secret)"},
		{"part of a plain line stays hidden", "PrivateKey = wg-private-key-1 is an example\n", wg, "PrivateKey = wg-private-key-1", "(secret)"},
		{"one-line value in plain text stays hidden", "admin-user\n", "admin-user", "login admin-user", "login (secret)"},
		{"one-line value with a newline stays hidden", "admin-user\n", "admin-user\n", "login admin-user", "login (secret)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFilter()
			f.Plain([]byte(tt.plain))
			f.Add(tt.value)
			if got := f.Text(tt.in); got != tt.want {
				t.Errorf("Text(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

// spec: Variables/Secrets in output (text filter)
func TestFilterManyValues(t *testing.T) {
	f := NewFilter()
	var values []string
	for i := range 50 {
		v := fmt.Sprintf("shared-prefix-%d", i)
		f.Add(v)
		values = append(values, v)
		for _, old := range values {
			if got := f.Text("x " + old + " y"); got != "x (secret) y" {
				t.Fatalf("after %d values, Text(%q) = %q", i+1, old, got)
			}
		}
	}
}

// spec: CLI/Output
func TestPrintable(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"web\u202Eevil", "web?evil"},
		{"a\u200Bb", "a?b"},
		{"bell\x07 tab\tline\u2028", "bell? tab\tline?"},
		{"Zürich café", "Zürich café"},
	}
	for _, tt := range tests {
		if got := Printable(tt.in); got != tt.want {
			t.Errorf("Printable(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// spec: CLI/Output (the text filter runs before winch adds color)
func TestFilterParts(t *testing.T) {
	f := NewFilter()
	f.Add("hunter2")
	key := fakeSecret(t, "rsa.txt")
	tests := []struct {
		name  string
		parts []string
		want  []string
	}{
		{"none", nil, []string{}},
		{"in one part", []string{"a ", "x hunter2 y", "\n"}, []string{"a ", "x (secret) y", "\n"}},
		{"across parts", []string{"x hun", "ter2", " y"}, []string{"x (secret)", "", " y"}},
		{"key over lines", []string{"  ", "+" + strings.ReplaceAll(key, "\n", "\n  +") + "\n", "  ", "after\n"},
			[]string{"  ", "+(secret)\n  (secret)\n  (secret)\n", "  ", "after\n"}},
		{"empty parts", []string{"", "hunter2", ""}, []string{"", "(secret)", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.Parts(tt.parts)
			if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", tt.want) {
				t.Errorf("Parts(%q) = %q, want %q", tt.parts, got, tt.want)
			}
			if j := strings.Join(got, ""); j != f.Text(strings.Join(tt.parts, "")) {
				t.Errorf("joined parts %q differ from Text", j)
			}
		})
	}
}
