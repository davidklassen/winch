package secret

import (
	"slices"
	"strings"
	"testing"
)

// spec: Variables/Secrets in output (text filter: the load warning)
func TestScan(t *testing.T) {
	fake := func(name string) string { return fakeSecret(t, name) }
	body := strings.Repeat(fake("key_line.txt"), 3)
	tests := []struct {
		name string
		in   string
		want []Finding
	}{
		{"private key", "key: |\n  -----BEGIN PRIVATE KEY-----\n  " + body + "\n  -----END PRIVATE KEY-----\n", []Finding{{9, "a private key"}}},
		{"two keys", "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\n" + body + "\n-----END EC PRIVATE KEY-----\n",
			[]Finding{{0, "a private key"}, {159, "a private key"}}},
		{"short key stub", "-----BEGIN PRIVATE KEY-----\nanything\n-----END PRIVATE KEY-----\n", nil},
		{"header and footer only", "-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----", nil},
		{"header without footer", "-----BEGIN PRIVATE KEY-----\n" + body + "\n", nil},
		{"public key", "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n", nil},
		{"certificate", "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n", nil},
		{"aws key", "id: " + fake("aws.txt") + "\n", []Finding{{4, "an AWS access key ID"}}},
		{"aws example", "id: " + fake("aws_example.txt") + "\n", nil},
		{"aws in a word", fake("aws_in_word.txt"), nil},
		{"github token", "token: " + fake("ghp.txt") + "\n", []Finding{{7, "a GitHub token"}}},
		{"github fine-grained", fake("github_fine_grained.txt"), []Finding{{0, "a GitHub token"}}},
		{"github placeholder", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", nil},
		{"slack token", "x: " + fake("slack_bot.txt"), []Finding{{3, "a Slack token"}}},
		{"slack webhook", fake("slack_webhook.txt"), []Finding{{0, "a Slack webhook URL"}}},
		{"slack negatives", "xoxb-my-bot-token xoxb-12345-abcd234 XOxE-RROAmw", nil},
		{"a secret value", "pw: !secret YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBBS0lBUVlMUE1ONUhISEZQWkFNMg==\nother: !secret '" + fake("aws.txt") + "'\n", nil},
		{"age identity", fake("age_identity.txt") + "\n", []Finding{{0, "an age identity"}}},
		{"url password", "repo: " + fake("url_password.txt") + "/app\n", []Finding{{21, "a password in a URL"}}},
		{"url password with a dollar", fake("url_password_dollar.txt"), []Finding{{15, "a password in a URL"}}},
		{"url password from a template", "repo: https://deploy:{{vars.pw}}@git.example.com\n", nil},
		{"url password from a shell variable", "a: https://deploy:$PW@h\nb: https://deploy:${PW}@h\n", nil},
		{"url without a password", "repo: https://deploy@git.example.com\nweb: https://h:8443/a@b\n", nil},
		{"after a secret value", "pw: !secret YWdl\nid: " + fake("aws.txt") + "\n", []Finding{{21, "an AWS access key ID"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Scan([]byte(tt.in)); !slices.Equal(got, tt.want) {
				t.Errorf("Scan = %v, want %v", got, tt.want)
			}
		})
	}
}
