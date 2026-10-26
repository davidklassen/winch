package module

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

// spec: Modules/repo
func TestRepoValidate(t *testing.T) {
	const base = "url: https://rspamd.com/apt-stable\nsuite: trixie\ncomponents: [main]\n"
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"all fields", "name: rspamd\n" + base + "key: https://rspamd.com/apt-stable/gpg.key\n", ""},
		{"no key", "name: backports\nurl: http://deb.debian.org/debian\nsuite: trixie-backports\ncomponents: [main, contrib]\n", ""},
		{"one component", "name: a\nurl: https://example.com/apt\nsuite: trixie\ncomponents: main\n", ""},
		{"flat", "name: a\nurl: https://example.com/apt\nsuite: ./\n", ""},
		{"dots and digits", "name: example.com_2-x\n" + base, ""},
		{"no name", base, `t.yaml:1:1: missing key "name"`},
		{"bad name", "name: a/b\n" + base, `t.yaml:1:7: name: "a/b" is not a source name; a name has letters, digits, "_", "-", and ".", and does not start with "."`},
		{"hidden name", "name: .a\n" + base, `t.yaml:1:7: name: ".a" is not a source name; a name has letters, digits, "_", "-", and ".", and does not start with "."`},
		{"no url", "name: a\nsuite: trixie\ncomponents: [main]\n", `t.yaml:1:1: missing key "url"`},
		{"ftp url", "name: a\nurl: ftp://example.com/apt\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: must start with http:// or https://`},
		{"no host", "name: a\nurl: https:///apt\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: has no host`},
		{"user info", "name: a\nurl: https://u:p@example.com/apt\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: holds a user name or password, and the source file is world-readable; put them in /etc/apt/auth.conf.d/a.conf with mode 0600`},
		{"space in url", "name: a\nurl: https://example.com/a b\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: has white space or a control character`},
		{"control in url", "name: a\nurl: \"https://example.com/a\\x01\"\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: has white space or a control character`},
		{"empty suite", "name: a\nurl: https://example.com/apt\nsuite: \"\"\ncomponents: [main]\n", `t.yaml:3:8: suite: is empty`},
		{"control in component", "name: a\nurl: https://example.com/apt\nsuite: trixie\ncomponents: [\"ma\\x01in\"]\n", `t.yaml:4:13: components: element 1 has white space or a control character`},
		{"space in suite", "name: a\nurl: https://example.com/apt\nsuite: trixie main\ncomponents: [main]\n", `t.yaml:3:8: suite: has white space or a control character`},
		{"newline in suite", "name: a\nurl: https://example.com/apt\nsuite: \"trixie\\nmain\"\ncomponents: [main]\n", `t.yaml:3:8: suite: has white space or a control character`},
		{"space in component", "name: a\nurl: https://example.com/apt\nsuite: trixie\ncomponents: [main, \"non free\"]\n", `t.yaml:4:13: components: element 2 has white space or a control character`},
		{"no components", "name: a\nurl: https://example.com/apt\nsuite: trixie\n", `t.yaml:3:8: suite: needs components, such as [main]; only a flat suite, which ends in "/", has none`},
		{"empty components", "name: a\nurl: https://example.com/apt\nsuite: trixie\ncomponents: []\n", `t.yaml:3:8: suite: needs components, such as [main]; only a flat suite, which ends in "/", has none`},
		{"flat with components", "name: a\nurl: https://example.com/apt\nsuite: ./\ncomponents: [main]\n", `t.yaml:4:13: components: a flat suite, which ends in "/", has no components`},
		{"http key", "name: a\n" + base + "key: http://example.com/key.asc\n", `t.yaml:5:6: key: must start with https://, so the network cannot choose the key`},
		{"space in key", "name: a\n" + base + "key: https://example.com/k ey\n", `t.yaml:5:6: key: has white space or a control character`},
		{"unknown key", "name: a\n" + base + "keyring: x\n", `t.yaml:5:1: unknown key "keyring"`},
		{"absent", "name: a\n" + base + "absent: true\n", `t.yaml:5:1: unknown key "absent"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Repo{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/repo
func TestRepoSource(t *testing.T) {
	tests := []struct {
		name string
		repo Repo
		want string
	}{
		{"key", Repo{Name: "rspamd", URL: "https://rspamd.com/apt-stable", Suite: "trixie", Components: []string{"main", "contrib"}, Key: "https://rspamd.com/apt-stable/gpg.key"},
			"Types: deb\nURIs: https://rspamd.com/apt-stable\nSuites: trixie\nComponents: main contrib\nSigned-By: /etc/apt/keyrings/rspamd.asc\n"},
		{"no key", Repo{Name: "bp", URL: "http://deb.debian.org/debian", Suite: "trixie-backports", Components: []string{"main"}},
			"Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie-backports\nComponents: main\n"},
		{"flat", Repo{Name: "f", URL: "http://example.com/flat", Suite: "./"},
			"Types: deb\nURIs: http://example.com/flat\nSuites: ./\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.repo.source()); got != tt.want {
				t.Errorf("source =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// spec: Modules/repo
func TestParsePGPKey(t *testing.T) {
	tests := []struct {
		file    string
		want    pgpKey
		wantErr string
	}{
		{"key.asc", pgpKey{fingerprint: "08F59DAD86F61D67A6A960698445EE6567433B2C", userID: "winch test key <test@example.com>"}, ""},
		{"rsa.asc", pgpKey{fingerprint: "68211508469BEE79A13385E5EE1E5094B9E465ED", userID: "winch rsa key <rsa@example.com>"}, ""},
		{"key.gpg", pgpKey{}, "is not an ASCII-armored OpenPGP public key"},
		{"signature.asc", pgpKey{}, "is not an ASCII-armored OpenPGP public key"},
		{"revoked.asc", pgpKey{}, "the key 06AC54F1582AD1504107DE2CD1EAA49074573A45 is revoked"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + tt.file)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parsePGPKey(data)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("parsePGPKey = %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestParsePGPKeyBad(t *testing.T) {
	key, err := os.ReadFile("testdata/key.asc")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(key), "\n")
	tests := []struct {
		name, data, want string
	}{
		{"empty", "", "is not an ASCII-armored OpenPGP public key"},
		{"html", "<html>Not found</html>\n", "is not an ASCII-armored OpenPGP public key"},
		{"no end", strings.Join(lines[:4], "\n"), "has no end line"},
		{"bad base64", lines[0] + "\n\n!!!!\n" + "-----END PGP PUBLIC KEY BLOCK-----\n", "is not base64"},
		{"cut packet", lines[0] + "\n\n" + lines[2][:8] + "\n" + "-----END PGP PUBLIC KEY BLOCK-----\n", "ends inside a packet"},
		{"no packets", lines[0] + "\n\n-----END PGP PUBLIC KEY BLOCK-----\n", "holds no public key"},
		// A user ID packet first.
		{"no key packet", lines[0] + "\n\nzQF4\n-----END PGP PUBLIC KEY BLOCK-----\n", "holds no public key"},
		// A new-format key packet with a partial length.
		{"partial length", lines[0] + "\n\nxuA=\n-----END PGP PUBLIC KEY BLOCK-----\n", "a packet of partial length"},
		// A version 6 key packet.
		{"version 6", lines[0] + "\n\nxgEG\n-----END PGP PUBLIC KEY BLOCK-----\n", "the key has version 6; winch reads version 4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePGPKey([]byte(tt.data)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// Some key files have no empty line after the first line, or CRLF line ends.
func TestParsePGPKeyForms(t *testing.T) {
	key, err := os.ReadFile("testdata/key.asc")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"no empty line": strings.Replace(string(key), "\n\n", "\n", 1),
		"headers":       strings.Replace(string(key), "\n\n", "\nComment: winch\n\n", 1),
		"crlf":          strings.ReplaceAll(string(key), "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parsePGPKey([]byte(data))
			if err != nil || got.fingerprint != "08F59DAD86F61D67A6A960698445EE6567433B2C" {
				t.Fatalf("parsePGPKey = %+v, %v", got, err)
			}
		})
	}
}

// spec: Modules/repo
func TestSourceChanges(t *testing.T) {
	const p = "/etc/apt/sources.list.d/a.sources"
	want := "Types: deb\nURIs: https://x.example/apt\nSuites: trixie\nComponents: main\nSigned-By: /etc/apt/keyrings/a.asc\n"
	tests := []struct {
		name, old string
		want      []string
	}{
		{"suite", strings.Replace(want, "trixie", "bookworm", 1), []string{p + ": Suites bookworm → trixie"}},
		{"added key", strings.Replace(want, "Signed-By: /etc/apt/keyrings/a.asc\n", "", 1), []string{p + ": Signed-By (none) → /etc/apt/keyrings/a.asc"}},
		{"two fields", strings.Replace(strings.Replace(want, "trixie", "bookworm", 1), "main", "main contrib", 1), []string{p + ": Suites bookworm → trixie", p + ": Components main contrib → main"}},
		{"another field", strings.Replace(want, "trixie", "bookworm", 1) + "Enabled: no\n", []string{"rewrite " + p}},
		{"two stanzas", strings.Replace(want, "trixie", "bookworm", 1) + "\n" + want, []string{"rewrite " + p}},
		{"white space only", strings.Replace(want, "Types: deb", "Types:  deb", 1), []string{"rewrite " + p}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sourceChanges(p, []byte(tt.old), []byte(want)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sourceChanges = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Modules/repo
func TestFetchKey(t *testing.T) {
	big := strings.Repeat("k", maxDiff+1)
	var agent string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent = r.UserAgent()
		switch r.URL.Path {
		case "/key.asc":
			fmt.Fprint(w, "key")
		case "/big":
			fmt.Fprint(w, big)
		case "/redirect":
			http.Redirect(w, r, "http://"+r.Host+"/key.asc", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := keyClient()
	client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	tests := []struct {
		path, want, wantErr string
	}{
		{"/key.asc", "key", ""},
		{"/missing", "", "404 Not Found"},
		{"/big", "", "larger than 1 MiB"},
		{"/redirect", "", "which is not https"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := fetchKey(t.Context(), client, srv.URL+tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("fetchKey = %q, %v", got, err)
			}
			if agent != "winch" {
				t.Errorf("user agent = %q, want winch", agent)
			}
		})
	}
}

func TestParseSources(t *testing.T) {
	deb822 := `# Debian
Types: deb deb-src
URIs: https://a.example/debian/ https://b.example/debian
Suites: trixie trixie-updates
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mDMEat+KcBYJKwYBBAHaRw8BAQdA
 -----END PGP PUBLIC KEY BLOCK-----

Types: deb
URIs: https://c.example/
# a comment in a stanza
Suites: stable
Components: main
Enabled: no

Types: deb
URIs: https://d.example/
Suites: stable
Enabled: yes

Types: deb
Suites: broken
`
	list := `deb [signed-by=/usr/share/keyrings/docker.gpg arch=amd64] https://download.docker.com/linux/debian trixie stable
# deb http://x.example/ y main
deb-src [ arch=amd64 ] http://deb.debian.org/debian trixie main

garbage
deb [arch=amd64 http://broken.example/ trixie main
`
	tests := []struct {
		name, file, data string
		want             []source
	}{
		{"deb822", "a.sources", deb822, []source{
			{uris: []string{"https://a.example/debian/", "https://b.example/debian"}, suites: []string{"trixie", "trixie-updates"}},
			{uris: []string{"https://d.example/"}, suites: []string{"stable"}},
		}},
		{"one-line", "a.list", list, []source{
			{uris: []string{"https://download.docker.com/linux/debian"}, suites: []string{"trixie"}},
			{uris: []string{"http://deb.debian.org/debian"}, suites: []string{"trixie"}},
		}},
		{"empty", "a.sources", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSources(tt.file, []byte(tt.data)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSources =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func TestSourceHas(t *testing.T) {
	s := source{uris: []string{"https://a.example/debian/", "https://b.example/debian"}, suites: []string{"trixie", "trixie-updates"}}
	tests := []struct {
		uri, suite string
		want       bool
	}{
		{"https://a.example/debian/", "trixie", true},
		{"https://a.example/debian", "trixie", true},
		{"https://b.example/debian//", "trixie-updates", true},
		{"https://a.example/debian", "bookworm", false},
		{"http://a.example/debian", "trixie", false},
		{"https://a.example/", "trixie", false},
	}
	for _, tt := range tests {
		if got := s.has(tt.uri, tt.suite); got != tt.want {
			t.Errorf("has(%q, %q) = %v, want %v", tt.uri, tt.suite, got, tt.want)
		}
	}
}
