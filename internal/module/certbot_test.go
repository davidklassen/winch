package module

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// spec: Modules/certbot
func TestCertbotValidate(t *testing.T) {
	const base = "name: example.com\ndomains: [example.com, www.example.com]\nemail: admin@example.com\n"
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"nginx by default", base, ""},
		{"one domain", "name: mail\ndomains: mail.example.com\nemail: a@example.com\n", ""},
		{"a single label", "name: demo\ndomains: [demo]\nemail: a@example.com\n", ""},
		{"apache", base + "authenticator: apache\n", ""},
		{"standalone with hooks", base + "authenticator: standalone\npre_hook: systemctl stop nginx\npost_hook: systemctl start nginx\n", ""},
		{"webroot", base + "authenticator: webroot\nwebroot_path: /var/www/html\n", ""},
		{"all", base + "deploy_hook: systemctl reload nginx\nreuse_key: true\n", ""},
		{"no name", "domains: [a.example.com]\nemail: a@example.com\n", `t.yaml:1:1: missing key "name"`},
		{"no domains", "name: a\nemail: a@example.com\n", `t.yaml:1:1: missing key "domains"`},
		{"no email", "name: a\ndomains: [a.example.com]\n", `t.yaml:1:1: missing key "email"`},
		{"name with a slash", "name: a/b\ndomains: [a.example.com]\nemail: a@example.com\n", `t.yaml:1:7: name: "a/b" is not a certificate name: letters, digits, ., _, and -, starting with a letter or digit`},
		{"name ..", "name: ..\ndomains: [a.example.com]\nemail: a@example.com\n", `t.yaml:1:7: name: ".." is not a certificate name: letters, digits, ., _, and -, starting with a letter or digit`},
		{"empty domains", "name: a\ndomains: []\nemail: a@example.com\n", `t.yaml:2:10: domains: needs at least one domain`},
		{"upper case", "name: a\ndomains: [Example.com]\nemail: a@example.com\n", `t.yaml:2:10: domains: "Example.com" is not a domain name such as example.com; certbot takes lowercase names`},
		{"bad domain", "name: a\ndomains: [a..example.com]\nemail: a@example.com\n", `t.yaml:2:10: domains: "a..example.com" is not a domain name such as example.com; certbot takes lowercase names`},
		{"long label", "name: a\ndomains: [" + strings.Repeat("a", 64) + ".com]\nemail: a@example.com\n", `t.yaml:2:10: domains: "` + strings.Repeat("a", 64) + `.com" is not a domain name such as example.com; certbot takes lowercase names`},
		{"long name", "name: a\ndomains: [" + strings.Repeat("a.", 127) + "com]\nemail: a@example.com\n", `t.yaml:2:10: domains: "` + strings.Repeat("a.", 127) + `com" is longer than 253 characters`},
		{"wildcard", "name: a\ndomains: [\"*.example.com\"]\nemail: a@example.com\n", `t.yaml:2:10: domains: "*.example.com" is a wildcard, which needs a DNS challenge; the nginx, apache, standalone, and webroot authenticators answer only HTTP challenges`},
		{"repeated domain", "name: a\ndomains: [a.example.com, a.example.com]\nemail: a@example.com\n", `t.yaml:2:10: domains: a.example.com is in the list twice`},
		{"bad email", "name: a\ndomains: [a.example.com]\nemail: admin\n", `t.yaml:3:8: email: "admin" is not an email address`},
		{"email with a space", "name: a\ndomains: [a.example.com]\nemail: a b@example.com\n", `t.yaml:3:8: email: "a b@example.com" is not an email address`},
		{"unknown authenticator", base + "authenticator: dns\n", `t.yaml:4:16: authenticator: "dns" is not an authenticator; use nginx, apache, standalone, or webroot`},
		{"webroot without path", base + "authenticator: webroot\n", `t.yaml:4:16: authenticator: webroot needs webroot_path`},
		{"path without webroot", base + "webroot_path: /var/www/html\n", `t.yaml:4:15: webroot_path: needs authenticator: webroot`},
		{"relative path", base + "authenticator: webroot\nwebroot_path: var/www\n", `t.yaml:5:15: webroot_path: must be an absolute path`},
		{"path with a comma", base + "authenticator: webroot\nwebroot_path: /var/www/a,b\n", `t.yaml:5:15: webroot_path: has a ",", which certbot reads as a list`},
		{"empty hook", base + "deploy_hook: \"\"\n", `t.yaml:4:14: deploy_hook: is empty`},
		{"empty pre_hook", base + "pre_hook: \"\"\n", `t.yaml:4:11: pre_hook: is empty`},
		{"empty post_hook", base + "post_hook: \"\"\n", `t.yaml:4:12: post_hook: is empty`},
		{"unknown key", base + "reuse-key: true\n", `t.yaml:4:1: unknown key "reuse-key"; did you mean "reuse_key"?`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Certbot{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/certbot (the check reads the renewal file)
func TestParseConfobj(t *testing.T) {
	data := `# renew_before_expiry = 30 days
version = 4.0.0
cert = /etc/letsencrypt/live/a/cert.pem

# Options used in the renewal process
[renewalparams]
reuse_key = True
renew_hook = 'echo "x, y # z" >> /root/hook'
pre_hook = '''echo pre
echo two'''
post_hook = "it's # here"
a = '''it's "x"'''
b = " lead"
c = plain value   # a comment
webroot_path = /var/www/html,
two = /a, "/b c"
k = tab	here
l = x\y
empty = ""
one = '''one line'''
space = '''first line 
second'''
[[webroot_map]]
a.example.com = /var/www/html
`
	got, err := parseConfobj([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	one := func(s string) []string { return []string{s} }
	want := map[string]map[string][]string{
		"": {
			"version": one("4.0.0"),
			"cert":    one("/etc/letsencrypt/live/a/cert.pem"),
		},
		"renewalparams": {
			"reuse_key":    one("True"),
			"renew_hook":   one(`echo "x, y # z" >> /root/hook`),
			"pre_hook":     one("echo pre\necho two"),
			"post_hook":    one("it's # here"),
			"a":            one(`it's "x"`),
			"b":            one(" lead"),
			"c":            one("plain value"),
			"webroot_path": {"/var/www/html"},
			"two":          {"/a", "/b c"},
			"k":            one("tab\there"),
			"l":            one(`x\y`),
			"empty":        one(""),
			"one":          one("one line"),
			"space":        one("first line \nsecond"),
		},
		"webroot_map": {
			"a.example.com": one("/var/www/html"),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// spec: Modules/certbot
func TestParseConfobjErrors(t *testing.T) {
	for _, data := range []string{
		"a = '''never closed\nmore\n",
		"a = 'unclosed\n",
		"[renewalparams\n",
		"no equals sign\n",
		"a = 'x' trailing\n",
	} {
		if _, err := parseConfobj([]byte(data)); err == nil {
			t.Errorf("parseConfobj(%q): no error", data)
		}
	}
}

// spec: Modules/certbot; Running a pipeline/Plan (a change lists the defaults)
func TestCertbotChanges(t *testing.T) {
	c := &Certbot{Name: "example.com", Domains: []string{"example.com", "www.example.com"}, Email: "a@example.com", DeployHook: new("systemctl reload nginx")}
	same := &certState{
		domains:  []string{"www.example.com", "example.com"},
		settings: map[string]string{"authenticator": "nginx", "deploy_hook": "systemctl reload nginx", "reuse_key": "false"},
	}
	tests := []struct {
		name string
		c    *Certbot
		cur  *certState
		want []string
	}{
		{"new", c, nil, []string{"domains example.com, www.example.com", "authenticator nginx", "deploy_hook systemctl reload nginx"}},
		{
			"new with every setting",
			&Certbot{Name: "a", Domains: []string{"a.example.com"}, Email: "a@example.com", Authenticator: "webroot", WebrootPath: "/var/www", PreHook: new("a"), PostHook: new("b\nc"), DeployHook: new("d"), ReuseKey: true},
			nil,
			[]string{"domains a.example.com", "authenticator webroot", "webroot_path /var/www", "pre_hook a", "post_hook\nb\nc", "deploy_hook d", "reuse_key true"},
		},
		{"the same domains in another order", c, same, nil},
		{
			"a new domain",
			&Certbot{Name: "example.com", Domains: []string{"example.com", "www.example.com", "mta-sts.example.com"}, Email: "a@example.com", DeployHook: new("systemctl reload nginx")},
			same,
			[]string{"domains www.example.com, example.com → example.com, www.example.com, mta-sts.example.com", "issue the certificate again, with a new key; run deploy_hook"},
		},
		{
			"an installer",
			&Certbot{Name: "example.com", Domains: []string{"example.com", "www.example.com"}, Email: "a@example.com"},
			&certState{domains: same.domains, settings: map[string]string{"authenticator": "nginx", "installer": "nginx", "reuse_key": "false"}},
			[]string{"installer nginx → (none)", "issue the certificate again, with a new key"},
		},
		{
			"a hook of several lines",
			&Certbot{Name: "example.com", Domains: []string{"example.com", "www.example.com"}, Email: "a@example.com", DeployHook: new("systemctl reload nginx\nsystemctl reload dovecot")},
			same,
			[]string{"deploy_hook systemctl reload nginx →\nsystemctl reload nginx\nsystemctl reload dovecot", "issue the certificate again, with a new key; run deploy_hook"},
		},
		{
			"every setting changes",
			&Certbot{Name: "example.com", Domains: []string{"example.com", "www.example.com"}, Email: "a@example.com", Authenticator: "standalone", PreHook: new("systemctl stop nginx"), PostHook: new("systemctl start nginx"), ReuseKey: true},
			&certState{domains: same.domains, settings: map[string]string{"authenticator": "webroot", "webroot_path": "/var/www", "deploy_hook": "systemctl reload nginx", "reuse_key": "false"}},
			[]string{
				"authenticator webroot → standalone",
				"webroot_path /var/www → (none)",
				"pre_hook (none) → systemctl stop nginx",
				"post_hook (none) → systemctl start nginx",
				"deploy_hook systemctl reload nginx → (none)",
				"reuse_key false → true",
				"issue the certificate again, with the same key; run pre_hook, post_hook",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.changes(tt.cur); !slices.Equal(got, tt.want) {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// writeCert writes a self-signed certificate for names to path.
func writeCert(t *testing.T, path string, notAfter time.Time, names ...string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// spec: Modules/certbot (the check reads the renewal file of name)
func TestReadCertState(t *testing.T) {
	dir := t.TempDir()
	if cur, err := readCertState(dir, "a"); err != nil || cur != nil {
		t.Fatalf("no renewal file: %v, %v; want nil, nil", cur, err)
	}
	cert := filepath.Join(dir, "live", "a", "cert.pem")
	conf := "cert = " + cert + `
[renewalparams]
authenticator = webroot
webroot_path = /var/www,
renew_hook = 'echo "x" >> /root/hook'
reuse_key = True
installer = None
server = https://localhost:14000/dir
[[webroot_map]]
a.example.com = /var/www
`
	if err := os.MkdirAll(filepath.Join(dir, "renewal"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "renewal", "a.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	want := &certState{settings: map[string]string{"authenticator": "webroot", "webroot_path": "/var/www", "deploy_hook": `echo "x" >> /root/hook`, "reuse_key": "true"}}
	cur, err := readCertState(dir, "a")
	if err != nil || !reflect.DeepEqual(cur, want) {
		t.Fatalf("no certificate: %+v, %v; want %+v", cur, err, want)
	}
	notAfter := time.Now().Add(time.Hour).Truncate(time.Second).UTC()
	writeCert(t, cert, notAfter, "a.example.com", "b.example.com")
	want.domains, want.notAfter = []string{"a.example.com", "b.example.com"}, notAfter
	cur, err = readCertState(dir, "a")
	if err != nil || !reflect.DeepEqual(cur, want) {
		t.Errorf("got %+v, %v; want %+v", cur, err, want)
	}
	if err := os.WriteFile(filepath.Join(dir, "renewal", "a.conf"), []byte(strings.Replace(conf, "installer = None", "installer = nginx", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	want.settings["installer"] = "nginx"
	cur, err = readCertState(dir, "a")
	if err != nil || !reflect.DeepEqual(cur, want) {
		t.Errorf("an installer: %+v, %v; want %+v", cur, err, want)
	}
	if err := os.WriteFile(cert, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCertState(dir, "a"); err == nil || !strings.Contains(err.Error(), cert) {
		t.Errorf("a bad certificate: %v, want an error that names %s", err, cert)
	}
}

// spec: Modules/certbot (a renewal file without its certificate)
func TestCertbotCheckBrokenLineage(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "renewal"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "cert = " + filepath.Join(dir, "live", "a", "cert.pem") + "\n[renewalparams]\nauthenticator = nginx\n"
	if err := os.WriteFile(filepath.Join(dir, "renewal", "a.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Certbot{Name: "a", Domains: []string{"a.example.com"}, Email: "a@example.com"}
	want := "certificate a: " + filepath.Join(dir, "renewal", "a.conf") + " exists, but its certificate does not; certbot would make a new certificate a-0001 on each run; certbot delete --cert-name a removes the rest"
	if _, err := c.check(dir, func(string) {}); err == nil || err.Error() != want {
		t.Errorf("got %v\nwant %s", err, want)
	}
}

// spec: Modules/certbot (an expiring certificate gives a plan note)
func TestCertbotCheckExpiry(t *testing.T) {
	day := 24 * time.Hour
	for _, tt := range []struct {
		name string
		left time.Duration
		note bool
	}{
		{"expired", -day, true},
		{"in 3 days", 3 * day, true},
		{"in 13 days", 13 * day, true},
		{"in 15 days", 15 * day, false},
		{"in 60 days", 60 * day, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cert := filepath.Join(dir, "live", "a", "cert.pem")
			notAfter := time.Now().Add(tt.left)
			writeCert(t, cert, notAfter, "a.example.com")
			if err := os.MkdirAll(filepath.Join(dir, "renewal"), 0o755); err != nil {
				t.Fatal(err)
			}
			conf := "cert = " + cert + "\n[renewalparams]\nauthenticator = nginx\n"
			if err := os.WriteFile(filepath.Join(dir, "renewal", "a.conf"), []byte(conf), 0o644); err != nil {
				t.Fatal(err)
			}
			c := &Certbot{Name: "a", Domains: []string{"a.example.com"}, Email: "a@example.com"}
			var notes []string
			res, err := c.check(dir, func(s string) { notes = append(notes, s) })
			if err != nil || res.Status != OK {
				t.Fatalf("got %+v, %v; want ok", res, err)
			}
			var want []string
			switch {
			case tt.left < 0:
				want = []string{"the certificate a expired on " + notAfter.UTC().Format(time.DateOnly) + "; check its renewal"}
			case tt.note:
				want = []string{"the certificate a expires on " + notAfter.UTC().Format(time.DateOnly) + "; check its renewal"}
			}
			if !slices.Equal(notes, want) {
				t.Errorf("notes %q, want %q", notes, want)
			}
		})
	}
	t.Run("no certificate", func(t *testing.T) {
		c := &Certbot{Name: "a", Domains: []string{"a.example.com"}, Email: "a@example.com"}
		var notes []string
		res, err := c.check(t.TempDir(), func(s string) { notes = append(notes, s) })
		if err != nil || res.Action != Create || notes != nil {
			t.Errorf("got %+v, %v, notes %q; want a create without notes", res, err, notes)
		}
	})
}

// spec: Modules/certbot
func TestCertbotArgs(t *testing.T) {
	base := []string{"certonly", "--non-interactive", "--agree-tos", "--no-eff-email", "--email=a@example.com", "--cert-name=example.com", "--domains=example.com,www.example.com"}
	tests := []struct {
		name string
		c    *Certbot
		want []string
	}{
		{
			"nginx by default",
			&Certbot{Name: "example.com", Domains: []string{"example.com", "www.example.com"}, Email: "a@example.com"},
			slices.Concat(base, []string{"--authenticator=nginx", "--force-renewal"}),
		},
		{
			"webroot with everything",
			&Certbot{Name: "example.com", Domains: []string{"example.com", "www.example.com"}, Email: "a@example.com", Authenticator: "webroot", WebrootPath: "/var/www", PreHook: new("a b"), PostHook: new("-c"), DeployHook: new("d\ne"), ReuseKey: true},
			slices.Concat(base, []string{"--authenticator=webroot", "--webroot-path=/var/www", "--pre-hook=sh -ec 'a b'", "--post-hook=sh -ec '-c'", "--deploy-hook=sh -ec 'd\ne'", "--reuse-key", "--force-renewal"}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.args(); !slices.Equal(got, tt.want) {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// spec: Modules/certbot (a failing hook fails the step)
func TestHookFailure(t *testing.T) {
	ok := "Saving debug log to /var/log/letsencrypt/letsencrypt.log\nRenewing an existing certificate for a.example.com\n\nSuccessfully received certificate.\n"
	if err := hookFailure(ok); err != nil {
		t.Errorf("no hook failed: %v", err)
	}
	stderr := "Hook 'deploy-hook' ran with error output:\n Job for nginx.service is a warning.\n\nSuccessfully received certificate.\n"
	if err := hookFailure(stderr); err != nil {
		t.Errorf("a hook that wrote to stderr and succeeded: %v", err)
	}
	failed := "Saving debug log to /var/log/letsencrypt/letsencrypt.log\nHook 'pre-hook' reported error code 1\nRenewing an existing certificate for a.example.com\nHook 'deploy-hook' reported error code 3\nHook 'deploy-hook' ran with error output:\n oops\n two\n\nSuccessfully received certificate.\n"
	want := "a hook failed:\nHook 'pre-hook' reported error code 1\nHook 'deploy-hook' reported error code 3\nHook 'deploy-hook' ran with error output:\n oops\n two"
	if err := hookFailure(failed); err == nil || err.Error() != want {
		t.Errorf("got %v\nwant %s", err, want)
	}
}

// spec: Modules/certbot (pending hooks)
func TestPendingHooks(t *testing.T) {
	const (
		deployFailed = "Hook 'deploy-hook' reported error code 3\nHook 'deploy-hook' ran with error output:\n Hook 'post-hook' reported error code 9\n"
		postFailed   = "Some challenges have failed.\nHook 'post-hook' reported error code 1\n"
		challenge    = "Certbot failed to authenticate some domains (authenticator: webroot).\nSome challenges have failed.\n"
	)
	for _, tt := range []struct {
		name    string
		pending []string
		out     string
		ok      bool
		want    []string
	}{
		{"success", nil, "Successfully received certificate.\n", true, nil},
		{"a failed challenge", nil, challenge, false, nil},
		{"a failed deploy_hook", nil, deployFailed, true, []string{"deploy_hook"}},
		{"a failed post_hook after a failed challenge", nil, postFailed, false, []string{"post_hook"}},
		{"pending hooks that ran", []string{"deploy_hook", "post_hook"}, "Successfully received certificate.\n", true, nil},
		{"pending hooks after a failed challenge", []string{"deploy_hook", "post_hook"}, challenge, false, []string{"deploy_hook", "post_hook"}},
		{"a pending hook that fails again", []string{"post_hook"}, postFailed, true, []string{"post_hook"}},
		{"deploy_hook comes before post_hook", []string{"post_hook"}, "Hook 'post-hook' reported error code 1\nHook 'deploy-hook' reported error code 1\n", true, []string{"deploy_hook", "post_hook"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := pendingHooks(tt.pending, tt.out, tt.ok); !slices.Equal(got, tt.want) {
				t.Errorf("pendingHooks = %v, want %v", got, tt.want)
			}
		})
	}
}

// spec: Modules/certbot (compare hooks as the step gives them)
func TestCertbotWrappedHooks(t *testing.T) {
	for _, key := range []string{"pre_hook", "post_hook", "deploy_hook"} {
		for _, saved := range []string{"echo 'hello'\ntrue", "sh -ec 'echo '\"'\"'hello'\"'\"'\ntrue'"} {
			t.Run(key+"/"+saved, func(t *testing.T) {
				command := "echo 'hello'\ntrue"
				c := &Certbot{Name: "example.com", Domains: []string{"example.com"}, Email: "a@example.com"}
				switch key {
				case "pre_hook":
					c.PreHook = &command
				case "post_hook":
					c.PostHook = &command
				case "deploy_hook":
					c.DeployHook = &command
				}
				cur := &certState{domains: c.Domains, settings: map[string]string{"authenticator": "nginx", "reuse_key": "false", key: saved}}
				if got := c.changes(cur); len(got) != 0 {
					t.Errorf("same hook: changes %q", got)
				}
				command = "echo changed\ntrue"
				if got := c.changes(cur); len(got) == 0 {
					t.Error("changed hook was ignored")
				}
			})
		}
	}
}

// spec: Modules/certbot (the check reads the renewal file)
func TestParseConfobjClosingQuotes(t *testing.T) {
	for _, q := range []string{"'", `"`} {
		for _, tail := range []string{q, q + q} {
			t.Run(q+tail, func(t *testing.T) {
				want := "sh -ec 'echo one\necho two" + tail
				data := "hook = " + strings.Repeat(q, 3) + want + strings.Repeat(q, 3) + " # comment with " + strings.Repeat(q, 3) + "\n"
				got, err := parseConfobj([]byte(data))
				if err != nil {
					t.Fatal(err)
				}
				if v := got[""]["hook"]; len(v) != 1 || v[0] != want {
					t.Errorf("got %q, want %q", v, want)
				}
			})
		}
	}
}

// spec: Modules/certbot (compare hooks as the step gives them)
func TestCertbotWrappedHookChanges(t *testing.T) {
	for _, tt := range []struct {
		name string
		hook *string
		want string
	}{
		{"later line", new("echo one\necho new"), "deploy_hook echo one ... →\necho one\necho new"},
		{"first line", new("echo new\necho old"), "deploy_hook echo one ... →\necho new\necho old"},
		{"removed hook", nil, "deploy_hook echo one ... → (none)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Certbot{Name: "example.com", Domains: []string{"example.com"}, Email: "a@example.com", DeployHook: tt.hook}
			cur := &certState{domains: c.Domains, settings: map[string]string{"authenticator": "nginx", "reuse_key": "false", "deploy_hook": "sh -ec 'echo one\necho old'"}}
			if got := c.changes(cur); len(got) == 0 || got[0] != tt.want {
				t.Errorf("changes %q, want first line %q", got, tt.want)
			}
		})
	}
}

func TestUnwrappedCertbotHook(t *testing.T) {
	for _, hook := range []string{"echo raw", "sh -ec '", "sh -ec ''", "sh -ec 'true'; echo 'extra'"} {
		if got := unwrappedCertbotHook(hook); got != hook {
			t.Errorf("unwrapped %q as %q", hook, got)
		}
	}
}

// spec: Modules/certbot (existing matching hooks stay as stored)
func TestCertbotMatchingLiteralWrapper(t *testing.T) {
	hook := "sh -ec 'true'"
	c := &Certbot{Name: "example.com", Domains: []string{"example.com"}, Email: "a@example.com", DeployHook: &hook}
	cur := &certState{domains: c.Domains, settings: map[string]string{"authenticator": "nginx", "reuse_key": "false", "deploy_hook": hook}}
	if got := c.changes(cur); len(got) != 0 {
		t.Errorf("matching literal hook: changes %q", got)
	}
}

// spec: Modules/certbot
func TestCertbotPendingHookOrder(t *testing.T) {
	log := filepath.Join(t.TempDir(), "hooks")
	t.Setenv("WINCH_HOOK_LOG", log)
	c := &Certbot{
		Name: "order", PendingHooks: []string{"post_hook"}, issue: true,
		DeployHook: new(`echo deploy >> "$WINCH_HOOK_LOG"`),
		PostHook:   new(`echo post >> "$WINCH_HOOK_LOG"`),
	}
	if got, want := c.HooksToRun(), []string{"deploy_hook", "post_hook"}; !slices.Equal(got, want) {
		t.Errorf("hooks to run = %v, want %v", got, want)
	}
	if want := []string{"post_hook"}; !slices.Equal(c.PendingHooks, want) {
		t.Errorf("pending after HooksToRun = %v, want %v", c.PendingHooks, want)
	}
	c.PendingHooks, c.issue = []string{"deploy_hook", "post_hook"}, false
	if err := c.Apply(t.Context(), Silent{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "deploy\npost\n" {
		t.Errorf("retry order = %q, want deploy then post", got)
	}
}

// spec: Modules/certbot (hooks round-trip through the renewal file)
func TestCertbotHookRoundTrip(t *testing.T) {
	// Each line is what configobj writes for the wrapped command.
	for _, tt := range []struct{ command, line string }{
		{"test \"$X\" = '' || systemctl reload nginx", "renew_hook = '''sh -ec 'test '\\\"'$X'\\\"' = '\"'\"''\"'\"' || systemctl reload nginx''''\n"},
		{"test $X = '' || true", "renew_hook = '''sh -ec 'test $X = '\"'\"''\"'\"' || true''''\n"},
		{"echo '''", "renew_hook = '''sh -ec 'echo '\"'\"''\"'\"''\"'\"'''''\n"},
		{"echo one\ntest \"$X\" = '' || echo 'two'\necho three", "renew_hook = '''sh -ec 'echo one\ntest '\\\"'$X'\\\"' = '\"'\"''\"'\"' || echo '\"'\"'two'\"'\"'\necho three''''\n"},
		{"x\ny = ''  # c\nz", "renew_hook = '''sh -ec 'x\ny = '\"'\"''\"'\"'  # c\nz''''\n"},
		{"echo \"x\"", "renew_hook = '''sh -ec 'echo '\\\"'x'\\\"'''''\n"},
		{"python3 -c \"\"\"\nprint(1)\"\"\"\necho ''", "renew_hook = '''sh -ec 'python3 -c '\\\"''\\\"''\\\"'\nprint(1)'\\\"''\\\"''\\\"'\necho '\"'\"''\"'\"'''''\n"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			got, err := parseConfobj([]byte(tt.line))
			if err != nil {
				t.Fatal(err)
			}
			v := got[""]["renew_hook"]
			if len(v) != 1 || v[0] != certbotHook(tt.command) {
				t.Fatalf("read %q, wrote %q", v, certbotHook(tt.command))
			}
			if c := unwrappedCertbotHook(v[0]); c != tt.command {
				t.Errorf("unwrapped %q, want %q", c, tt.command)
			}
		})
	}
}

// spec: Modules/certbot (the check reads the renewal file)
func TestParseConfobjTripleQuotes(t *testing.T) {
	// configobj reads each line to this value.
	for _, tt := range []struct{ line, want string }{
		{"h = '''sh -ec 'test \"$X\" = '\\'''\\'' || systemctl reload nginx''''", "sh -ec 'test \"$X\" = '\\'''\\'' || systemctl reload nginx'"},
		{"h = '''sh -ec 'a\nb = '\\'''\\''''''", "sh -ec 'a\nb = '\\'''\\'''"},
		{"h = \"\"\"sh -ec 'echo \"\"\"'\"\"\"", "sh -ec 'echo \"\"\"'"},
		{"h = '''a'''' # x '''", "a'"},
		{"h = '''a\nb''''  # x", "a\nb'"},
	} {
		got, err := parseConfobj([]byte(tt.line))
		if err != nil {
			t.Errorf("parseConfobj(%q): %v", tt.line, err)
			continue
		}
		if v := got[""]["h"]; len(v) != 1 || v[0] != tt.want {
			t.Errorf("parseConfobj(%q) = %q, want %q", tt.line, v, tt.want)
		}
	}
	for _, line := range []string{"h = '''a''' b'''x", "h = '''a\nb''' c\nd'''"} {
		if _, err := parseConfobj([]byte(line)); err == nil {
			t.Errorf("parseConfobj(%q): no error", line)
		}
	}
}

// spec: CLI/Messages
func TestCertbotApplyMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	c := &Certbot{Name: "example.com", Domains: []string{"example.com"}, Email: "a@example.com", issue: true}
	err := c.Apply(t.Context(), Silent{})
	if want := "certbot is missing; install the package certbot in an earlier pkg step"; err == nil || err.Error() != want {
		t.Errorf("got %v, want %s", err, want)
	}
}
