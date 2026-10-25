package secret

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"text/template"
	"unicode/utf8"

	"github.com/davidklassen/winch/internal/diff"
)

// spec: Variables/Secrets in output (two evaluations)
func TestPlaceholders(t *testing.T) {
	a, b := Placeholder(1), Placeholder(2)
	if a == "" || b == "" || len(a) == len(b) {
		t.Fatalf("placeholders %q and %q: want two of different lengths", a, b)
	}
	if strings.ContainsAny(a, b) {
		t.Errorf("placeholders %q and %q share characters", a, b)
	}
	if strings.ContainsAny(a+b, Mark+"\n") {
		t.Errorf("placeholders share characters with %q or hold a newline", Mark)
	}
}

// spec: Variables/Secrets in output (two evaluations)
func TestMask(t *testing.T) {
	a, b := Placeholder(1), Placeholder(2)
	tests := []struct {
		real, a, b string
		shown      string
		part       string
	}{
		{"allow monit:hunter2\n", "allow monit:" + a + "\n", "allow monit:" + b + "\n", "allow monit:(secret)\n", "hunter2"},
		{"no secret", "no secret", "no secret", "no secret", ""},
		{"n=8", "n=8", "n=9", "n=(secret)", "8"},
		{"strong", "weak", "weak", "(secret)", "strong"},
		{"pre x mid y post", "pre " + a + " mid " + a + " post", "pre " + b + " mid " + b + " post", "pre (secret) post", "x mid y"},
		{"", a, b, "(secret)", ""},
	}
	for _, tt := range tests {
		shown, part := Mask(tt.real, tt.a, tt.b)
		if shown != tt.shown || part != tt.part {
			t.Errorf("Mask(%q) = %q, %q; want %q, %q", tt.real, shown, part, tt.shown, tt.part)
		}
	}
}

// spec: Variables/Secrets in output (secret variables, two evaluations)
func TestParts(t *testing.T) {
	a, b := Placeholder(1), Placeholder(2)
	real := map[string]any{"alice": "$6$aaa$hash", "port": 8080, "on": true, "list": []any{"one-x", "two"}, "text": "a\nkey-line\nb"}
	alt := func(p string) any {
		return map[string]any{"alice": p, "port": p, "on": true, "list": []any{"one-" + p, "two"}, "text": "a\n" + p + "\nb"}
	}
	got := Parts(real, alt(a), alt(b))
	want := []string{"$6$aaa$hash", "x", "8080", "key-line"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parts = %q, want %q", got, want)
	}
	if got := Parts(real, real, real); got != nil {
		t.Errorf("Parts of equal values = %q", got)
	}
	if got := Parts([]any{"secret-1", "secret-2"}, []any{a}, []any{b}); !reflect.DeepEqual(got, []string{"secret-1", "secret-2"}) {
		t.Errorf("Parts of lists of other lengths = %q", got)
	}
}

// sec is a secret in the test data.
type sec string

// variant returns data with each secret replaced: 0 keeps the real value.
func variant(data any, n int) any {
	switch d := data.(type) {
	case sec:
		if n == 0 {
			return string(d)
		}
		return Placeholder(n)
	case map[string]any:
		m := map[string]any{}
		for k, v := range d {
			m[k] = variant(v, n)
		}
		return m
	}
	return data
}

func render(t testing.TB, tpl string, data any) []byte {
	t.Helper()
	tmpl, err := template.New("t").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"b64":   func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	}).Parse(tpl)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := tmpl.Execute(&out, data); err != nil {
		t.Fatal(err)
	}
	return []byte(out.String())
}

// maskedDiff renders the old content on the host and the new content three
// times, and returns the masked diff, and the diff after the text filter,
// which knows the new secrets.
func maskedDiff(t testing.TB, oldTpl, newTpl string, oldData, newData any) (string, string) {
	t.Helper()
	lines, ok := Lines(render(t, newTpl, variant(newData, 0)), render(t, newTpl, variant(newData, 1)), render(t, newTpl, variant(newData, 2)))
	if !ok {
		return Mark + "\n", Mark + "\n"
	}
	f := NewFilter()
	for _, s := range secrets(newData) {
		f.Add(s)
	}
	d := string(Diff(render(t, oldTpl, variant(oldData, 0)), lines))
	return d, f.Text(d)
}

func secrets(data any) []string {
	switch d := data.(type) {
	case sec:
		return []string{string(d)}
	case map[string]any:
		var out []string
		for _, v := range d {
			out = append(out, secrets(v)...)
		}
		return out
	}
	return nil
}

// spec: Variables/Secrets in output (two evaluations, file diffs)
func TestMaskedDiff(t *testing.T) {
	pemOld := fakeSecret(t, "pem_old.txt") + "\n"
	pemNew := fakeSecret(t, "pem_new.txt") + "\n"
	monit := "set httpd unixsocket /run/monit.sock\n  allow monit:{{ .pw }}\nset ssl { verify: enable }\n"
	users := "{{ range $user, $hash := .users }}{{ $user }}@example.com:{{ $hash }}\n{{ end }}"
	keys := "{{ range $k, $v := .m }}{{ $k }}={{ $v }}\n{{ end }}"
	pw := func(s string) any { return map[string]any{"pw": sec(s)} }
	plain := func(s string) any { return map[string]any{"pw": s} }
	tests := []struct {
		name             string
		oldTpl, newTpl   string
		oldData, newData any
		// want is the diff before the text filter.
		want string
		// shows is a value that the output holds: the known gap.
		shows string
	}{
		{name: "rotate a password", oldTpl: monit, newTpl: monit, oldData: pw("oldpass123"), newData: pw("n3wPa55!"), want: `@@ -1,3 +1,3 @@
 set httpd unixsocket /run/monit.sock
-  allow monit:(secret)
+  allow monit:(secret) (secret value changed)
 set ssl { verify: enable }
`},
		{name: "unrelated change in a file with a secret", oldTpl: monit, newTpl: strings.Replace(monit, "enable", "disable", 1), oldData: pw("same-pass"), newData: pw("same-pass"), want: `@@ -1,3 +1,3 @@
 set httpd unixsocket /run/monit.sock
   allow monit:(secret)
-set ssl { verify: enable }
+set ssl { verify: disable }
`},
		{name: "rotate and change the same line", oldTpl: monit, newTpl: strings.Replace(monit, "allow monit:{{ .pw }}", "allow admin:{{ .pw }} read-only", 1), oldData: pw("oldpass123"), newData: pw("n3wPa55!"), want: `@@ -1,3 +1,3 @@
 set httpd unixsocket /run/monit.sock
-(line hidden: may hold a secret)
+  allow admin:(secret) read-only
 set ssl { verify: enable }
`},
		{name: "delete the secret line, same secret", oldTpl: monit, newTpl: strings.Replace(monit, "  allow monit:{{ .pw }}\n", "", 1), oldData: pw("same-pass"), newData: pw("same-pass"), want: `@@ -1,3 +1,2 @@
 set httpd unixsocket /run/monit.sock
-  allow monit:same-pass
 set ssl { verify: enable }
`},
		{name: "delete the secret line and rotate", oldTpl: monit, newTpl: strings.Replace(monit, "  allow monit:{{ .pw }}\n", "", 1), oldData: pw("oldpass123"), newData: pw("n3wPa55!"), want: `@@ -1,3 +1,2 @@
 set httpd unixsocket /run/monit.sock
-  allow monit:oldpass123
 set ssl { verify: enable }
`, shows: "oldpass123"},
		{name: "users: add a user and rotate a hash", oldTpl: users, newTpl: users,
			oldData: map[string]any{"users": map[string]any{"alice": sec("$6$aaa$oldhash"), "bob": sec("$6$bbb$bobhash")}},
			newData: map[string]any{"users": map[string]any{"alice": sec("$6$aaa$newhash"), "bob": sec("$6$bbb$bobhash"), "carol": sec("$6$ccc$carolhash")}},
			want: `@@ -1,2 +1,3 @@
-alice@example.com:(secret)
+alice@example.com:(secret) (secret value changed)
 bob@example.com:(secret)
+carol@example.com:(secret)
`},
		{name: "users: remove a user whose secret stays", oldTpl: users, newTpl: "{{ .keep }}\n" + users,
			oldData: map[string]any{"users": map[string]any{"alice": sec("$6$aaa$alicehash"), "bob": sec("$6$bbb$bobhash")}},
			newData: map[string]any{"users": map[string]any{"alice": sec("$6$aaa$alicehash")}, "keep": sec("$6$bbb$bobhash")},
			want: `@@ -1,2 +1,2 @@
+(secret)
 alice@example.com:(secret)
-bob@example.com:$6$bbb$bobhash
`},
		{name: "users: remove a user and the secret", oldTpl: users, newTpl: users,
			oldData: map[string]any{"users": map[string]any{"alice": sec("$6$aaa$alicehash"), "bob": sec("$6$bbb$bobhash")}},
			newData: map[string]any{"users": map[string]any{"alice": sec("$6$aaa$alicehash")}},
			want: `@@ -1,2 +1,1 @@
 alice@example.com:(secret)
-bob@example.com:$6$bbb$bobhash
`, shows: "$6$bbb$bobhash"},
		{name: "upper and base64", oldTpl: "u {{ upper .pw }}\nb {{ b64 .pw }}\n", newTpl: "u {{ upper .pw }}\nb {{ b64 .pw }}\n", oldData: pw("oldpass123"), newData: pw("n3wPa55!"), want: `@@ -1,2 +1,2 @@
-u (secret)
-b (secret)
+u (secret) (secret value changed)
+b (secret) (secret value changed)
`},
		{name: "control flow on a secret", oldTpl: "auth {{ if gt (len .pw) 9 }}strong{{ else }}weak{{ end }} user\n", newTpl: "auth {{ if gt (len .pw) 9 }}strong{{ else }}weak{{ end }} user\n", oldData: pw("short"), newData: pw("a-much-longer-password"), want: `@@ -1,1 +1,1 @@
-auth (secret) user
+auth (secret) user (secret value changed)
`},
		{name: "multi-line key, rotated", oldTpl: "{{ .pw }}", newTpl: "{{ .pw }}", oldData: pw(pemOld), newData: pw(pemNew), want: `@@ -1,4 +1,5 @@
 (secret)
-(line hidden: may hold a secret)
-(line hidden: may hold a secret)
+(secret)
+(secret)
+(secret)
 (secret)
`},
		{name: "secret equals the mark", oldTpl: monit, newTpl: monit, oldData: pw("x"), newData: pw("(secret)"), want: `@@ -1,3 +1,3 @@
 set httpd unixsocket /run/monit.sock
-  allow monit:(secret)
+  allow monit:(secret) (secret value changed)
 set ssl { verify: enable }
`},
		{name: "secret holds the mark", oldTpl: monit, newTpl: monit, oldData: pw("x"), newData: pw("my(secret)pass"), want: `@@ -1,3 +1,3 @@
 set httpd unixsocket /run/monit.sock
-  allow monit:(secret)
+  allow monit:(secret) (secret value changed)
 set ssl { verify: enable }
`},
		{name: "secret shares letters with the mark", oldTpl: monit, newTpl: monit, oldData: pw("x"), newData: pw("secbet"), want: `@@ -1,3 +1,3 @@
 set httpd unixsocket /run/monit.sock
-  allow monit:(secret)
+  allow monit:(secret) (secret value changed)
 set ssl { verify: enable }
`},
		{name: "a plain value becomes secret with a new value", oldTpl: monit, newTpl: monit, oldData: plain("plainpass"), newData: pw("n3wPa55!"), want: `@@ -1,3 +1,3 @@
 set httpd unixsocket /run/monit.sock
-  allow monit:(secret)
+  allow monit:(secret) (secret value changed)
 set ssl { verify: enable }
`},
		{name: "a plain value becomes secret with the same value", oldTpl: monit, newTpl: monit, oldData: plain("samepass"), newData: pw("samepass"), want: ""},
		{name: "a secret becomes plain with a new value", oldTpl: monit, newTpl: monit, oldData: pw("oldsecret"), newData: plain("newplain"), want: `@@ -1,3 +1,3 @@
 set httpd unixsocket /run/monit.sock
-  allow monit:oldsecret
+  allow monit:newplain
 set ssl { verify: enable }
`, shows: "oldsecret"},
		{name: "add, change, and remove in one hunk", oldTpl: keys, newTpl: keys,
			oldData: map[string]any{"m": map[string]any{"k1": sec("alpha-1"), "k2": sec("bravo-1"), "k3": sec("charlie-1")}},
			newData: map[string]any{"m": map[string]any{"k1": sec("alpha-2"), "k2": sec("bravo-1"), "k4": sec("delta-1")}},
			want: `@@ -1,3 +1,3 @@
-k1=(secret)
+k1=(secret) (secret value changed)
 k2=(secret)
-(line hidden: may hold a secret)
+k4=(secret)
`},
		{name: "a new file", oldTpl: "", newTpl: monit, oldData: nil, newData: pw("n3wPa55!"), want: `@@ -0,0 +1,3 @@
+set httpd unixsocket /run/monit.sock
+  allow monit:(secret)
+set ssl { verify: enable }
`},
		{name: "no secret in the file", oldTpl: "a\nb\n", newTpl: "a\nc\n", oldData: nil, newData: nil, want: "@@ -1,2 +1,2 @@\n a\n-b\n+c\n"},
		{name: "two lines with the same secret, one changes its text", oldTpl: "a {{ .pw }}\nb {{ .pw }}\n", newTpl: "a {{ .pw }}\nc {{ .pw }}\n", oldData: pw("same-pass"), newData: pw("same-pass"), want: `@@ -1,2 +1,2 @@
 a (secret)
-(line hidden: may hold a secret)
+c (secret)
`},
		{name: "repeated plain lines between secret lines", oldTpl: "PW={{ .pw }}\nc\nc\nPW={{ .pw }}\n", newTpl: "PW={{ .pw }}\nc\nc\nPW={{ .pw }}\n", oldData: pw("oldpass123"), newData: pw("n3wPa55!"), want: `@@ -1,4 +1,4 @@
-PW=(secret)
-(line hidden: may hold a secret)
-(line hidden: may hold a secret)
-PW=(secret)
+PW=(secret) (secret value changed)
+c
+c
+PW=(secret) (secret value changed)
`},
		{name: "a change without a secret line beside a line that is only a secret", oldTpl: "{{ .pw }}\nlisten {{ .port }}\n", newTpl: "{{ .pw }}\nlisten {{ .port }}\n",
			oldData: map[string]any{"pw": sec("hunter2"), "port": 80}, newData: map[string]any{"pw": sec("hunter2"), "port": 8080}, want: `@@ -1,2 +1,2 @@
 (secret)
-listen 80
+listen 8080
`},
		{name: "the length of a secret as long as a placeholder", oldTpl: "n={{ len .pw }}\n", newTpl: "n={{ len .pw }}\n", oldData: pw("1234567"), newData: pw("12345678"), want: `@@ -1,1 +1,1 @@
-n=(secret)
+n=(secret) (secret value changed)
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, got := maskedDiff(t, tt.oldTpl, tt.newTpl, tt.oldData, tt.newData)
			if raw != tt.want {
				t.Errorf("diff\n%s\nwant\n%s", raw, tt.want)
			}
			for _, s := range append(secrets(tt.oldData), secrets(tt.newData)...) {
				for _, line := range strings.Split(s, "\n") {
					if utf8.RuneCountInString(line) >= 4 && line != Mark && line != tt.shows && strings.Contains(got, line) {
						t.Errorf("the diff shows %q", line)
					}
				}
			}
		})
	}
}

// spec: Variables/Secrets in output (two evaluations)
func TestLinesHidden(t *testing.T) {
	// The placeholder variants have different numbers of lines.
	if _, ok := Lines([]byte("a\nb\n"), []byte("a\n"), []byte("a\nb\nc\n")); ok {
		t.Error("Lines of variants with different line counts: ok")
	}
	lines, ok := Lines([]byte("a\nb\n"), []byte("a\nb\n"), []byte("a\nb\n"))
	if !ok || len(lines) != 2 || lines[0].Secret || lines[1].Show != "b\n" {
		t.Errorf("Lines without a secret = %+v, %v", lines, ok)
	}
	old := []byte("a\nb\nc\n")
	if got, want := string(Diff(old, lines)), string(diff.Diff(old, []byte("a\nb\n"))); got != want {
		t.Errorf("Diff without a secret = %q, want the plain diff %q", got, want)
	}
}

// spec: Variables/Secrets in output (two evaluations, file diffs, text
// filter)
func FuzzMaskedDiff(f *testing.F) {
	f.Add("set a\nallow {{.pw}} x\nend\n", "OLD9SECRET", "NEW7SECRET2", "keep\n")
	f.Add("{{.pw}}{{.pw}}\n", "ABCD", "WXYZ", "")
	f.Add("u {{upper .pw}}\nb {{b64 .pw}}\n", "PASS", "PASSWORD", "x\ny\n")
	f.Add("a {{if gt (len .pw) 9}}long{{else}}short{{end}}\nc\nc\n{{.pw}}\n", "ABCDEFGHIJK", "XYZW", "c\n")
	f.Fuzz(func(t *testing.T, tpl, oldPw, newPw, extra string) {
		if !secretChars(oldPw) || !secretChars(newPw) || !templateChars(tpl) || !templateChars(extra) {
			return
		}
		tmpl, err := template.New("t").Funcs(template.FuncMap{
			"upper": strings.ToUpper,
			"b64":   func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
		}).Parse(tpl)
		if err != nil {
			return
		}
		run := func(data any) []byte {
			var b strings.Builder
			if tmpl.Execute(&b, data) != nil {
				return nil
			}
			return []byte(b.String())
		}
		newData := map[string]any{"pw": sec(newPw)}
		real := run(variant(newData, 0))
		a, b := run(variant(newData, 1)), run(variant(newData, 2))
		old := append(run(map[string]any{"pw": oldPw}), extra...)
		if real == nil || a == nil || b == nil {
			return
		}
		lines, ok := Lines(real, a, b)
		if !ok {
			return
		}
		fl := NewFilter()
		fl.Add(newPw)
		got := fl.Text(string(Diff(old, lines)))
		for _, s := range []string{oldPw, newPw} {
			if strings.Contains(got, s) {
				t.Errorf("template %q, old %q, new %q: the diff shows %q:\n%s", tpl, oldPw, newPw, s, got)
			}
		}
	})
}

// secretChars reports whether s is a secret for the fuzz test: 4 to 40
// upper-case letters, which no template text holds.
func secretChars(s string) bool {
	if len(s) < 4 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// templateChars reports whether s has only lower-case text, digits, spaces,
// newlines, and template actions.
func templateChars(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789 \n{}.()$|=-", r) {
			return false
		}
	}
	return true
}
