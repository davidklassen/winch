package cli

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

// sweepSecret is the value of the secret vars.pw. Its letters are not hex
// digits, and its parts are rare in English, so a part in the output is a leak
// and not a plan hash or a word. The steps of TestSecretSweep take the parts
// vars.pw[:5], vars.pw[2:6], and vars.pw[6:].
const sweepSecret = "kwzqxjqz"

// sweepBase64 is toBase64("user:" + vars.pw). Its characters from the 9th on
// encode only bytes of the secret.
var sweepBase64 = base64.StdEncoding.EncodeToString([]byte("user:" + sweepSecret))

// sweepForms are the texts that no output may hold, the longest first.
var sweepForms = []string{
	sweepSecret,
	strings.ToUpper(sweepSecret),
	base64.StdEncoding.EncodeToString([]byte(sweepSecret)),
	strings.TrimRight(sweepBase64[8:], "="),
	sweepSecret[:5],
	sweepSecret[2:6],
	sweepSecret[6:],
}

// sweepLeaks are the known leaks of TestSecretSweep: the case, and the first
// form of sweepForms that its output holds. A fix that removes a leak removes
// its line here.
var sweepLeaks = []string{
	// exec evaluates no step, so the filter knows no value built from a
	// secret.
	"exec: " + strings.TrimRight(sweepBase64[8:], "="),
}

// sweepTexts returns the lines of the string values of a JSON event, or a
// text line, without the indent.
func sweepTexts(line string) []string {
	var v any
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		return []string{strings.TrimSpace(line)}
	}
	var texts []string
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			for _, l := range strings.Split(v, "\n") {
				texts = append(texts, strings.TrimSpace(l))
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		case map[string]any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(v)
	return texts
}

// spec: Variables/Secrets (Secrets in output)
func TestSecretSweep(t *testing.T) {
	planAll := [][]string{{"plan", "site"}, {"plan", "site", "--json"}}
	applyAll := append(slices.Clone(planAll), []string{"apply", "site", "--yes"}, []string{"apply", "site", "--yes", "--json"})
	sha := strings.Repeat("a", 64)
	key := "            " + strings.ReplaceAll(strings.TrimSuffix(readFile(t, filepath.Join("..", "module", "testdata", "key.asc")), "\n"), "\n", "\n            ")
	// The fake host builds few change lines and errors. The results that
	// cases set stand for the text of a real host, built from the real
	// arguments.
	cases := []struct {
		// want is a text of the output that shows the path of the case.
		name, want, steps string
		host              func(h *fakehost.Hosts)
		args              [][]string
	}{
		{"every module", "1 host: 1 changed, 0 unchanged", `
      - file:
          path: !expr '"/srv/f-" + vars.pw[2:6]'
          content: !expr 'vars.pw + "\n"'
        then: !expr '"notify " + vars.pw[:5]'
      - file:
          path: /srv/b64
          content: !expr 'toBase64("user:" + vars.pw)'
          validate: !expr '"check " + vars.pw[6:]'
      - file:
          path: /srv/tpl
          content: !tpl "a {{ .vars.pw }}\n"
      - file:
          path: /srv/upper
          content: !expr 'upper(vars.pw) + "\n"'
          owner: !expr '"o" + vars.pw[2:6]'
          group: !expr '"p" + vars.pw[2:6]'
      - dir:
          path: !expr '"/srv/d-" + vars.pw[6:]'
      - line:
          path: /etc/app.conf
          line: !expr '"pass " + vars.pw'
          match: "^pass "
      - link:
          path: /srv/link
          target: !expr '"/srv/" + vars.pw[2:6]'
      - download:
          url: !expr '"https://example.com/" + vars.pw[:5]'
          sha256: ` + sha + `
          path: /srv/dl
      - pkg:
          name: !expr '"lib" + vars.pw[2:6]'
      - service:
          name: !expr '"app-" + vars.pw[2:6]'
          running: true
      - group:
          name: !expr '"g" + vars.pw[:5]'
      - user:
          name: !expr '"u" + vars.pw[2:6]'
          comment: !expr 'vars.pw'
          home: !expr '"/home/" + vars.pw[2:6]'
          groups: [!expr '"g" + vars.pw[:5]']
      - cmd:
          command: !expr '"setpw " + vars.pw'
          unless: !expr '"test " + vars.pw[6:]'
          user: !expr 'vars.pw[6:]'
          dir: !expr '"/srv/" + vars.pw[2:6]'
      - cmd:
          command: make
          creates: !expr '"/srv/c-" + vars.pw[2:6]'
      - debconf:
          package: app
          question: app/token
          type: string
          value: !expr 'vars.pw[:5]'
      - hostname:
          name: !expr '"h-" + vars.pw[2:6]'
      - assert:
          command: !expr '"check " + vars.pw[2:6]'
          message: !expr '"no " + vars.pw[6:]'
      - unit:
          name: app.service
          content: !expr '"[Service]\nExecStart=/bin/app " + vars.pw + "\n"'
      - certbot:
          name: !expr '"c-" + vars.pw[2:6]'
          domains: [a.example.com]
          email: !expr 'vars.pw[6:] + "@example.com"'
          authenticator: standalone
`, func(h *fakehost.Hosts) {
			h.SetFile("web1", "/srv/tpl", "a old\n")
			h.SetFile("web1", "/etc/app.conf", "pass old\n")
			h.SetAnswer("web1", "app/token", "old")
			h.RemoveDir("web1", "/srv/d-qz")
			h.RemoveDir("web1", "/srv/zqxj")
			h.FailCommand("web1", "test qz")
			h.SetResult("web1", "/srv/link", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"target /srv/old → /srv/zqxj"}})
			h.SetResult("web1", "^pass ", module.Result{Status: module.Change, Action: module.Modify, Old: new("pass old\n")})
			h.SetResult("web1", "h-zqxj", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"name old → h-zqxj"}})
		}, applyAll},
		{"a package install", `"changes":["(secret)","(secret)"]`, `
      - pkg:
          name: !expr '"lib" + vars.pw[6:]'
`, nil, planAll},
		{"a user with its group", `"changes":["(secret)"]`, `
      - user:
          name: !expr '"u" + vars.pw[6:]'
`, nil, planAll},
		{"a host name change", `"changes":["(secret)"]`, `
      - hostname:
          name: !expr '"h-" + vars.pw[6:]'
`, func(h *fakehost.Hosts) {
			h.SetResult("web1", "h-qz", module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"name old → h-qz"}})
		}, planAll},
		{"two steps on one path", "is also in", `
      - file:
          path: !expr '"/srv/" + vars.pw[6:]'
          content: "a\n"
      - file:
          path: !expr '"/srv/" + vars.pw[6:]'
          content: "b\n"
`, nil, planAll},
		{"two steps on one path from a longer part", "is also in", `
      - file:
          path: !expr '"/srv/" + vars.pw[2:6]'
          content: "a\n"
      - file:
          path: !expr '"/srv/" + vars.pw[2:6]'
          content: "b\n"
`, nil, planAll},
		{"two steps for one user", "is also in", `
      - user:
          name: !expr 'vars.pw[6:]'
      - user:
          name: !expr 'vars.pw[6:]'
          comment: app
`, nil, planAll},
		{"two steps for one package", "is also in", `
      - pkg:
          name: !expr '"lib" + vars.pw[6:]'
      - pkg:
          name: !expr '"lib" + vars.pw[6:]'
          recommends: false
`, nil, planAll},
		{"two steps for one unit", "is also in", `
      - service:
          name: !expr '"app-" + vars.pw[6:]'
          running: true
      - service:
          name: !expr '"app-" + vars.pw[6:]'
          running: false
`, nil, planAll},
		{"a user that a later step creates", "which an earlier step needs", `
      - file:
          path: /srv/a
          content: "a\n"
          owner: !expr 'vars.pw[6:]'
      - user:
          name: !expr 'vars.pw[6:]'
`, nil, planAll},
		{"a removed tree", "undo each other", `
      - dir:
          path: !expr '"/srv/" + vars.pw[6:]'
          absent: true
      - file:
          path: !expr '"/srv/" + vars.pw[6:] + "/a"'
          content: "a\n"
`, nil, planAll},
		{"two line steps that overlap", "finds the line of this step", `
      - line:
          path: /etc/app.conf
          line: !expr 'vars.pw[6:] + " 1"'
          match: !expr '"^" + vars.pw[6:]'
      - line:
          path: /etc/app.conf
          line: !expr 'vars.pw[6:] + " 2"'
          match: !expr '"^" + vars.pw[6:] + " 2"'
`, nil, planAll},
		{"a unit after its service", "before this step writes it", `
      - service:
          name: !expr '"app-" + vars.pw[6:]'
          running: true
      - unit:
          name: !expr '"app-" + vars.pw[6:] + ".service"'
          content: "[Service]\n"
`, nil, planAll},
		{"a drop-in after its service", "before this step changes its drop-in", `
      - service:
          name: !expr '"app-" + vars.pw[6:]'
          running: true
      - file:
          path: !expr '"/etc/systemd/system/app-" + vars.pw[6:] + ".service.d/a.conf"'
          content: "[Service]\n"
`, nil, planAll},
		{"an answer after its package", "before this step sets the answer", `
      - pkg:
          name: !expr '"lib" + vars.pw[6:]'
      - debconf:
          package: !expr '"lib" + vars.pw[6:]'
          question: lib/a
          type: string
          value: a
`, nil, planAll},
		{"two steps for one group", "is also in", `
      - group:
          name: !expr 'vars.pw[6:]'
      - group:
          name: !expr 'vars.pw[6:]'
          system: true
`, nil, planAll},
		{"two steps for one unpack directory", "is also in", `
      - download:
          url: https://example.com/a.tar.gz
          sha256: ` + sha + `
          unpack: !expr '"/srv/" + vars.pw[6:]'
      - download:
          url: https://example.com/b.tar.gz
          sha256: ` + sha + `
          unpack: !expr '"/srv/" + vars.pw[6:]'
`, nil, planAll},
		{"two steps for the groups of one user", "is also in", `
      - user:
          name: !expr 'vars.pw[6:]'
          groups: [a]
      - user:
          name: !expr 'vars.pw[6:]'
          add_groups: [b]
`, nil, planAll},
		{"a tree that a later step removes", "undo each other", `
      - file:
          path: !expr '"/srv/" + vars.pw[6:] + "/a"'
          content: "a\n"
      - dir:
          path: !expr '"/srv/" + vars.pw[6:]'
          absent: true
`, nil, planAll},
		{"two line steps that overlap the other way", "finds the line of", `
      - line:
          path: /etc/app.conf
          line: !expr 'vars.pw[6:] + " 1"'
          match: !expr '"^" + vars.pw[6:] + " 1"'
      - line:
          path: /etc/app.conf
          line: !expr 'vars.pw[6:] + " 2"'
          match: !expr '"^" + vars.pw[6:]'
`, nil, planAll},
		{"a removal of an installed package", "undo each other", `
      - pkg:
          name: !expr '"lib" + vars.pw[6:]'
      - pkg:
          name: app
          absent: true
`, func(h *fakehost.Hosts) {
			h.SetPkg("web1", "libqz", "app")
			h.SetPkgDeps("libqz", "app")
		}, planAll},
		{"an evaluation error", "invalid operation", `
      - file:
          path: /srv/a
          content: !expr 'string(int(vars.pw))'
`, nil, planAll},
		{"an evaluation error on a part", "invalid operation", `
      - file:
          path: /srv/a
          content: !expr 'string(int(vars.pw[6:]))'
`, nil, planAll},
		{"a failed file", `"error":"(secret)"`, `
      - file:
          path: !expr '"/srv/" + vars.pw[6:]'
          content: "a\n"
`, func(h *fakehost.Hosts) { h.FailApply("web1 /srv/qz") }, applyAll},
		{"a failed file with a longer part", "read-only file system", `
      - file:
          path: !expr '"/srv/" + vars.pw[2:6]'
          content: "a\n"
`, func(h *fakehost.Hosts) { h.FailApply("web1 /srv/zqxj") }, applyAll},
		{"a failed service", `"error":"(secret)"`, `
      - service:
          name: !expr '"app-" + vars.pw[6:]'
          running: true
`, func(h *fakehost.Hosts) { h.FailApply("web1 app-qz") }, applyAll},
		{"a failed command", "exit status 1", `
      - cmd:
          command: !expr '"setpw " + vars.pw[:5]'
`, func(h *fakehost.Hosts) { h.FailCommand("web1", "setpw kwzqx") }, applyAll},
		{"a failed then", "then: notify", `
      - file:
          path: /srv/a
          content: "a\n"
        then: !expr '"notify " + vars.pw[6:]'
`, func(h *fakehost.Hosts) { h.FailCommand("web1", "notify qz") }, applyAll},
		{"a failed assert", `"error":"(secret)"`, `
      - file:
          path: /srv/a
          content: "a\n"
      - assert:
          command: !expr '"check " + vars.pw[2:6]'
          message: !expr '"no " + vars.pw[6:]'
`, func(h *fakehost.Hosts) { h.FailCommand("web1", "check zqxj") }, applyAll},
		{"a certbot hook", "a certbot hook cannot hold a secret", `
      - certbot:
          name: app
          domains: [a.example.com]
          email: a@example.com
          authenticator: standalone
          deploy_hook: !expr '"reload " + vars.pw[2:6]'
`, nil, planAll},
		{"a repo source", "a repo step cannot hold a secret", `
      - repo:
          name: app
          url: !expr '"https://example.com/" + vars.pw[2:6]'
          suite: stable
          components: [main]
          key_content: |
` + key + `
`, nil, planAll},
		{"exec", "(secret)", `
      - file:
          path: /srv/auth
          content: !expr 'toBase64("user:" + vars.pw)'
`, func(h *fakehost.Hosts) {
			h.SetExec("web1", module.ExecResult{Output: sweepSecret + "\n" + base64.StdEncoding.EncodeToString([]byte(sweepSecret)) + "\n" + sweepBase64 + "\n"})
		}, [][]string{{"exec", "all", "--", "cat", "/srv/auth"}, {"exec", "all", "--json", "--", "cat", "/srv/auth"}}},
	}

	identity, id := newIdentity(t)
	text, err := secret.Encrypt(sweepSecret, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, c := range cases {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: acme\ninventory: test\nrecipients: [" + id.Recipient().String() + "]\n",
			"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret " + text + "\n",
			"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:" + c.steps,
		})
		all := ""
		for _, args := range c.args {
			h := fakehost.New()
			if c.host != nil {
				c.host(h)
			}
			r := winchWith(t, dir, "", identity, "", h, false, "", args...)
			t.Logf("%s: winch %s: exit %d\n%s%s", c.name, strings.Join(args, " "), r.code, r.out, r.err)
			if r.code == exitInvalid && !strings.Contains(r.out+r.err, c.want) {
				t.Errorf("%s: winch %s: the project does not load", c.name, strings.Join(args, " "))
			}
			all += r.out + r.err
			for _, line := range slices.Concat(strings.Split(r.out, "\n"), strings.Split(r.err, "\n")) {
				for _, s := range sweepTexts(line) {
					if i := slices.IndexFunc(sweepForms, func(f string) bool { return strings.Contains(s, f) }); i >= 0 {
						got[c.name+": "+sweepForms[i]] = true
					}
				}
			}
		}
		if !strings.Contains(all, c.want) {
			t.Errorf("%s: the output has no %q", c.name, c.want)
		}
	}
	for _, l := range sweepLeaks {
		if !got[l] {
			t.Errorf("a known leak no longer shows; remove it from sweepLeaks: %q", l)
		}
		delete(got, l)
	}
	for _, l := range slices.Sorted(maps.Keys(got)) {
		t.Errorf("a secret shows: %q; the log has the output", l)
	}
}
