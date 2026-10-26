package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

// jsonProject has a stage step with then, a recipe with a handler and a
// loop, and the unreachable host web3.
func jsonProject(t *testing.T) string {
	return vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n  web3:\n    address: unreachable\n",
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "hello\n"
        then: echo done
      - recipe: app
`,
		"recipes/app/recipe.yaml": `steps:
  - name: Pages
    file:
      path: !tpl /srv/{{ .item }}.html
      content: "page\n"
    loop: [a, b]
    notify: reload
handlers:
  reload:
    - service:
        name: app
        reloaded: true
`,
	})
}

// spec: CLI/JSON output
func TestJSON(t *testing.T) {
	tests := []struct {
		name     string
		dir      func(t *testing.T) string
		setup    func(h *fakehost.Hosts)
		terminal bool
		args     []string
	}{
		{name: "plan", dir: jsonProject, setup: func(h *fakehost.Hosts) {
			h.SetFile("web1", "/etc/motd", "hi\n")
			h.SetFile("web2", "/etc/motd", "hello\n")
			h.SetFile("web2", "/srv/a.html", "page\n")
			h.SetFile("web2", "/srv/b.html", "page\n")
			h.SetPending("web2", "app.reload")
			sum := sha256.Sum256([]byte("echo done"))
			h.SetThen("web2", protocol.Then{Stage: "base", SHA256: hex.EncodeToString(sum[:])})
		}, args: []string{"plan", "site", "--json"}},
		{name: "apply", dir: jsonProject, setup: func(h *fakehost.Hosts) {
			h.SetFile("web2", "/srv/a.html", "page\n")
		}, args: []string{"apply", "site", "--json", "--yes"}},
		{name: "apply-fails", dir: jsonProject, setup: func(h *fakehost.Hosts) {
			h.FailApply("web1 /srv/b.html")
		}, args: []string{"apply", "site", "--json", "--yes"}},
		{name: "apply-no-terminal", dir: jsonProject, args: []string{"apply", "site", "--json", "--inventory", "inventories/test.yaml"}},
		{name: "validate-errors", dir: func(t *testing.T) string {
			return vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nfoo: 1\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/motd\n          content: \"x\\n\"\n        when: !expr 'true &&& false'\n",
			})
		}, args: []string{"validate", "--json"}},
		{name: "plan-warning", dir: func(t *testing.T) string {
			return vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nvars:\n  token:\n",
				"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      token: " + fakeSecret(t, "ghp.txt") + "\n",
				"pipelines/site.yaml":   "stages:\n  - name: base\n    hosts: all\n    steps:\n      - file:\n          path: /etc/token\n          content: !expr vars.token\n",
			})
		}, args: []string{"plan", "site", "--json"}},
		{name: "plan-no-pipeline", dir: jsonProject, args: []string{"plan", "--json"}},
		{name: "apply-stale-check", dir: jsonProject, args: []string{"apply", "site", "--json", "--check", "0badc0de"}},
		{name: "apply-confirm", dir: func(t *testing.T) string {
			return vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
				"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - recipe: app
      - file:
          path: !tpl /etc/{{ .item }}
          content: "x\n"
        loop: [a, b]
`,
				"recipes/app/recipe.yaml": "steps:\n  - file:\n      path: /etc/app\n      content: \"a\\n\"\n",
			})
		}, args: []string{"apply", "site", "--json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			r := winch(t, tt.dir(t), h, tt.terminal, "", tt.args...)
			golden.Assert(t, filepath.Join("testdata", "json", tt.name+".golden"),
				[]byte("stdout:\n"+r.out+"stderr:\n"+r.err))
			lines := jsonLines(t, r.out)
			if lines[0]["type"] != "version" || lines[len(lines)-1]["type"] != "summary" {
				t.Errorf("first line %v, last line %v", lines[0]["type"], lines[len(lines)-1]["type"])
			}
		})
	}
}

// jsonLines parses each line of out as a JSON object with type and time.
func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for line := range strings.Lines(out) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		if m["type"] == nil || m["time"] == nil {
			t.Errorf("line %q has no type or time", line)
		}
		lines = append(lines, m)
	}
	if len(lines) == 0 {
		t.Fatal("no JSON lines")
	}
	return lines
}

// spec: CLI/JSON output ("summary ... Always the last line"); CLI/Exit codes
func TestJSONLastLine(t *testing.T) {
	good := writeProject(t, motd)
	bad := writeProject(t, "stages:\n  - name: base\n    hosts: all\n    steps:\n      - fiel: {}\n")
	present := func(h *fakehost.Hosts) {
		h.SetFile("web1", "/etc/motd", "hello\n")
		h.SetFile("web2", "/etc/motd", "hello\n")
	}
	tests := []struct {
		name     string
		dir      string
		setup    func(h *fakehost.Hosts)
		args     []string
		code     int
		terminal bool
	}{
		{"validate", good, nil, []string{"validate"}, exitOK, false},
		{"validate an invalid project", bad, nil, []string{"validate"}, exitInvalid, false},
		{"validate with an argument", good, nil, []string{"validate", "x"}, exitInvalid, false},
		{"plan", good, nil, []string{"plan", "site"}, exitOK, false},
		{"plan an invalid project", bad, nil, []string{"plan", "site"}, exitInvalid, false},
		{"plan an unknown pipeline", good, nil, []string{"plan", "nope"}, exitInvalid, false},
		{"plan with a failed host", good, func(h *fakehost.Hosts) { h.FailCheck("web1") }, []string{"plan", "site"}, exitFailed, false},
		{"plan --exit-code", good, nil, []string{"plan", "site", "--exit-code"}, exitChanges, false},
		{"apply without a terminal", good, nil, []string{"apply", "site"}, exitConfirm, false},
		{"apply --yes", good, nil, []string{"apply", "site", "--yes"}, exitOK, false},
		{"apply with a failed host", good, func(h *fakehost.Hosts) { h.FailApply("web1") }, []string{"apply", "site", "--yes"}, exitFailed, false},
		{"apply with a stale hash", good, nil, []string{"apply", "site", "--check", "0badc0de"}, exitHash, false},
		{"apply with a bad hash", good, nil, []string{"apply", "site", "--check", "x"}, exitInvalid, false},
		{"apply without changes", good, present, []string{"apply", "site"}, exitOK, false},
		{"apply answered no", good, nil, []string{"apply", "site"}, exitOK, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			if tt.setup != nil {
				tt.setup(h)
			}
			r := winch(t, tt.dir, h, tt.terminal, "n\n", append(tt.args, "--json")...)
			if r.code != tt.code {
				t.Errorf("exit %d, want %d", r.code, tt.code)
			}
			lines := jsonLines(t, r.out)
			last := lines[len(lines)-1]
			if lines[0]["type"] != "version" || last["type"] != "summary" || last["exit_code"] != float64(tt.code) {
				t.Errorf("first line %v, last line %v", lines[0], last)
			}
			if r.err != "" && !tt.terminal {
				t.Errorf("stderr = %q, want nothing", r.err)
			}
		})
	}
}

// writes records each write.
type writes []string

func (w *writes) Write(p []byte) (int, error) {
	*w = append(*w, string(p))
	return len(p), nil
}

// spec: CLI/JSON output; Variables/Secrets in output ("each JSON event passes
// the secret filter in one write")
func TestJSONOneWrite(t *testing.T) {
	h := fakehost.New()
	for _, args := range [][]string{{"plan", "site", "--json"}, {"apply", "site", "--json", "--yes"}} {
		var out writes
		var errOut strings.Builder
		code := Main(context.Background(), args, Env{
			Dir: jsonProject(t), In: strings.NewReader(""), Out: &out, Err: &errOut,
			Connect: h.Connector(), Filter: secret.NewFilter(), Now: fixedNow,
		})
		if code != exitUnreachable || len(out) < 3 {
			t.Fatalf("%v: exit %d, %d writes, stderr %q", args, code, len(out), errOut.String())
		}
		for _, w := range out {
			if strings.Count(w, "\n") != 1 || !strings.HasSuffix(w, "\n") || !json.Valid([]byte(w)) {
				t.Errorf("%v: a write is not one JSON line: %q", args, w)
			}
		}
	}
}

// spec: Variables/Secrets in output; CLI/JSON output
func TestJSONSecret(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	// JSON escapes each character after hunt.
	password := `hunt&<>"\\2`
	setPassword(t, dir, encrypt(t, dir, password+"\n"))
	h := fakehost.New()
	h.SetFile("web1", "/etc/pw", "pw=old-password\n")
	// The error of the host holds the real value; only the filter masks it.
	h.FailCommand("web1", "echo "+password+" | chpasswd")
	for _, args := range [][]string{{"plan", "site", "--json"}, {"apply", "site", "--json", "--yes"}} {
		r := winchWith(t, dir, "", identity, h, false, "", args...)
		if !strings.Contains(r.out, "(secret)") {
			t.Errorf("%v: exit %d, stdout %q", args, r.code, r.out)
		}
		if strings.Contains(r.out+r.err, "hunt") {
			t.Errorf("%v: the output shows the secret:\n%s", args, r.out)
		}
	}
	if c, _ := h.File("web1", "/etc/pw"); c != "pw="+password+"\n" {
		t.Errorf("/etc/pw = %q", c)
	}
}
