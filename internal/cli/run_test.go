package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

func runProject(t *testing.T) string {
	return vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\ngroups:\n  none:\n    hosts: []\n",
	})
}

// spec: CLI (winch run)
func TestRun(t *testing.T) {
	dir := runProject(t)
	h := fakehost.New()
	r := winch(t, dir, h, false, "", "run", "web1", "file", "path=/etc/motd", "content=hi", "--yes")
	if r.code != exitOK || !strings.HasPrefix(r.out, "web1\n  run\n    + file /etc/motd\n") || !strings.Contains(r.out, "web1: run: + file /etc/motd\n") {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	if c, _ := h.File("web1", "/etc/motd"); c != "hi" {
		t.Errorf("web1 /etc/motd = %q", c)
	}
	if _, ok := h.File("web2", "/etc/motd"); ok {
		t.Error("run changed a host outside the pattern")
	}
	r = winch(t, dir, h, false, "", "run", "web1", "file", "path=/etc/motd", "content=hi")
	if r.code != exitOK || !strings.Contains(r.out, "1 host: 0 to change, 1 unchanged, 0 unknown\n") {
		t.Errorf("second run: exit %d, stdout %q", r.code, r.out)
	}
	r = winch(t, dir, h, false, "", "run", "all", "pkg", "name=[htop,curl]", "--yes")
	if r.code != exitOK || strings.Count(r.out, ": run: + pkg htop, curl\n") != 2 {
		t.Errorf("run on all: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	r = winch(t, dir, h, false, "", "run", "web2", "file", "path=/etc/n", `content="0644"`, "--yes")
	if c, _ := h.File("web2", "/etc/n"); r.code != exitOK || c != "0644" {
		t.Errorf("a quoted number: exit %d, content %q, stderr %q", r.code, c, r.err)
	}
}

// spec: CLI (winch run); CLI/Errors; Modules/assert
func TestRunArgs(t *testing.T) {
	dir := runProject(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no module", []string{"web1"}, "winch: run needs a host pattern and a module"},
		{"no key", []string{"web1", "pkg", "htop"}, "winch run: htop: an argument is key=value, such as name=htop"},
		{"empty key", []string{"web1", "pkg", "=htop"}, "winch run: =htop: an argument is key=value, such as name=htop"},
		{"a key twice", []string{"web1", "pkg", "name=a", "name=b"}, "winch run: name=b: name is given twice"},
		{"unknown module", []string{"web1", "pkgg", "name=htop"}, `winch run: unknown module "pkgg"; did you mean "pkg"?`},
		{"a step field", []string{"web1", "when", "x=1"}, `winch run: unknown module "when"`},
		{"unknown key", []string{"web1", "pkg", "nam=htop"}, `winch run: nam=htop: unknown key "nam"; did you mean "name"?`},
		{"missing key", []string{"web1", "pkg"}, `winch run: pkg: missing key "name"`},
		{"a map", []string{"web1", "file", "path=/x", "content={a: b}"}, `winch run: content={a: b}: YAML reads a map; quote it: "{a: b}"`},
		{"a comment", []string{"web1", "file", "path=/x", "content=a #b"}, `winch run: content=a #b: YAML drops the comment; quote it: "a #b"`},
		{"a number with other text", []string{"web1", "file", "path=/x", "content=x", "mode=0644"}, `winch run: mode=0644: YAML reads 0644 as 644; quote it: "0644"`},
		{"null", []string{"web1", "file", "path=/x", "content="}, "winch run: content=: null is not a value"},
		{"a tag", []string{"web1", "file", "path=/x", "content=!tpl x"}, "winch run: content=!tpl x: winch run gives no !tpl values"},
		{"a wrong type", []string{"web1", "pkg", "name=htop", "recommends=yes"}, `winch run: recommends=yes: recommends: expected true or false, got the string "yes"`},
		{"template", []string{"web1", "file", "path=/x", "template=a.tmpl"}, "winch run: template=a.tmpl: winch run cannot use template; use it in a recipe"},
		{"source", []string{"web1", "file", "path=/x", "source=a"}, "winch run: source=a: winch run cannot use source; use it in a recipe"},
		{"assert", []string{"all", "assert", "command=systemctl is-active nginx", "message=down"}, "winch run: winch run cannot use assert; run a check with winch exec"},
		{"assert with no argument", []string{"web1", "assert"}, "winch run: winch run cannot use assert; run a check with winch exec"},
		{"unit source", []string{"web1", "unit", "name=app.service", "source=app.service"}, "winch run: source=app.service: winch run cannot use source; use it in a recipe"},
		{"unknown host", []string{"web9", "pkg", "name=htop"}, `winch run: unknown host or group "web9" in inventories/test.yaml; did you mean "web1"?`},
		{"no host", []string{"none", "pkg", "name=htop"}, `winch run: the host pattern "none" matches no host in inventories/test.yaml`},
		{"a YAML error", []string{"web1", "file", "path=/x", "content=[a"}, `winch run: content=[a: did not find expected ',' or ']'; quote it: "[a"`},
		{"an alias", []string{"web1", "file", "path=/x", "content=*x"}, `; quote it: "*x"`},
		{"a reserved character", []string{"web1", "file", "path=/x", "content=@x"}, `; quote it: "@x"`},
		{"a bad hash", []string{"web1", "pkg", "name=htop", "--check", "xyz"}, "a plan hash has 16 hex characters"},
		{"--hosts", []string{"web1", "pkg", "name=htop", "--hosts", "web1"}, "flag provided but not defined: -hosts"},
		{"--set", []string{"web1", "pkg", "name=htop", "--set", "vars.x=1"}, "flag provided but not defined: -set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			r := winch(t, dir, h, false, "", append([]string{"run"}, tt.args...)...)
			if r.code != exitInvalid || !strings.Contains(r.err, tt.want) {
				t.Errorf("exit %d, stderr %q, want %q", r.code, r.err, tt.want)
			}
			if len(h.Connects) != 0 {
				t.Error("winch contacted a host")
			}
		})
	}
}

// spec: CLI/Prompts; Running a pipeline/Apply (--check)
func TestRunConfirm(t *testing.T) {
	dir := runProject(t)
	args := []string{"run", "web1", "file", "path=/etc/motd", "content=hi there", "--inventory", "test", "--user", "web1=deploy"}
	h := fakehost.New()
	r := winch(t, dir, h, false, "", args...)
	hash := planHash(t, r.out)
	want := "To apply, run: winch run web1 file path=/etc/motd 'content=hi there' --inventory test --user web1=deploy --check " + hash + "\n"
	if r.code != exitConfirm || !strings.HasSuffix(r.out, want) || h.Applies != 0 {
		t.Errorf("exit %d, applies %d, stdout %q, want suffix %q", r.code, h.Applies, r.out, want)
	}
	r = winch(t, dir, h, false, "", "run", "web1", "file", "path=/etc/motd", "content=hi there", "--check", "0badc0de0badc0de")
	if r.code != exitHash || h.Applies != 0 {
		t.Errorf("a stale hash: exit %d, applies %d", r.code, h.Applies)
	}
	r = winch(t, dir, h, false, "", append(args, "--check", hash)...)
	if c, _ := h.File("web1", "/etc/motd"); r.code != exitOK || c != "hi there" || h.Users["web1"] != "deploy" {
		t.Errorf("--check: exit %d, content %q, user %q, stderr %q", r.code, c, h.Users["web1"], r.err)
	}
	// spec: Remote execution/Sessions; CLI/JSON output (summary)
	h = fakehost.New()
	r = winch(t, dir, h, false, "", "run", "web1", "file", "path=/etc/motd", "content=hi", "--json")
	lines := jsonLines(t, r.out)
	command := "winch run web1 file path=/etc/motd content=hi --json --check " + lines[len(lines)-1]["hash"].(string)
	if r.code != exitConfirm || lines[len(lines)-1]["command"] != command {
		t.Errorf("--json: exit %d, summary %v", r.code, lines[len(lines)-1])
	}
	h = fakehost.New()
	r = winch(t, dir, h, true, "", "run", "web1", "file", "path=/etc/motd", "content=hi", "--batch", "--yes")
	if r.code != exitOK || !slices.Equal(h.Batch, []bool{true}) {
		t.Errorf("--batch: exit %d, batch %v", r.code, h.Batch)
	}
}

// spec: Modules/service and unit (restarted and reloaded in winch run)
func TestRunRestarted(t *testing.T) {
	dir := runProject(t)
	for _, action := range []string{"restart", "reload"} {
		h := fakehost.New()
		r := winch(t, dir, h, false, "", "run", "web1", "service", "name=nginx", action+"ed=true", "--yes")
		if r.code != exitOK || !slices.Equal(h.Log["web1"], []string{"nginx " + action, "access"}) {
			t.Errorf("%sed: exit %d, log %q, stderr %q", action, r.code, h.Log["web1"], r.err)
		}
	}
}

// spec: CLI/JSON output
func TestRunJSON(t *testing.T) {
	h := fakehost.New()
	r := winch(t, runProject(t), h, false, "", "run", "web1", "file", "path=/etc/motd", "content=hi", "--yes", "--json")
	var got []string
	for _, l := range jsonLines(t, r.out) {
		e := l["type"].(string)
		if a, ok := l["address"]; ok {
			e += " " + a.(string) + " " + l["stage"].(string)
		}
		got = append(got, e)
	}
	want := []string{"version", "planned web1:run#1 run", "host", "applied web1:run#1 run", "host", "summary"}
	if r.code != exitOK || !slices.Equal(got, want) {
		t.Errorf("exit %d, events %q, want %q", r.code, got, want)
	}
}

// spec: CLI (winch exec); CLI/Output; CLI/Exit codes
func TestExec(t *testing.T) {
	dir := runProject(t)
	tests := []struct {
		name    string
		results map[string]module.ExecResult
		down    string
		fail    string
		close   string
		want    string
		wantErr string
		code    int
	}{
		{name: "the same output shares a block",
			results: map[string]module.ExecResult{"web1": {Output: "same\n"}, "web2": {Output: "same\n"}},
			want:    "web1, web2 (2 hosts)\n  same\n\n"},
		{name: "other output, a non-zero exit",
			results: map[string]module.ExecResult{"web1": {Output: "a\nb"}, "web2": {Output: "a\nb", ExitCode: 3}},
			want:    "web1\n  a\n  b\n\nweb2\n  a\n  b\n  exit status 3\n\n", code: exitFailed},
		{name: "no output and a signal",
			results: map[string]module.ExecResult{"web1": {}, "web2": {ExitCode: 137, Signal: 9}},
			want:    "web1\n\nweb2\n  killed by signal 9\n\n", code: exitFailed},
		{name: "control characters",
			results: map[string]module.ExecResult{"web1": {Output: "a\x1b[31mb\tc\n"}, "web2": {Output: "a\x1b[31mb\tc\n"}},
			want:    "web1, web2 (2 hosts)\n  a?[31mb\tc\n\n"},
		{name: "an unreachable host",
			results: map[string]module.ExecResult{"web1": {Output: "up\n"}}, down: "web2",
			want: "web1\n  up\n\n", wantErr: "web2: ssh: connect to host", code: exitUnreachable},
		{name: "a failed host",
			results: map[string]module.ExecResult{"web1": {Output: "up\n"}}, fail: "web2",
			want: "web1\n  up\n\n", wantErr: "web2: session: the helper ended\n", code: exitFailed},
		{name: "a failed close keeps the output",
			results: map[string]module.ExecResult{"web1": {Output: "up\n"}, "web2": {Output: "up\n"}}, close: "web2",
			want: "web1, web2 (2 hosts)\n  up\n\n", wantErr: "web2: session: exit status 255\n", code: exitFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			for host, res := range tt.results {
				h.SetExec(host, res)
			}
			if tt.down != "" {
				h.SetUnreachable(tt.down)
			}
			if tt.fail != "" {
				h.FailExec(tt.fail)
			}
			if tt.close != "" {
				h.FailClose(tt.close)
			}
			r := winch(t, dir, h, false, "", "exec", "all", "--", "echo", "same")
			if r.code != tt.code || r.out != tt.want || !strings.Contains(r.err, tt.wantErr) || tt.wantErr == "" && r.err != "" {
				t.Errorf("exit %d, stdout %q, stderr %q, want exit %d, stdout %q", r.code, r.out, r.err, tt.code, tt.want)
			}
			if !slices.Equal(h.Log["web1"], []string{"exec echo same"}) {
				t.Errorf("web1 ran %q", h.Log["web1"])
			}
			if h.Open != 0 {
				t.Errorf("%d sessions stay open", h.Open)
			}
		})
	}
}

// spec: CLI/JSON output (exec)
func TestExecJSON(t *testing.T) {
	h := fakehost.New()
	h.SetExec("web1", module.ExecResult{Output: "up\n"})
	h.SetExec("web2", module.ExecResult{Output: "x\n", ExitCode: 137, Signal: 9})
	r := winch(t, runProject(t), h, false, "", "exec", "all", "--json", "--", "uptime")
	lines := jsonLines(t, r.out)
	if r.code != exitFailed || len(lines) != 4 {
		t.Fatalf("exit %d, stdout %q", r.code, r.out)
	}
	for i, want := range []map[string]any{
		{"type": "version"},
		{"type": "exec", "host": "web1", "output": "up\n", "exit_code": 0.0},
		{"type": "exec", "host": "web2", "output": "x\n", "exit_code": 137.0},
		{"type": "summary", "exit_code": 1.0},
	} {
		for k, v := range want {
			if lines[i][k] != v {
				t.Errorf("line %d: %s = %v, want %v", i+1, k, lines[i][k], v)
			}
		}
	}
	h = fakehost.New()
	h.SetUnreachable("web2")
	r = winch(t, runProject(t), h, false, "", "exec", "all", "--json", "--", "uptime")
	lines = jsonLines(t, r.out)
	if r.code != exitUnreachable || len(lines) != 4 || lines[2]["type"] != "host" || lines[2]["phase"] != "exec" || lines[2]["status"] != "unreachable" || r.err != "" {
		t.Errorf("unreachable: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
}

// spec: CLI (winch exec)
func TestExecArgs(t *testing.T) {
	dir := runProject(t)
	usage := "winch exec: put the command after --, such as winch exec all -- uptime"
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"no --", []string{"all", "uptime"}, usage},
		{"nothing after --", []string{"all", "--"}, usage},
		{"no pattern", []string{"--", "uptime"}, "winch: exec needs one host pattern before --"},
		{"two patterns", []string{"web1", "web2", "--", "uptime"}, "winch: exec needs one host pattern before --"},
		{"--yes", []string{"all", "--yes", "--", "uptime"}, "flag provided but not defined: -yes"},
		{"no host", []string{"none", "--", "uptime"}, `winch exec: the host pattern "none" matches no host in inventories/test.yaml`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := fakehost.New()
			r := winch(t, dir, h, false, "", append([]string{"exec"}, tt.args...)...)
			if r.code != exitInvalid || !strings.Contains(r.err, tt.want) || len(h.Connects) != 0 {
				t.Errorf("exit %d, stderr %q, want %q", r.code, r.err, tt.want)
			}
		})
	}
	h := fakehost.New()
	r := winch(t, dir, h, true, "", "exec", "--batch", "web1", "--", "ls", "-la", "--json")
	if r.code != exitOK || !slices.Equal(h.Log["web1"], []string{"exec ls -la --json"}) || !slices.Equal(h.Batch, []bool{true}) {
		t.Errorf("exit %d, log %q, batch %v, stderr %q", r.code, h.Log["web1"], h.Batch, r.err)
	}
}

// spec: CLI/JSON output (diagnostic)
func TestRunJSONDiagnostic(t *testing.T) {
	r := winch(t, runProject(t), fakehost.New(), false, "", "run", "web1", "pkg", "nam=htop", "--json")
	lines := jsonLines(t, r.out)
	d := lines[1]
	if r.code != exitInvalid || d["type"] != "diagnostic" || d["file"] != nil || d["line"] != nil ||
		d["message"] != `winch run: nam=htop: unknown key "nam"; did you mean "name"?` {
		t.Errorf("exit %d, diagnostic %v", r.code, d)
	}
}

// spec: Variables/Secrets in output (winch exec)
func TestExecSecret(t *testing.T) {
	identity, id := newIdentity(t)
	dir := secretProject(t, id)
	setPassword(t, dir, encrypt(t, dir, "hunter2"))
	for _, json := range []bool{false, true} {
		h := fakehost.New()
		h.SetExec("web1", module.ExecResult{Output: "pw=hunter2\n"})
		args := []string{"exec", "web1", "--", "cat", "/etc/pw"}
		if json {
			args = []string{"exec", "web1", "--json", "--", "cat", "/etc/pw"}
		}
		r := winchWith(t, dir, "", identity, "", h, false, "", args...)
		if r.code != exitOK || strings.Contains(r.out, "hunter2") || !strings.Contains(r.out, "pw=(secret)") {
			t.Errorf("json %v: exit %d, stdout %q, stderr %q", json, r.code, r.out, r.err)
		}
	}
	r := winch(t, dir, fakehost.New(), false, "", "exec", "web1", "--", "uptime")
	if r.code != exitInvalid || !strings.Contains(r.err, "no age key") {
		t.Errorf("without an identity: exit %d, stderr %q", r.code, r.err)
	}
}
