package cli

import (
	"bytes"
	"context"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

func writeProject(t *testing.T, pipeline string) string {
	return vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n",
		"pipelines/site.yaml":   pipeline,
	})
}

const motd = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: "hello\n"
`

type result struct {
	code     int
	out, err string
}

func winch(t *testing.T, dir string, h *fakehost.Hosts, terminal bool, stdin string, args ...string) result {
	t.Helper()
	return winchWith(t, dir, "", "", "", h, terminal, stdin, args...)
}

// winchWith runs winch with the home directory home and WINCH_AGE_KEY set to
// ageKey.
func winchWith(t *testing.T, dir, home, ageKey, ageCmd string, h *fakehost.Hosts, terminal bool, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Main(context.Background(), args, Env{
		Dir:      dir,
		In:       strings.NewReader(stdin),
		Out:      &out,
		Err:      &errOut,
		Terminal: terminal,
		Connect:  h.ConnectorFor,
		Home:     home,
		AgeKey:   ageKey,
		AgeCmd:   ageCmd,
		Filter:   secret.NewFilter(),
		Now:      fixedNow,
	})
	return result{code, out.String(), errOut.String()}
}

// fixedNow is the clock of the JSON events in tests.
func fixedNow() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }

// spec: CLI/Exit codes
func TestInvalid(t *testing.T) {
	dir := writeProject(t, motd)
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no command", nil, "Commands:"},
		{"unknown command", []string{"aply", "site"}, `unknown command "aply"; did you mean "apply"?`},
		{"unknown flag", []string{"plan", "site", "--nope"}, "flag provided but not defined: -nope"},
		{"no pipeline", []string{"plan"}, "name a pipeline: site; only steps at the top of winch.yaml run without a name"},
		{"two pipelines", []string{"apply", "site", "other"}, "apply takes one pipeline"},
		{"unknown pipeline", []string{"plan", "sit"}, `unknown pipeline "sit"; did you mean "site"?`},
		{"validate with argument", []string{"validate", "site"}, "validate takes no arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := winch(t, dir, fakehost.New(), false, "", tt.args...)
			if r.code != exitInvalid {
				t.Errorf("exit code %d, want %d", r.code, exitInvalid)
			}
			if !strings.Contains(r.err, tt.wantErr) {
				t.Errorf("stderr = %q, want %q", r.err, tt.wantErr)
			}
		})
	}
}

// spec: CLI/Errors
func TestInvalidProject(t *testing.T) {
	dir := writeProject(t, "stages:\n  - name: base\n    hosts: all\n    steps:\n      - fiel: {}\n")
	for _, cmd := range []string{"validate", "plan", "apply"} {
		args := []string{cmd}
		if cmd != "validate" {
			args = append(args, "site")
		}
		r := winch(t, dir, fakehost.New(), false, "", args...)
		want := "pipelines/site.yaml:5:9: unknown module \"fiel\"; did you mean \"file\"?\n"
		if r.code != exitInvalid || r.err != want {
			t.Errorf("%s: exit %d, stderr %q", cmd, r.code, r.err)
		}
	}
}

// spec: Running a pipeline/Order; CLI/Exit codes
func TestNoHost(t *testing.T) {
	const twoStages = "stages:\n  - name: base\n    hosts: all\n    steps: []\n  - name: mail\n    hosts: mail\n    steps: []\n"
	const noStage = "no stage of pipeline site matches a host in inventories/test.yaml"
	tests := []struct {
		name      string
		inventory string
		pipeline  string
		want      string
	}{
		{"an empty inventory", "", motd, `the host pattern "all" matches no host in inventories/test.yaml`},
		{"a comment-only inventory", "# no hosts yet\n", motd, `the host pattern "all" matches no host in inventories/test.yaml`},
		{"two stages on an empty inventory", "groups:\n  mail:\n    hosts: []\n", twoStages, noStage},
		{"no stage matches a host", "hosts:\n  web1: {}\ngroups:\n  mail:\n    hosts: []\n", strings.Replace(twoStages, "hosts: all\n", "hosts: mail\n", 1), noStage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: acme\ninventory: test\n",
				"inventories/test.yaml": tt.inventory,
				"pipelines/site.yaml":   tt.pipeline,
			})
			for _, args := range [][]string{{"plan", "site"}, {"plan", "site", "--exit-code"}, {"apply", "site", "--yes"}} {
				cmd := strings.Join(args, " ")
				h := fakehost.New()
				r := winch(t, dir, h, false, "", args...)
				want := "winch " + args[0] + ": " + tt.want + "\n"
				if r.code != exitInvalid || r.err != want {
					t.Errorf("%s: exit %d, stderr %q, want %q", cmd, r.code, r.err, want)
				}
				if len(h.Connects) != 0 {
					t.Errorf("%s: winch contacted a host", cmd)
				}
			}
		})
	}
}

func TestValidate(t *testing.T) {
	r := winch(t, writeProject(t, motd), fakehost.New(), false, "", "validate")
	if r.code != exitOK || r.out != "ok\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
}

// spec: CLI
func TestValidateSet(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\n",
		"inventories/prod.yaml": "hosts:\n  web1: {}\n",
		"inventories/test.yaml": "hosts:\n  web2: {}\n",
		"pipelines/site.yaml":   strings.Replace(motd, `"hello\n"`, "!expr vars.release", 1),
	})
	r := winch(t, dir, fakehost.New(), false, "", "validate")
	if r.code != exitInvalid || !strings.Contains(r.err, `pipelines/site.yaml:7:20: unknown variable "release"`) {
		t.Errorf("without --set: exit %d, stderr %q", r.code, r.err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "validate", "--set", "vars.release=1.4.2")
	if r.code != exitOK || r.out != "ok\n" {
		t.Errorf("with --set: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
}

func TestExamples(t *testing.T) {
	entries, err := os.ReadDir("../../examples")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			r := winch(t, "../../examples/"+e.Name(), fakehost.New(), false, "", "validate")
			if r.code != exitOK || r.out != "ok\n" || r.err != "" {
				t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
			}
		})
	}
}

// spec: CLI
func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"plan", "--help"}, {"apply", "-h"}, {"validate", "--help"}, {"secret", "--help"}, {"secret", "encrypt", "--help"}, {"secret", "generate", "--help"}, {"secret", "rekey", "-h"}, {"fmt", "--help"}} {
		r := winch(t, t.TempDir(), fakehost.New(), false, "", args...)
		if r.code != exitOK {
			t.Errorf("%v: exit %d", args, r.code)
		}
		if !strings.HasPrefix(r.out, "Examples:\n  winch ") {
			t.Errorf("%v: help does not start with examples:\n%s", args, r.out)
		}
	}
}

// spec: Running a pipeline/Plan
func TestPlan(t *testing.T) {
	h := fakehost.New()
	r := winch(t, writeProject(t, motd), h, true, "", "plan", "site")
	if r.code != exitOK || !strings.Contains(r.out, "+ file /etc/motd") {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	if _, ok := h.File("web1", "/etc/motd"); ok || h.Applies != 0 {
		t.Error("plan changed a host")
	}
}

// spec: Running a pipeline/Apply
func TestApply(t *testing.T) {
	dir := writeProject(t, motd)
	t.Run("yes", func(t *testing.T) {
		h := fakehost.New()
		r := winch(t, dir, h, false, "", "apply", "site", "--yes")
		if r.code != exitOK || !strings.Contains(r.out, "web1: base: + file /etc/motd") {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
		}
		if c, _ := h.File("web2", "/etc/motd"); c != "hello\n" {
			t.Errorf("web2 /etc/motd = %q", c)
		}
		r = winch(t, dir, h, false, "", "apply", "site")
		if r.code != exitOK || !strings.Contains(r.out, "2 hosts: 0 to change, 2 unchanged, 0 unknown\nplan ") {
			t.Errorf("second apply: exit %d, stdout %q", r.code, r.out)
		}
	})
	// spec: Running a pipeline/Apply
	t.Run("only a gone record", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			terminal bool
			args     []string
		}{
			{"yes", false, []string{"--yes"}},
			{"no terminal", false, nil},
			{"terminal", true, nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h := fakehost.New()
				h.SetFile("web1", "/etc/motd", "hello\n")
				h.SetFile("web2", "/etc/motd", "hello\n")
				h.SetThen("web1", protocol.Then{Pipeline: "site", Stage: "base", Module: "file", Mains: []string{"/etc/aliases"}})
				if r := winch(t, dir, h, false, "", "plan", "site", "--exit-code"); r.code != exitOK {
					t.Errorf("plan --exit-code: exit %d", r.code)
				}
				r := winch(t, dir, h, tc.terminal, "", append([]string{"apply", "site"}, tc.args...)...)
				if r.code != exitOK || !strings.Contains(r.out, "2 hosts: 0 changed, 2 unchanged\n") || strings.Contains(r.err, "Apply these changes?") {
					t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
				}
				if got := h.ThenOf("web1"); len(got) != 0 {
					t.Errorf("then records after apply = %v, want none", got)
				}
			})
		}
	})
	t.Run("no terminal", func(t *testing.T) {
		h := fakehost.New()
		r := winch(t, dir, h, false, "", "apply", "site", "--inventory", "test")
		if r.code != exitConfirm {
			t.Errorf("exit %d, want %d", r.code, exitConfirm)
		}
		// spec: CLI/Prompts
		if want := "To apply, run: winch apply site --inventory test --check " + planHash(t, r.out) + "\n"; !strings.HasSuffix(r.out, want) {
			t.Errorf("stdout = %q, want suffix %q", r.out, want)
		}
		if h.Applies != 0 {
			t.Error("apply changed a host without confirmation")
		}
	})
	t.Run("answer no", func(t *testing.T) {
		h := fakehost.New()
		r := winch(t, dir, h, true, "n\n", "apply", "site")
		if r.code != exitOK || h.Applies != 0 {
			t.Errorf("exit %d, applies %d", r.code, h.Applies)
		}
		if !strings.Contains(r.err, "Apply these changes? [y/N] ") || !strings.Contains(r.err, "Nothing changed.") {
			t.Errorf("stderr = %q", r.err)
		}
	})
	t.Run("answer yes", func(t *testing.T) {
		h := fakehost.New()
		in := &answer{text: "y\n", hosts: h}
		var out, errOut bytes.Buffer
		code := Main(context.Background(), []string{"apply", "site"}, Env{
			Dir: dir, In: in, Out: &out, Err: &errOut, Terminal: true,
			Connect: h.ConnectorFor, Filter: secret.NewFilter(),
		})
		if code != exitOK || h.Applies != 2 {
			t.Errorf("exit %d, applies %d", code, h.Applies)
		}
		// spec: Remote execution/Sessions
		if in.open != 0 {
			t.Errorf("%d sessions were open at the question", in.open)
		}
	})
	t.Run("a failed host wins over confirmation", func(t *testing.T) {
		h := fakehost.New()
		h.FailCheck("web1")
		r := winch(t, dir, h, false, "", "apply", "site")
		if r.code != exitFailed || !strings.HasSuffix(r.out, "To apply, run: winch apply site --check "+planHash(t, r.out)+"\n") {
			t.Errorf("exit %d, stdout %q", r.code, r.out)
		}
	})
	t.Run("a failed host", func(t *testing.T) {
		h := fakehost.New()
		h.FailApply("web1")
		r := winch(t, dir, h, false, "", "apply", "site", "--yes")
		if r.code != exitFailed {
			t.Errorf("exit %d, want %d", r.code, exitFailed)
		}
		if c, _ := h.File("web2", "/etc/motd"); c != "hello\n" {
			t.Error("the other host did not continue")
		}
	})
	t.Run("a failed check", func(t *testing.T) {
		h := fakehost.New()
		h.FailCheck("web1")
		r := winch(t, dir, h, false, "", "plan", "site")
		if r.code != exitFailed || !strings.Contains(r.err, "web1: base: file /etc/motd: permission denied") {
			t.Errorf("exit %d, stderr %q", r.code, r.err)
		}
	})
}

// answer is stdin for the question. It records how many sessions are open
// when winch reads the answer.
type answer struct {
	text  string
	hosts *fakehost.Hosts
	open  int
	read  bool
}

func (a *answer) Read(p []byte) (int, error) {
	if a.read {
		return 0, io.EOF
	}
	a.read = true
	a.open = a.hosts.Open
	return copy(p, a.text), nil
}

func TestQuote(t *testing.T) {
	tests := map[string]string{
		"inventories/test.yaml": "inventories/test.yaml",
		"my inventory.yaml":     "'my inventory.yaml'",
		"it's.yaml":             `'it'\''s.yaml'`,
	}
	for in, want := range tests {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestIsTerminal(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for _, f := range []*os.File{null, r, w} {
		if IsTerminal(f) {
			t.Errorf("%s is a terminal", f.Name())
		}
	}
}

const greeting = `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: !tpl "{{ .vars.greeting }}\n"
`

// spec: CLI ("--set vars.<name>=<value>"); Variables/Sources
func TestSet(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nvars:\n  greeting: hello\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n",
		"pipelines/site.yaml":   greeting,
	})
	r := winch(t, dir, fakehost.New(), false, "", "plan", "site", "--set", "vars.greeting=first", "--set", "vars.greeting=hi there")
	if r.code != exitOK || !strings.Contains(r.out, "+hi there\n") || strings.Contains(r.out, "first") {
		t.Errorf("plan with the last --set: exit %d, stdout %q", r.code, r.out)
	}
	r = winch(t, dir, fakehost.New(), false, "", "plan", "site", "--set", "vars.greting=x")
	if r.code != exitInvalid || !strings.Contains(r.err, `--set vars.greting=x: unknown variable "greting"; did you mean "greeting"?`) {
		t.Errorf("unknown variable: exit %d, stderr %q", r.code, r.err)
	}
	h := fakehost.New()
	r = winch(t, dir, h, false, "", "apply", "site", "--set", "vars.greeting=it's")
	if want := `To apply, run: winch apply site --set 'vars.greeting=it'\''s' --check ` + planHash(t, r.out) + "\n"; r.code != exitConfirm || !strings.HasSuffix(r.out, want) {
		t.Errorf("apply without a terminal: exit %d, stdout %q, want suffix %q", r.code, r.out, want)
	}
	r = winch(t, dir, h, false, "", "apply", "site", "--set", "vars.greeting=it's", "--yes")
	if c, _ := h.File("web1", "/etc/motd"); r.code != exitOK || c != "it's\n" {
		t.Errorf("apply: exit %d, /etc/motd %q", r.code, c)
	}
	r = winch(t, dir, fakehost.New(), false, "", "validate", "--set", "vars.greting=x")
	if r.code != exitInvalid || !strings.Contains(r.err, `--set vars.greting=x: unknown variable "greting"; did you mean "greeting"?`) {
		t.Errorf("validate with an unknown variable: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: CLI/Output
func TestLoadErrorPrintable(t *testing.T) {
	const rlo = "\u202e"
	pipeline := func(step string) string {
		return "stages:\n  - name: base\n    hosts: all\n    steps:\n      - " + step + "\n"
	}
	tests := []struct {
		name  string
		files map[string]string
	}{
		{name: "template-path", files: map[string]string{
			"pipelines/site.yaml":       pipeline("recipe: nginx"),
			"recipes/nginx/recipe.yaml": "steps:\n  - file:\n      path: /a\n      template: a" + rlo + "b.tmpl\n",
		}},
		{name: "recipe-name", files: map[string]string{
			"pipelines/site.yaml":               pipeline("recipe: a" + rlo + "b"),
			"recipes/a" + rlo + "b/recipe.yaml": "steps:\n  - fiel: {}\n",
		}},
		{name: "require-snippet-control-characters", files: map[string]string{
			"pipelines/site.yaml":       pipeline("recipe: nginx"),
			"recipes/nginx/recipe.yaml": "require:\n  - !expr \"\\\"\\e[2J\\\" + 1\"\nsteps: []\n",
		}},
		{name: "require-snippet-format-characters", files: map[string]string{
			"pipelines/site.yaml":       pipeline("recipe: nginx"),
			"recipes/nginx/recipe.yaml": "require:\n  - !expr \"\\\"\\u202E\\\" + 1\"\nsteps: []\n",
		}},
		{name: "require-check-format-characters", files: map[string]string{
			"pipelines/site.yaml":       pipeline("recipe: nginx"),
			"recipes/nginx/recipe.yaml": "require:\n  - !expr \"\\\"\\u202E\\\" + $env\"\nsteps: []\n",
		}},
		{name: "require-field-format-characters", files: map[string]string{
			"pipelines/site.yaml":       pipeline("recipe: nginx"),
			"recipes/nginx/recipe.yaml": "require:\n  - !expr \"facts[\\\"\\u202E\\\"] == 1\"\nsteps: []\n",
		}},
		{name: "warning", files: map[string]string{
			"pipelines/a" + rlo + "b.yaml": pipeline(`dir: {path: /srv/a, mode: "0640"}`),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"winch.yaml":            "name: acme\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  web1: {}\n",
			}
			maps.Copy(files, tt.files)
			dir := vmtest.WriteProject(t, files)
			text := winch(t, dir, fakehost.New(), false, "", "validate")
			js := winch(t, dir, fakehost.New(), false, "", "validate", "--json")
			golden.Assert(t, filepath.Join("testdata", "printable", tt.name+".golden"),
				[]byte("text:\n"+text.err+"json:\n"+js.out))
		})
	}
}
