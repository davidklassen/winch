package module

import (
	"os"
	"path/filepath"
	"testing"
)

// spec: Modules (the table); Modules/cmd
func TestCmdValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"command", "command: make install\n", ""},
		{"all fields", "command: make install\ncreates: /usr/local/bin/app\nuser: deploy\ndir: /srv/app\n", ""},
		{"no command", "creates: /x\n", `t.yaml:1:1: missing key "command"`},
		{"empty command", "command: \"\"\n", `t.yaml:1:10: command: must not be empty`},
		{"relative creates", "command: x\ncreates: bin/app\n", `t.yaml:2:10: creates: must be an absolute path`},
		{"unclean creates", "command: x\ncreates: /usr/local/bin/\n", `t.yaml:2:10: creates: must be a clean path, such as "/usr/local/bin"`},
		{"creates with dots", "command: x\ncreates: /srv/../etc\n", `t.yaml:2:10: creates: ".." is not allowed; write the path without it`},
		{"creates with a control character", "command: x\ncreates: \"/srv/a\\tb\"\n", `t.yaml:2:10: creates: has a control character`},
		{"creates with *", "command: x\ncreates: /opt/app/*.jar\n", `t.yaml:2:10: creates: names one path; "*" is not allowed`},
		{"creates with ?", "command: x\ncreates: /opt/app?\n", `t.yaml:2:10: creates: names one path; "?" is not allowed`},
		{"creates with [", "command: x\ncreates: /opt/app[12]\n", `t.yaml:2:10: creates: names one path; "[" is not allowed`},
		{"relative dir", "command: x\ndir: srv/app\n", `t.yaml:2:6: dir: must be an absolute path`},
		{"bad user", "command: x\nuser: Deploy\n", `t.yaml:2:7: user: "Deploy" is not a user name; a name has lower-case letters, digits, "_", and "-", and starts with a letter or "_"`},
		{"numeric user", "command: x\nuser: \"1000\"\n", `t.yaml:2:7: user: "1000" is not a user name; a name has lower-case letters, digits, "_", and "-", and starts with a letter or "_"`},
		{"unknown key", "command: x\ncreate: /x\n", `t.yaml:2:1: unknown key "create"; did you mean "creates"?`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Cmd{}, tt.yaml, tt.want) })
	}
}

// spec: Modules (the table); Modules/assert
func TestAssertValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"both", "command: systemctl is-active nginx\nmessage: nginx does not run\n", ""},
		{"no message", "command: \"true\"\n", `t.yaml:1:1: missing key "message"`},
		{"no command", "message: x\n", `t.yaml:1:1: missing key "command"`},
		{"empty command", "command: \"\"\nmessage: x\n", `t.yaml:1:10: command: must not be empty`},
		{"empty message", "command: \"true\"\nmessage: \"\"\n", `t.yaml:2:10: message: must not be empty`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Assert{}, tt.yaml, tt.want) })
	}
}

// spec: Running a pipeline/Plan; Modules/cmd
func TestCmdCheck(t *testing.T) {
	dir := t.TempDir()
	exists := filepath.Join(dir, "exists")
	if err := os.WriteFile(exists, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nothing"), dangling); err != nil {
		t.Fatal(err)
	}
	ran := filepath.Join(dir, "ran")
	command := "touch " + ran
	tests := []struct {
		name    string
		creates string
		want    Result
	}{
		{"without creates", "", Result{Status: Unknown}},
		{"creates exists", exists, Result{Status: OK}},
		{"creates is missing", filepath.Join(dir, "missing"), Result{Status: Change, Action: Create}},
		{"creates in a missing directory", filepath.Join(dir, "missing", "x"), Result{Status: Change, Action: Create}},
		{"creates is a dangling link", dangling, Result{Status: OK}},
		{"creates under a file", filepath.Join(exists, "x"), Result{Status: Change, Action: Create}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&Cmd{Command: command, Creates: tt.creates}).Check(t.Context(), &State{}, func(string) {})
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tt.want.Status || got.Action != tt.want.Action || got.Deferred {
				t.Errorf("check = %+v, want %+v", got, tt.want)
			}
			if _, err := os.Stat(ran); err == nil {
				t.Error("the check ran the command")
			}
		})
	}
}

// spec: Modules (the command rules); Modules/cmd
func TestCmdApply(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := (&Cmd{Command: "pwd > " + out}).Apply(t.Context(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != "/\n" {
		t.Errorf("without dir: pwd = %q, want /", got)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Cmd{Command: "pwd -P > out", Dir: dir}).Apply(t.Context(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != real+"\n" {
		t.Errorf("with dir: pwd = %q, want %q", got, real)
	}
	err = (&Cmd{Command: "echo the cause; exit 3"}).Apply(t.Context(), func(string) {})
	if want := "echo the cause; exit 3: exit status 3: the cause"; err == nil || err.Error() != want {
		t.Errorf("a failing command: %v, want %q", err, want)
	}
	missing := filepath.Join(dir, "missing")
	err = (&Cmd{Command: "true", Dir: missing}).Apply(t.Context(), func(string) {})
	if want := "dir " + missing + ": no such file or directory"; err == nil || err.Error() != want {
		t.Errorf("a missing dir: %v, want %q", err, want)
	}
	err = (&Cmd{Command: "true", Creates: missing}).Apply(t.Context(), func(string) {})
	if want := "the command did not create " + missing; err == nil || err.Error() != want {
		t.Errorf("creates is missing after the command: %v, want %q", err, want)
	}
	if err := (&Cmd{Command: "touch " + missing, Creates: missing}).Apply(t.Context(), func(string) {}); err != nil {
		t.Errorf("a command that creates creates: %v", err)
	}
	os.Remove(missing)
	err = (&Cmd{Command: "true", Dir: out}).Apply(t.Context(), func(string) {})
	if want := "dir " + out + ": not a directory"; err == nil || err.Error() != want {
		t.Errorf("a dir that is a file: %v, want %q", err, want)
	}
}

// spec: Modules/assert
func TestAssert(t *testing.T) {
	dir := t.TempDir()
	ran := filepath.Join(dir, "ran")
	a := &Assert{Command: "touch " + ran + "; exit 3", Message: "port 25 is blocked"}
	got, err := a.Check(t.Context(), &State{}, func(string) {})
	if err != nil || got.Status != OK || !got.Deferred || got.Action != "" {
		t.Errorf("check = %+v, %v; want ok and deferred", got, err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("the check ran the command")
	}
	if err := a.Apply(t.Context(), func(string) {}); err == nil || err.Error() != "port 25 is blocked" {
		t.Errorf("a failing assert: %v, want the message", err)
	}
	if _, err := os.Stat(ran); err != nil {
		t.Error("apply did not run the command")
	}
	if err := (&Assert{Command: "true", Message: "x"}).Apply(t.Context(), func(string) {}); err != nil {
		t.Errorf("a passing assert: %v", err)
	}
}

// spec: Steps (name: the plan shows the module and its main argument)
func TestCommandMain(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"make install", "make install"},
		{"cd /srv\nmake install\n", "cd /srv ..."},
		{"make install\n", "make install"},
	}
	for _, tt := range tests {
		if got := (&Cmd{Command: tt.command}).Main(); got != tt.want {
			t.Errorf("cmd %q: Main = %q, want %q", tt.command, got, tt.want)
		}
		if got := (&Assert{Command: tt.command}).Main(); got != tt.want {
			t.Errorf("assert %q: Main = %q, want %q", tt.command, got, tt.want)
		}
	}
}
