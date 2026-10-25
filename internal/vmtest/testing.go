package vmtest

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/session"
)

// StartVM starts a VM and stops it when the test ends.
func (l *Lab) StartVM(t *testing.T, name string) *VM {
	t.Helper()
	vm, err := l.Start(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vm.Stop)
	return vm
}

// MustRun runs a command as root on the VM and fails the test on an error.
func (vm *VM) MustRun(t *testing.T, command string) string {
	t.Helper()
	out, err := vm.Run(t.Context(), command)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// WriteProject writes files into a new directory and returns it.
func WriteProject(t *testing.T, files map[string]string) string {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	dir := t.TempDir()
	if err := os.CopyFS(dir, fsys); err != nil {
		t.Fatal(err)
	}
	return dir
}

type Result struct {
	Code           int
	Stdout, Stderr string
}

// Winch runs the winch binary from WINCH_BIN in dir.
func (l *Lab) Winch(t *testing.T, dir string, args ...string) Result {
	t.Helper()
	return l.WinchEnv(t, dir, nil, args...)
}

// WinchEnv runs the winch binary from WINCH_BIN in dir, with env added to the
// environment.
func (l *Lab) WinchEnv(t *testing.T, dir string, env []string, args ...string) Result {
	t.Helper()
	bin := os.Getenv("WINCH_BIN")
	if bin == "" {
		t.Fatal("WINCH_BIN is not set; run make test-integration")
	}
	cmd := exec.CommandContext(t.Context(), bin, args...)
	cmd.Dir = dir
	cmd.Env = append(l.Env(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	r := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		r.Code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	t.Logf("winch %s: exit %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), r.Code, r.Stdout, r.Stderr)
	return r
}

// Session opens a helper session to the VM as admin. The lab's PATH must be
// the PATH of this process.
func (vm *VM) Session(t *testing.T) *session.Session {
	t.Helper()
	s, err := session.Open(t.Context(), session.Config{
		Host:     vm.Name,
		Address:  vm.Name,
		Binaries: helperbin.Binaries(),
		Hello:    protocol.Hello{Run: "test-" + t.Name(), User: "test", Machine: "test"},
		Progress: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Case is one module case: a start state, the arguments, and the expected
// check result. Every case also checks that a second check after apply is ok,
// or Want again when the case never converges.
type Case struct {
	Name string
	// Setup runs as root before the check.
	Setup string
	// State is the state of the run before the step.
	State module.State
	Args  module.Module
	// Want is the result of the check, and of the apply without Old.
	Want module.Result
	// WantState is the state after the check and after the apply.
	WantState module.State
	// Unchanged runs as root after the check and must exit 0: it shows that
	// the check changed nothing.
	Unchanged string
	// BeforeApply runs as root after the check and before apply.
	BeforeApply string
	// WantErr is part of the error of the first check.
	WantErr string
	// WantApplyErr is part of the error of apply.
	WantApplyErr string
	// After runs as root after apply, also after a failed one, and must
	// exit 0.
	After string
	// NoConverge marks a case where the host cannot reach the wanted state,
	// so the second check is Want again.
	NoConverge bool
}

// RunCases runs module cases one after another on one VM. reset runs as root
// before each case, so each case starts from its own Setup.
func RunCases(t *testing.T, vm *VM, name, reset string, cases []Case) {
	t.Helper()
	s := vm.Session(t)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			ctx := t.Context()
			vm.MustRun(t, reset+"\n"+c.Setup)
			st := c.State
			got, err := s.Check(ctx, name, c.Args, &st)
			if c.WantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.WantErr) {
					t.Fatalf("check error = %v, want %q", err, c.WantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if !equal(got, c.Want) {
				t.Fatalf("check = %s, want %s", show(got), show(c.Want))
			}
			if st != c.WantState {
				t.Fatalf("state after check = %+v, want %+v", st, c.WantState)
			}
			if c.Unchanged != "" {
				vm.MustRun(t, c.Unchanged)
			}
			if c.BeforeApply != "" {
				vm.MustRun(t, c.BeforeApply)
			}
			st = c.State
			applied, err := s.Apply(ctx, name, c.Args, &st, nil, nil)
			if c.WantApplyErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.WantApplyErr) {
					t.Fatalf("apply error = %v, want %q", err, c.WantApplyErr)
				}
				if c.After != "" {
					vm.MustRun(t, c.After)
				}
				return
			}
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			// Apply returns no old content; the plan has shown the diff.
			want := c.Want
			want.Old = nil
			if !equal(applied, want) {
				t.Errorf("apply = %s, want %s", show(applied), show(want))
			}
			if st != c.WantState {
				t.Errorf("state after apply = %+v, want %+v", st, c.WantState)
			}
			if c.After != "" {
				vm.MustRun(t, c.After)
			}
			want2 := module.Result{Status: module.OK}
			if c.NoConverge {
				want2 = c.Want
			}
			again, err := s.Check(ctx, name, c.Args, &module.State{})
			if err != nil || !equal(again, want2) {
				t.Fatalf("second check = %s, %v; want %s", show(again), err, show(want2))
			}
		})
	}
}

func equal(got, want module.Result) bool {
	if (got.Old == nil) != (want.Old == nil) || got.Old != nil && *got.Old != *want.Old {
		return false
	}
	return got.Status == want.Status && got.Action == want.Action && got.Link == want.Link && slices.Equal(got.Changes, want.Changes)
}

func show(r module.Result) string {
	old := "<nil>"
	if r.Old != nil {
		old = *r.Old
	}
	return string(r.Status) + " " + string(r.Action) + " " + strings.Join(r.Changes, "; ") + " old=" + old + " link=" + r.Link
}
