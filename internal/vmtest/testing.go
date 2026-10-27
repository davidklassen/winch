package vmtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/helperbin"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/session"
)

// StartVM starts a VM and stops it when the test ends.
func (l *Lab) StartVM(t *testing.T, name string) *VM {
	t.Helper()
	start := time.Now()
	vm, err := l.Start(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("vm %s is ready after %s", name, time.Since(start).Round(time.Millisecond))
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

// Serve serves data from the lab's HTTP server and returns its URL in the
// guest. name is a path below www/serve/.
func (l *Lab) Serve(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(l.Dir, "www", "serve", name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return "http://" + labAddr + "/serve/" + name
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
	return l.WinchBin(t, bin, dir, env, args...)
}

// WinchBin runs the winch binary bin in dir, with env added to the
// environment.
func (l *Lab) WinchBin(t *testing.T, bin, dir string, env []string, args ...string) Result {
	t.Helper()
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
	t.Logf("winch %s: exit %d\nstdout:\n%s\nstderr:\n%s%s", strings.Join(args, " "), r.Code, r.Stdout, r.Stderr, l.hint(r.Stdout+r.Stderr))
	failOnWarnings(t, args, r)
	return r
}

func failOnWarnings(t interface{ Errorf(string, ...any) }, args []string, r Result) {
	for _, w := range warnings(r.Stdout, r.Stderr) {
		t.Errorf("winch %s: unexpected warning: %s", strings.Join(args, " "), w)
	}
}

var textWarning = regexp.MustCompile(`^.*:\d+:\d+: warning: `)

// warnings returns the warnings of winch in its output.
func warnings(stdout, stderr string) []string {
	var out []string
	for line := range strings.Lines(stderr) {
		if textWarning.MatchString(line) {
			out = append(out, strings.TrimSuffix(line, "\n"))
		}
	}
	for line := range strings.Lines(stdout) {
		var ev struct{ Type, Severity string }
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Type == "diagnostic" && ev.Severity == "warning" {
			out = append(out, strings.TrimSuffix(line, "\n"))
		}
	}
	return out
}

// Session opens a helper session to the VM as admin. The lab's PATH must be
// the PATH of this process.
func (vm *VM) Session(t *testing.T) *session.Session {
	t.Helper()
	s, err := session.Open(t.Context(), session.Config{
		Host:     vm.Name,
		Address:  vm.Name,
		Binaries: helperbin.Binaries(),
		Hello:    protocol.Hello{Project: "test", Run: "test-" + t.Name(), User: "test", Machine: "test"},
		Progress: color.NewWriter(io.Discard, secret.NewFilter().Parts, false),
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
	// Want is the result of the check, and of the apply without Old and
	// OldReason.
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
	// Fix runs as root after a failed apply and removes its cause on the host.
	Fix string
	// FixArgs are the arguments without the cause of a failed apply, for a
	// cause in the arguments, such as a checksum that pins a bad archive.
	FixArgs module.Module
	// ErrAfterChange marks a failed apply that still reaches the wanted
	// state, so the next check is ok.
	ErrAfterChange bool
	// SkipRecovery names the issue that blocks the recovery of the case. The
	// case skips its recovery test.
	SkipRecovery string
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
				if c.Unchanged != "" {
					vm.MustRun(t, c.Unchanged)
				}
				return
			}
			if err != nil {
				t.Fatalf("check: %v%s", err, vm.lab.hint(err.Error()))
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
			applied, err := s.Apply(ctx, name, c.Args, &st, nil, nil, protocol.Guard{})
			// A guarded step started the rollback timer; the case keeps its
			// change.
			if err == nil && applied.Timer > 0 {
				err = s.Confirm(ctx)
				applied.Timer = 0
			}
			if c.WantApplyErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.WantApplyErr) {
					t.Fatalf("apply error = %v, want %q", err, c.WantApplyErr)
				}
				if c.After != "" {
					vm.MustRun(t, c.After)
				}
				checkRecovery(t, vm, s, name, c)
				return
			}
			if err != nil {
				t.Fatalf("apply: %v%s", err, vm.lab.hint(err.Error()))
			}
			// Apply returns no old content; the plan has shown the diff.
			want := c.Want
			want.Old, want.OldReason = nil, ""
			if !equal(applied, want) {
				t.Errorf("apply = %s, want %s", show(applied), show(want))
			}
			if st != c.WantState {
				t.Errorf("state after apply = %+v, want %+v", st, c.WantState)
			}
			if c.After != "" {
				vm.MustRun(t, c.After)
			}
			checkAgain(t, s, name, c)
		})
	}
}

// checkRecovery checks that the check after a failed apply is not ok, and that
// apply succeeds after the case's Fix or with its FixArgs. A check error counts
// as not ok, but the check after the fix must pass. With ErrAfterChange, the
// check after the failed apply is ok.
func checkRecovery(t *testing.T, vm *VM, s *session.Session, name string, c Case) {
	t.Helper()
	if c.SkipRecovery != "" {
		t.Skip(c.SkipRecovery)
	}
	if c.ErrAfterChange {
		checkAgain(t, s, name, c)
		return
	}
	if c.Fix == "" && c.FixArgs == nil {
		t.Fatal("the case has no Fix or FixArgs for its failed apply")
	}
	ctx := t.Context()
	st := c.State
	got, err := s.Check(ctx, name, c.Args, &st)
	if err == nil && got.Status == module.OK && !got.Deferred {
		t.Fatalf("check after the failed apply = %s, want a change", show(got))
	}
	if c.Fix != "" {
		vm.MustRun(t, c.Fix)
	}
	if c.FixArgs != nil {
		c.Args = c.FixArgs
	}
	st = c.State
	if _, err := s.Check(ctx, name, c.Args, &st); err != nil {
		t.Fatalf("check after the fix: %v", err)
	}
	st = c.State
	applied, err := s.Apply(ctx, name, c.Args, &st, nil, nil, protocol.Guard{})
	if err == nil && applied.Timer > 0 {
		err = s.Confirm(ctx)
	}
	if err != nil {
		t.Fatalf("apply after the fix: %v%s", err, vm.lab.hint(err.Error()))
	}
	checkAgain(t, s, name, c)
}

// checkAgain checks that a second check after apply is ok, or Want for a case
// that never converges.
func checkAgain(t *testing.T, s *session.Session, name string, c Case) {
	t.Helper()
	want := module.Result{Status: module.OK}
	if c.NoConverge {
		want = c.Want
	}
	got, err := s.Check(t.Context(), name, c.Args, &module.State{})
	if err != nil || !equal(got, want) {
		t.Fatalf("second check = %s, %v; want %s", show(got), err, show(want))
	}
}

func equal(got, want module.Result) bool {
	if (got.Old == nil) != (want.Old == nil) || got.Old != nil && *got.Old != *want.Old {
		return false
	}
	return got.Status == want.Status && got.Action == want.Action && got.OldReason == want.OldReason && got.Link == want.Link && slices.Equal(got.Changes, want.Changes) && slices.Equal(got.StartedBy, want.StartedBy) && got.Deferred == want.Deferred
}

func show(r module.Result) string {
	old := "<nil>"
	if r.Old != nil {
		old = *r.Old
	}
	return string(r.Status) + " " + string(r.Action) + " " + strings.Join(r.Changes, "; ") + " old=" + old + " old reason=" + r.OldReason + " link=" + r.Link + " started by=" + strings.Join(r.StartedBy, " ") + " deferred=" + strconv.FormatBool(r.Deferred)
}
