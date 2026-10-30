package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/yamlx"
)

// TestMain runs the timer process when a test helper starts this binary as
// the helper binary.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--rollback" {
		if err := RunTimer(context.Background(), os.Args[2], 10*time.Millisecond); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type lockout struct {
	dir  string
	c    *client
	a, b string
}

// startLockout starts a helper of the project acme that can start timers,
// and writes the files a and b with "old".
func startLockout(t *testing.T) *lockout {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	l := &lockout{dir: t.TempDir()}
	files := t.TempDir()
	l.a, l.b = filepath.Join(files, "a"), filepath.Join(files, "b")
	write(t, l.a, "old\n")
	write(t, l.b, "old\n")
	l.c = start(t, l.dir, self)
	h := hello("r1")
	h.Project = "acme"
	if r := l.c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	return l
}

func fileArgs(p, content string) json.RawMessage {
	uid, gid := yamlx.NameOrID(strconv.Itoa(os.Getuid())), yamlx.NameOrID(strconv.Itoa(os.Getgid()))
	args, _ := json.Marshal(module.File{Path: p, Data: []byte(content), Owner: uid, Group: gid, Mode: "0600"})
	return args
}

func failingFileArgs(p string) json.RawMessage {
	uid, gid := yamlx.NameOrID(strconv.Itoa(os.Getuid())), yamlx.NameOrID(strconv.Itoa(os.Getgid()))
	validate := "false"
	args, _ := json.Marshal(module.File{Path: p, Data: []byte("bad\n"), Owner: uid, Group: gid, Mode: "0600", Validation: &validate})
	return args
}

// applyBoth applies "new" to a with the store of recipe ssh, and to b with
// confirm_access, and returns the result of the second apply.
func (l *lockout) applyBoth(t *testing.T) protocol.StepResult {
	t.Helper()
	g := protocol.Guard{Recipe: "ssh", Save: true}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"ssh.reload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	g.Confirm = true
	r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.b, "new\n"), Guard: g, Notify: []string{"ssh.restart"}, Then: &protocol.Then{Recipe: "ssh", Module: "file", Mains: []string{"2"}}})
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	var res protocol.StepResult
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func content(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (l *lockout) job() string { return filepath.Join(l.dir, "rollback", "timer.json") }

// spec: Running a pipeline/Lockout protection (the helper stops the timer
// when the second connection works)
func TestConfirmStopsTheTimer(t *testing.T) {
	l := startLockout(t)
	res := l.applyBoth(t)
	if res.Timer <= 50*time.Second || res.Timer >= TimerTime {
		t.Errorf("timer = %v, want the time left of %v", res.Timer, TimerTime)
	}
	data, err := os.ReadFile(l.job())
	if err != nil {
		t.Fatalf("no timer job: %v", err)
	}
	var j job
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(j.Deadline); left < 50*time.Second || left > TimerTime {
		t.Errorf("the timer ends in %v, want about 60s", left)
	}
	var paths []string
	for _, s := range j.Restore {
		paths = append(paths, s.Path)
	}
	if want := []string{l.a, l.b}; !slices.Equal(paths, want) {
		t.Errorf("the timer puts back %v, want the store of the recipe %v", paths, want)
	}
	if r := l.c.call(t, "confirm", nil); r.Error != "" {
		t.Fatalf("confirm: %s", r.Error)
	}
	if _, err := os.Lstat(l.job()); !os.IsNotExist(err) {
		t.Errorf("the timer job stays after confirm: %v", err)
	}
	if content(t, l.a) != "new\n" || content(t, l.b) != "new\n" {
		t.Error("confirm put back old content")
	}
	// The end of the session asks for a rollback.
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Errorf("a rollback after confirm: %s", r.Error)
	}
	if r := l.c.call(t, "confirm", nil); !strings.Contains(r.Error, "the rollback timer ended first") {
		t.Errorf("a second confirm: %q", r.Error)
	}
}

// spec: Running a pipeline/Lockout protection (the old files come back; the
// records of the failed step go)
func TestRollbackNow(t *testing.T) {
	l := startLockout(t)
	l.applyBoth(t)
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Fatalf("rollback: %s", r.Error)
	}
	if content(t, l.a) != "old\n" || content(t, l.b) != "old\n" {
		t.Errorf("after the rollback: a %q, b %q; want old", content(t, l.a), content(t, l.b))
	}
	// The end of the session asks for a rollback again.
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Errorf("a second rollback: %s", r.Error)
	}
	if _, err := os.Lstat(l.job()); !os.IsNotExist(err) {
		t.Errorf("the timer job stays after the rollback: %v", err)
	}
	p := pendingAll(t, l.c)
	if want := []string{"ssh.reload"}; !slices.Equal(p.Handlers, want) {
		t.Errorf("pending handlers %v, want %v: the rolled-back step's record goes", p.Handlers, want)
	}
	if len(p.Then) != 0 {
		t.Errorf("then records %v, want none", p.Then)
	}
}

// spec: Running a pipeline/Lockout protection (when the timer ends first, the
// old files come back)
func TestTimerFires(t *testing.T) {
	l := startLockout(t)
	l.applyBoth(t)
	data, err := os.ReadFile(l.job())
	if err != nil {
		t.Fatal(err)
	}
	var j job
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	j.Deadline = time.Now()
	data, _ = json.Marshal(j)
	if err := writeJob(l.job(), data); err != nil {
		t.Fatal(err)
	}
	for start := time.Now(); content(t, l.a) != "old\n" || content(t, l.b) != "old\n"; {
		if time.Since(start) > 10*time.Second {
			t.Fatalf("the timer process did not put back the files: a %q, b %q", content(t, l.a), content(t, l.b))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r := l.c.call(t, "confirm", nil); !strings.Contains(r.Error, "the rollback timer ended first; the old files are back") {
		t.Errorf("confirm after the timer: %q", r.Error)
	}
	// The timer alone leaves the records: the helper owns them.
	if p := pendingAll(t, l.c); !slices.Equal(p.Handlers, []string{"ssh.reload", "ssh.restart"}) || len(p.Then) != 1 {
		t.Errorf("records after the timer: %+v", p)
	}
}

// spec: Running a pipeline/Lockout protection (a guarded step that ends after
// its rollback timer fails; the old files are back)
func TestRollbackAfterTimer(t *testing.T) {
	l := startLockout(t)
	l.applyBoth(t)
	data, err := os.ReadFile(l.job())
	if err != nil {
		t.Fatal(err)
	}
	var j job
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	j.Deadline = time.Now()
	data, _ = json.Marshal(j)
	if err := writeJob(l.job(), data); err != nil {
		t.Fatal(err)
	}
	for start := time.Now(); content(t, l.a) != "old\n" || content(t, l.b) != "old\n"; {
		if time.Since(start) > 10*time.Second {
			t.Fatalf("the timer process did not put back the files: a %q, b %q", content(t, l.a), content(t, l.b))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Errorf("rollback after the timer: %q", r.Error)
	}
	p := pendingAll(t, l.c)
	if want := []string{"ssh.reload"}; !slices.Equal(p.Handlers, want) || len(p.Then) != 0 {
		t.Errorf("records after the rollback: %+v, want the handler %v", p, want)
	}
}

// spec: Running a pipeline/Lockout protection (the timer takes the job and its
// undo step fails: the helper reports the rollback failure)
func TestTimerRollbackFails(t *testing.T) {
	for _, method := range []string{"rollback", "confirm"} {
		t.Run(method, func(t *testing.T) {
			l := startLockout(t)
			l.applyBoth(t)
			data, err := os.ReadFile(l.job())
			if err != nil {
				t.Fatal(err)
			}
			var j job
			if err := json.Unmarshal(data, &j); err != nil {
				t.Fatal(err)
			}
			j.Deadline = time.Now()
			j.Undo = &undo{Module: "file", Args: failingFileArgs(l.b)}
			data, _ = json.Marshal(j)
			if err := writeJob(l.job(), data); err != nil {
				t.Fatal(err)
			}
			for start := time.Now(); ; time.Sleep(10 * time.Millisecond) {
				if _, err := os.Lstat(l.job()); os.IsNotExist(err) {
					break
				}
				if time.Since(start) > 10*time.Second {
					t.Fatal("the timer process did not take the job")
				}
			}
			r := l.c.call(t, method, nil)
			want := "file " + l.b + ": validate: false"
			if method == "confirm" {
				want = "the rollback timer ended first; the rollback failed: " + want
			}
			if !strings.HasPrefix(r.Error, want) {
				t.Errorf("%s after the timer: %q, want the rollback failure of the timer %q", method, r.Error, want)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection
func TestRunTimer(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	write(t, p, "old\n")
	saved, err := module.Save(module.Touch{Path: p, Tree: true}, filepath.Join(dir, "1.tar"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, p, "new\n")
	jobPath := filepath.Join(dir, "timer.json")
	data, _ := json.Marshal(job{Deadline: time.Now().Add(time.Hour), Restore: []module.Saved{saved}})
	write(t, jobPath, string(data))
	done := make(chan error, 1)
	go func() { done <- RunTimer(t.Context(), jobPath, 5*time.Millisecond) }()
	time.Sleep(50 * time.Millisecond)
	if err := os.Remove(jobPath); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || content(t, p) != "new\n" {
		t.Errorf("a stopped timer: %v, content %q", err, content(t, p))
	}

	data, _ = json.Marshal(job{Deadline: time.Now().Add(-time.Second), Restore: []module.Saved{saved}})
	write(t, jobPath, string(data))
	if err := RunTimer(t.Context(), jobPath, 5*time.Millisecond); err != nil || content(t, p) != "old\n" {
		t.Errorf("a timer at its deadline: %v, content %q", err, content(t, p))
	}
	for _, f := range []string{jobPath, jobPath + ".fired"} {
		if _, err := os.Lstat(f); !os.IsNotExist(err) {
			t.Errorf("%s stays: %v", f, err)
		}
	}
}

// spec: Remote execution/Helper (a session waits for no timer of an earlier
// run)
func TestHelloFailsWhileATimerRuns(t *testing.T) {
	dir := t.TempDir()
	deadline := time.Now().Add(time.Hour).UTC()
	data, _ := json.Marshal(job{Deadline: deadline})
	write(t, filepath.Join(dir, "rollback", "timer.json"), string(data))
	c := start(t, dir, "")
	r := c.call(t, "hello", hello("r1"))
	if want := "a rollback timer of an earlier run runs until " + deadline.Format(time.RFC3339) + "; run winch again after it ends"; r.Error != want {
		t.Errorf("hello: %q, want %q", r.Error, want)
	}
	if r := c.call(t, "facts", nil); r.Error != "the first request must be hello" {
		t.Errorf("a request after the failed hello: %q", r.Error)
	}
}

// spec: Remote execution/State on the host (rollback/: during a run); roadmap
// phase 16 (a pending handler has its files)
func TestStoresAfterTheSession(t *testing.T) {
	l := startLockout(t)
	g := protocol.Guard{Recipe: "ssh", Save: true}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"ssh.reload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	g = protocol.Guard{Recipe: "nginx", Save: true}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.b, "new\n"), Guard: g}); r.Error != "" {
		t.Fatal(r.Error)
	}
	g = protocol.Guard{Stage: "base", Save: true}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.b+"2", "new\n"), Guard: g}); r.Error != "" {
		t.Fatal(r.Error)
	}
	stores := func() []string {
		entries, _ := os.ReadDir(filepath.Join(l.dir, "rollback", "acme"))
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return names
	}
	if got := stores(); len(got) != 3 {
		t.Fatalf("stores during the session: %v", got)
	}
	l.end(t)

	// The reconnect after a reboot is the same run: every store stays.
	c := start(t, l.dir, "")
	h := hello("r1")
	h.Project, h.Resume = "acme", true
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got := stores(); len(got) != 3 {
		t.Errorf("stores after a reconnect: %v, want all three", got)
	}
	c.w.Close()
	if err := <-c.done; err != nil {
		t.Fatal(err)
	}

	// The next run keeps only the store of the recipe with a pending handler.
	c = start(t, l.dir, "")
	h = hello("r2")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got, want := stores(), []string{"recipe-ssh"}; !slices.Equal(got, want) {
		t.Errorf("stores at the next hello: %v, want %v: the pending handler keeps its store", got, want)
	}
	if r := c.call(t, "handled", protocol.Handled{Name: "ssh.reload"}); r.Error != "" {
		t.Fatal(r.Error)
	}
	c.w.Close()
	if err := <-c.done; err != nil {
		t.Fatal(err)
	}
	c = start(t, l.dir, "")
	h = hello("r3")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got := stores(); len(got) != 0 {
		t.Errorf("stores after the handler ran: %v", got)
	}
}

// spec: Running a pipeline/Lockout protection; Handlers (a pending handler
// of a stage keeps the store of that stage of that pipeline)
func TestStageStoreOfAPendingHandler(t *testing.T) {
	l := startLockout(t)
	g := protocol.Guard{Pipeline: "site", Stage: "web", Save: true}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"site\tweb\treload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	g.Pipeline = "deploy"
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.b, "new\n"), Guard: g}); r.Error != "" {
		t.Fatal(r.Error)
	}
	l.end(t)
	c := start(t, l.dir, "")
	h := hello("r2")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	entries, _ := os.ReadDir(filepath.Join(l.dir, "rollback", "acme"))
	if len(entries) != 1 {
		t.Fatalf("stores at the next hello: %v, want one", entries)
	}
	all, err := readIndex(filepath.Join(l.dir, "rollback", "acme", entries[0].Name()))
	if err != nil || len(all) != 1 || all[0].Path != l.a {
		t.Errorf("the kept store holds %+v, %v; want the old state of %s", all, err, l.a)
	}
}

// spec: Remote execution/Helper (a second session fails on the lock and
// changes nothing)
func TestLockedHelloKeepsTheStores(t *testing.T) {
	l := startLockout(t)
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: protocol.Guard{Recipe: "ssh", Save: true}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	other := start(t, l.dir, "")
	h := hello("r2")
	h.Project = "acme"
	if r := other.call(t, "hello", h); !strings.Contains(r.Error, "locked by run") {
		t.Fatalf("second hello: %q", r.Error)
	}
	other.w.Close()
	if err := <-other.done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(l.dir, "rollback", "acme", "recipe-ssh", "index")); err != nil {
		t.Errorf("the store of the running session is gone: %v", err)
	}
}

// spec: Running a pipeline/Lockout protection (a timer that no process runs
// any more: its job runs at the next hello)
func TestHelloRunsADeadTimer(t *testing.T) {
	for _, name := range []string{"timer.json", "timer.json.fired"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(t.TempDir(), "f")
			write(t, p, "old\n")
			saved, err := module.Save(module.Touch{Path: p, Tree: true}, filepath.Join(t.TempDir(), "1.tar"))
			if err != nil {
				t.Fatal(err)
			}
			write(t, p, "new\n")
			data, _ := json.Marshal(job{Deadline: time.Now().Add(-time.Minute), Restore: []module.Saved{saved}})
			write(t, filepath.Join(dir, "rollback", name), string(data))
			c := start(t, dir, "")
			if r := c.call(t, "hello", hello("r1")); r.Error != "" {
				t.Fatalf("hello: %s", r.Error)
			}
			if content(t, p) != "old\n" {
				t.Errorf("content %q: the dead timer's files are not back", content(t, p))
			}
			for _, f := range []string{"timer.json", "timer.json.fired"} {
				if _, err := os.Lstat(filepath.Join(dir, "rollback", f)); !os.IsNotExist(err) {
					t.Errorf("%s stays: %v", f, err)
				}
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (a path keeps its first saved
// state; an archive name is never taken twice)
func TestStoreKeepsTheFirstState(t *testing.T) {
	l := startLockout(t)
	// A file that a failed save left behind.
	write(t, filepath.Join(l.dir, "rollback", "acme", "recipe-ssh", "1.tar"), "junk")
	g := protocol.Guard{Recipe: "ssh", Save: true}
	for _, c := range []string{"one\n", "two\n"} {
		if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, c), Guard: g}); r.Error != "" {
			t.Fatal(r.Error)
		}
	}
	g.Confirm = true
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.b, "new\n"), Guard: g}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Fatal(r.Error)
	}
	if content(t, l.a) != "old\n" {
		t.Errorf("a after the rollback: %q, want the state before the first change", content(t, l.a))
	}
}

// spec: Running a pipeline/Lockout protection (a removal of a directory whose
// attributes the store has keeps its tree too)
func TestStoreSavesATreeAfterAttributes(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(t.TempDir(), "conf.d")
	write(t, filepath.Join(d, "x.conf"), "x\n")
	rb := &rollbacks{dir: dir, project: "acme"}
	store := rb.scope(protocol.Guard{Recipe: "ssh"})
	if _, _, err := rb.save(store, &module.Dir{Path: d}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	_, all, err := rb.save(store, &module.Dir{Path: d, Absent: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(d); err != nil {
		t.Fatal(err)
	}
	if err := module.Restore(t.Context(), all); err != nil {
		t.Fatal(err)
	}
	if content(t, filepath.Join(d, "x.conf")) != "x\n" {
		t.Error("x.conf is not back")
	}
	if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("conf.d after the rollback: %v, %v; want mode 0700", fi, err)
	}
}

// spec: Running a pipeline/Lockout protection (the timer job: the store of
// the recipe and the undo step for confirm_access; the step's own paths for
// another guarded step)
func TestTimerJob(t *testing.T) {
	l := startLockout(t)
	rb := &rollbacks{dir: filepath.Join(l.dir, "rollback"), project: "acme", self: "/usr/bin/true"}
	saved := []module.Saved{{Path: "/b", Missing: true}}
	all := []module.Saved{{Path: "/a", Missing: true}, {Path: "/b", Missing: true}}
	read := func() job {
		data, err := os.ReadFile(rb.job())
		if err != nil {
			t.Fatal(err)
		}
		var j job
		if err := json.Unmarshal(data, &j); err != nil {
			t.Fatal(err)
		}
		return j
	}
	if _, err := startTimer(rb, protocol.Guard{Recipe: "ssh", Confirm: true}, &module.Service{Name: "ssh", Restarted: true}, saved, all); err != nil {
		t.Fatal(err)
	}
	j := read()
	if len(j.Restore) != 2 || j.Undo == nil || j.Undo.Module != "service" || string(j.Undo.Args) != `{"name":"ssh","restarted":true}` {
		t.Errorf("confirm_access job: %+v", j)
	}
	if _, err := startTimer(rb, protocol.Guard{Stage: "base"}, &module.File{Path: "/b"}, saved, all); err != nil {
		t.Fatal(err)
	}
	if j := read(); len(j.Restore) != 1 || j.Restore[0].Path != "/b" || j.Undo != nil {
		t.Errorf("guarded job: %+v", j)
	}
}

// spec: Running a pipeline/Lockout protection (a failed guarded step puts back
// the old files at once)
func TestFailedGuardedApplyRollsBack(t *testing.T) {
	l := startLockout(t)
	g := protocol.Guard{Recipe: "ssh", Save: true}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g}); r.Error != "" {
		t.Fatal(r.Error)
	}
	g.Confirm = true
	r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: failingFileArgs(l.b), Guard: g})
	if !strings.Contains(r.Error, "validate: false") || !strings.HasSuffix(r.Error, "; the old files are back") {
		t.Errorf("apply error %q, want the validate error and the rollback", r.Error)
	}
	if content(t, l.a) != "old\n" || content(t, l.b) != "old\n" {
		t.Errorf("after the failed step: a %q, b %q; want old", content(t, l.a), content(t, l.b))
	}
	if _, err := os.Lstat(l.job()); !os.IsNotExist(err) {
		t.Errorf("the timer job stays: %v", err)
	}
}

// spec: Running a pipeline/Lockout protection (a step saves in the store of
// its own recipe and in that of each recipe whose confirm_access handler it
// notifies)
func TestStepSavesInTheNotifiedStores(t *testing.T) {
	l := startLockout(t)
	g := protocol.Guard{Recipe: "ssh", Save: true, Handlers: []string{"nftables.reload"}}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"nftables.reload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	rb := &rollbacks{dir: filepath.Join(l.dir, "rollback"), project: "acme"}
	for _, recipe := range []string{"ssh", "nftables"} {
		saved, err := readIndex(rb.scope(protocol.Guard{Recipe: recipe}))
		if err != nil {
			t.Fatal(err)
		}
		if len(saved) != 1 || saved[0].Path != l.a {
			t.Errorf("the store of %s holds %+v, want %s", recipe, saved, l.a)
		}
	}
}

// spec: Running a pipeline/Lockout protection (a failed copy into the store of
// a notified recipe fails the step and drops its records)
func TestFailedNotifiedSaveFailsTheStep(t *testing.T) {
	l := startLockout(t)
	// A file in place of the store directory fails the save.
	rb := &rollbacks{dir: filepath.Join(l.dir, "rollback"), project: "acme"}
	store := rb.scope(protocol.Guard{Recipe: "nftables"})
	mkdir(t, filepath.Dir(store))
	write(t, store, "")
	g := protocol.Guard{Recipe: "app", Handlers: []string{"nftables.reload"}}
	r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"nftables.reload"}, Then: &protocol.Then{Recipe: "app", Module: "file", Mains: []string{"1"}}})
	if !strings.Contains(r.Error, "not a directory") {
		t.Fatalf("apply error %q, want the failed save", r.Error)
	}
	if content(t, l.a) != "old\n" {
		t.Error("the step changed the file after the failed save")
	}
	if p := pendingAll(t, l.c); len(p.Handlers) != 0 || len(p.Then) != 0 {
		t.Errorf("pending %+v, want no records of the failed step", p)
	}
}

// spec: Running a pipeline/Lockout protection (a failed copy fails the step
// before it changes anything)
func TestFailedSaveFailsTheStep(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(t.TempDir(), "d")
	mkdir(t, d)
	if err := syscall.Mkfifo(filepath.Join(d, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	rb := &rollbacks{dir: dir, project: "acme"}
	_, _, err := rb.save(rb.scope(protocol.Guard{Recipe: "ssh"}), &module.Dir{Path: d, Absent: true})
	if err == nil || !strings.HasPrefix(err.Error(), "keep the old state of "+d+" for the rollback: ") || !strings.Contains(err.Error(), "is a named pipe") {
		t.Fatalf("save of an unsavable tree: %v", err)
	}
	if lines, _ := index(rb.scope(protocol.Guard{Recipe: "ssh"})).read(); len(lines) != 0 {
		t.Errorf("a failed save wrote the index: %q", lines)
	}
}

// end closes the input of the helper and waits until it ends.
func (l *lockout) end(t *testing.T) {
	t.Helper()
	l.c.w.Close()
	if err := <-l.c.done; err != nil {
		t.Fatalf("the helper ended with %v", err)
	}
}

// spec: Running a pipeline/Lockout protection (the run of a host ends before
// a notified handler with confirm_access ran)
func TestEndPutsBackTheStoreOfAPendingHandler(t *testing.T) {
	for _, tt := range []struct {
		name    string
		guard   protocol.Guard
		handler string
	}{
		{"recipe", protocol.Guard{Recipe: "ssh", Save: true}, "ssh.reload"},
		{"stage", protocol.Guard{Pipeline: "site", Stage: "base", Save: true}, "site\tbase\treload"},
		{"other recipe", protocol.Guard{Recipe: "app"}, "nftables.reload"},
	} {
		l := startLockout(t)
		g := tt.guard
		g.Handlers = []string{tt.handler}
		notify := []string{tt.handler, "app.restart"}
		if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: notify}); r.Error != "" {
			t.Fatal(r.Error)
		}
		l.end(t)
		if got := content(t, l.a); got != "old\n" {
			t.Errorf("%s: a = %q, want the old file", tt.name, got)
		}
		lines, err := records{dir: filepath.Join(l.dir, "handlers"), project: "acme"}.read()
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"app.restart"}; !slices.Equal(lines, want) {
			t.Errorf("%s: pending %q, want %q", tt.name, lines, want)
		}
	}
}

// spec: Running a pipeline/Lockout protection
func TestEndKeepsTheFilesOfAHandlerThatRan(t *testing.T) {
	l := startLockout(t)
	g := protocol.Guard{Recipe: "ssh", Save: true, Handlers: []string{"ssh.reload"}}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"ssh.reload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := l.c.call(t, "handled", protocol.Handled{Name: "ssh.reload"}); r.Error != "" {
		t.Fatal(r.Error)
	}
	l.end(t)
	if got := content(t, l.a); got != "new\n" {
		t.Errorf("a = %q, want the new file", got)
	}
}

// spec: Running a pipeline/Lockout protection (when the session is gone, the
// old files come back)
func TestEndRollsBackARunningTimer(t *testing.T) {
	l := startLockout(t)
	g := protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"ssh.restart"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	l.end(t)
	if got := content(t, l.a); got != "old\n" {
		t.Errorf("a = %q, want the old file at once", got)
	}
	if _, err := os.Lstat(l.job()); !os.IsNotExist(err) {
		t.Errorf("the timer job stays: %v", err)
	}
	lines, err := records{dir: filepath.Join(l.dir, "handlers"), project: "acme"}.read()
	if err != nil || len(lines) != 0 {
		t.Errorf("pending %q, %v; want none", lines, err)
	}
}

// spec: Running a pipeline/Lockout protection (only the store of the handler
// comes back)
func TestEndPutsBackOnlyTheStoreOfThePendingHandler(t *testing.T) {
	l := startLockout(t)
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.b, "new\n"), Guard: protocol.Guard{Recipe: "nginx", Save: true}, Notify: []string{"nginx.reload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	g := protocol.Guard{Recipe: "app", Handlers: []string{"nftables.reload"}}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"nftables.reload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	l.end(t)
	if a, b := content(t, l.a), content(t, l.b); a != "old\n" || b != "new\n" {
		t.Errorf("a = %q, b = %q; want a old and b new", a, b)
	}
}

// spec: Running a pipeline/Lockout protection (a handler whose files did not
// come back stays pending)
func TestEndKeepsTheHandlerWhenTheRestoreFails(t *testing.T) {
	l := startLockout(t)
	g := protocol.Guard{Recipe: "ssh", Save: true, Handlers: []string{"ssh.reload"}}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"ssh.reload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	// A read-only directory fails the restore.
	if err := os.Chmod(filepath.Dir(l.a), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Dir(l.a), 0o700) }) //nolint:errcheck // the test cleans up
	l.c.w.Close()
	if err := <-l.c.done; err == nil || !strings.Contains(err.Error(), "put back the files of the handler ssh.reload") {
		t.Fatalf("the helper ended with %v, want the failed restore", err)
	}
	lines, err := records{dir: filepath.Join(l.dir, "handlers"), project: "acme"}.read()
	if err != nil || !slices.Equal(lines, []string{"ssh.reload"}) {
		t.Errorf("pending %q, %v; want ssh.reload", lines, err)
	}
}

// spec: Running a pipeline/Lockout protection (a timer that a confirm or the
// helper's rollback stopped has ended before the next guarded step starts
// one: an old timer must not take the next job)
func TestStoppedTimerHasEnded(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"confirm", "rollback"} {
		t.Run(method, func(t *testing.T) {
			rb := &rollbacks{dir: t.TempDir(), project: "acme", self: self}
			if err := rb.start(job{Deadline: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			timer := rb.timer
			if method == "confirm" {
				err = rb.confirm(t.Context())
			} else {
				err = rb.rollback(t.Context())
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-timer:
			default:
				t.Errorf("%s returned while the timer process still runs", method)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (a timer that ended without a
// result: the helper reports neither the old files nor an earlier result)
func TestTimerWithoutResult(t *testing.T) {
	rb := &rollbacks{dir: t.TempDir(), project: "acme", self: "/usr/bin/true"}
	write(t, result(rb.job()), "an earlier failure")
	if err := rb.start(job{Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// The timer took the job and ended before it wrote its result.
	if err := os.Remove(rb.job()); err != nil {
		t.Fatal(err)
	}
	if err := rb.rollback(t.Context()); err == nil || err.Error() != "the rollback timer ended without a result" {
		t.Errorf("rollback: %v", err)
	}
}
