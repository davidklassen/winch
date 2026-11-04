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

// expire moves the deadline of the timer job to now, after edit changes the
// job.
func (l *lockout) expire(t *testing.T, edit func(*job)) {
	t.Helper()
	data, err := os.ReadFile(l.job())
	if err != nil {
		t.Fatal(err)
	}
	var j job
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	j.Deadline = time.Now()
	if edit != nil {
		edit(&j)
	}
	data, _ = json.Marshal(j)
	if err := writeJob(l.job(), data); err != nil {
		t.Fatal(err)
	}
}

// waitTimer waits until the timer process takes the job.
func (l *lockout) waitTimer(t *testing.T) {
	t.Helper()
	for start := time.Now(); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Lstat(l.job()); os.IsNotExist(err) {
			return
		}
		if time.Since(start) > 10*time.Second {
			t.Fatal("the timer process did not take the job")
		}
	}
}

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
	l.expire(t, nil)
	for start := time.Now(); content(t, l.a) != "old\n" || content(t, l.b) != "old\n"; {
		if time.Since(start) > 10*time.Second {
			t.Fatalf("the timer process did not put back the files: a %q, b %q", content(t, l.a), content(t, l.b))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r := l.c.call(t, "confirm", nil); !strings.Contains(r.Error, "the rollback timer ended first; the old files are back") {
		t.Errorf("confirm after the timer: %q", r.Error)
	}
	p := pendingAll(t, l.c)
	if want := []string{"ssh.reload"}; !slices.Equal(p.Handlers, want) || len(p.Then) != 0 {
		t.Errorf("records after the confirm: %+v, want the handler %v", p, want)
	}
}

// spec: Running a pipeline/Lockout protection (a guarded step that ends after
// its rollback timer fails; the old files are back)
func TestRollbackAfterTimer(t *testing.T) {
	l := startLockout(t)
	l.applyBoth(t)
	l.expire(t, nil)
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
			l.expire(t, func(j *job) { j.Undo = []undo{{Module: "file", Args: failingFileArgs(l.b)}} })
			l.waitTimer(t)
			r := l.c.call(t, method, nil)
			want := "file " + l.b + ": validate failed, and the old file is back: false"
			if method == "confirm" {
				want = "the rollback timer ended first; the rollback failed: " + want
			}
			if !strings.HasPrefix(r.Error, want) {
				t.Errorf("%s after the timer: %q, want the rollback failure of the timer %q", method, r.Error, want)
			}
			if p := pendingAll(t, l.c); !slices.Equal(p.Handlers, []string{"ssh.reload", "ssh.restart"}) || len(p.Then) != 1 {
				t.Errorf("records after the failed rollback: %+v, want both handlers and the then record", p)
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
	data, _ := json.Marshal(job{Deadline: time.Now().Add(time.Hour), Restore: []module.Saved{saved}, Downloads: filepath.Join(dir, "downloads")})
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

	data, _ = json.Marshal(job{Deadline: time.Now().Add(-time.Second), Restore: []module.Saved{saved}, Downloads: filepath.Join(dir, "downloads")})
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
	holdLock(t, filepath.Join(dir, "rollback", "timer.json"))
	c := start(t, dir, "")
	r := c.call(t, "hello", hello("r1"))
	if want := "a rollback timer of an earlier run runs until " + deadline.Format(time.RFC3339) + "; run winch again after it ends"; r.Error != want {
		t.Errorf("hello: %q, want %q", r.Error, want)
	}
	if r := c.call(t, "facts", nil); r.Error != "the first request must be hello" {
		t.Errorf("a request after the failed hello: %q", r.Error)
	}
}

// holdLock takes the flock of the job file p, as a live timer process holds it.
func holdLock(t *testing.T, p string) {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

// spec: Running a pipeline/Lockout protection (a session fails while a timer
// still runs; a timer whose process is gone does not run on its own)
func TestIdleTellsATimerByItsLock(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	for _, name := range []string{"timer.json", "timer.json.fired"} {
		for _, c := range []struct {
			name     string
			deadline time.Time
			held     bool
			wantErr  string
		}{
			{"held before the deadline", future, true, "a rollback timer of an earlier run runs until " + future.Format(time.RFC3339) + "; run winch again after it ends"},
			{"held past the deadline", past, true, "a rollback timer of an earlier run started its rollback at " + past.Format(time.RFC3339) + "; run winch again after it ends"},
			{"free before the deadline", future, false, ""},
			{"free past the deadline", past, false, ""},
		} {
			t.Run(name+" "+c.name, func(t *testing.T) {
				rb := &rollbacks{dir: t.TempDir(), project: "acme"}
				p := filepath.Join(rb.dir, name)
				data, _ := json.Marshal(job{Version: jobVersion, Deadline: c.deadline})
				write(t, p, string(data))
				if c.held {
					holdLock(t, p)
				}
				err := rb.idle()
				if c.wantErr != "" {
					if err == nil || err.Error() != c.wantErr {
						t.Errorf("idle: %v, want %q", err, c.wantErr)
					}
					if len(rb.due) != 0 {
						t.Errorf("due %q, want none", rb.due)
					}
					return
				}
				if err != nil {
					t.Fatalf("idle: %v", err)
				}
				if !slices.Equal(rb.due, []string{p}) {
					t.Errorf("due %q, want the job", rb.due)
				}
			})
		}
	}
}

// spec: Running a pipeline/Lockout protection (the timer process holds the
// lock of its job from its start until it ends)
func TestTimerHoldsTheLockOfItsJob(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rb := &rollbacks{dir: t.TempDir(), project: "acme", self: self}
	if err := rb.start(job{Deadline: time.Now().Add(time.Hour), Downloads: filepath.Join(rb.dir, "downloads")}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(rb.job())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if free, err := tryLock(f); err != nil || free {
		t.Errorf("the lock of a started timer: free %v, %v", free, err)
	}
	if err := rb.confirm(t.Context()); err != nil {
		t.Fatal(err)
	}
	if free, err := tryLock(f); err != nil || !free {
		t.Errorf("the lock after the timer ended: free %v, %v", free, err)
	}
}

// spec: Running a pipeline/Lockout protection (a session fails while a timer
// still runs, also when its rollback runs long past the deadline)
func TestSlowRollbackIsNotDue(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, state := t.TempDir(), t.TempDir()
	running, release := filepath.Join(state, "running"), filepath.Join(state, "release")
	write(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\n: > "+running+"\nwhile [ ! -e "+release+" ]; do sleep 0.01; done\nexit 1\n")
	if err := os.Chmod(filepath.Join(bin, "systemctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	yes := true
	args, _ := json.Marshal(module.Service{Name: "app", Running: &yes})
	deadline := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	rb := &rollbacks{dir: t.TempDir(), project: "acme", self: self}
	if err := rb.start(job{Deadline: deadline, Undo: []undo{{Module: "service", Args: args}}, Downloads: filepath.Join(rb.dir, "downloads")}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		write(t, release, "")
		// The fake systemctl fails the rollback.
		if err := rb.timerResult(t.Context()); err == nil {
			t.Error("the rollback did not run the fake systemctl")
		}
	}()
	for {
		if _, err := os.Lstat(running); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	next := &rollbacks{dir: rb.dir, project: "acme"}
	want := "a rollback timer of an earlier run started its rollback at " + deadline.Format(time.RFC3339) + "; run winch again after it ends"
	if err := next.idle(); err == nil || err.Error() != want {
		t.Errorf("idle: %v, want %q", err, want)
	}
	if len(next.due) != 0 {
		t.Errorf("due %q, want none", next.due)
	}
}

// spec: Running a pipeline/Lockout protection (a command of the rollback keeps
// no lock of the timer: a process that it leaves would look like a live timer)
func TestTimerCommandsHaveNoLock(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "marker")
	write(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\nif (: <&3) 2>/dev/null; then echo open > "+marker+"; else echo closed > "+marker+"; fi\nexit 1\n")
	if err := os.Chmod(filepath.Join(bin, "systemctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	yes := true
	args, _ := json.Marshal(module.Service{Name: "app", Running: &yes})
	rb := &rollbacks{dir: t.TempDir(), project: "acme", self: self}
	j := job{Deadline: time.Now().Add(-time.Second), Undo: []undo{{Module: "service", Args: args}}, Downloads: filepath.Join(rb.dir, "downloads")}
	if err := rb.start(j); err != nil {
		t.Fatal(err)
	}
	// The fake systemctl fails the rollback after it wrote the marker.
	if err := rb.timerResult(t.Context()); err == nil {
		t.Fatal("the rollback did not run the fake systemctl")
	}
	if got := content(t, marker); got != "closed\n" {
		t.Errorf("the command sees the lock: %q", got)
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

// spec: Running a pipeline/Lockout protection (a timer whose process is gone
// does not run on its own: the plan shows its rollback, and apply runs it
// first)
func TestDeadTimer(t *testing.T) {
	for _, name := range []string{"timer.json", "timer.json.fired"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p, q := filepath.Join(t.TempDir(), "f"), filepath.Join(t.TempDir(), "g")
			write(t, p, "old\n")
			write(t, q, "new\n")
			store := filepath.Join(dir, "rollback", "acme", "recipe-ssh")
			mkdir(t, store)
			saved, err := module.Save(module.Touch{Path: p, Tree: true}, filepath.Join(store, "1.tar"))
			if err != nil {
				t.Fatal(err)
			}
			write(t, p, "new\n")
			data, _ := json.Marshal(job{Version: jobVersion, Deadline: time.Now().Add(-time.Minute), Restore: []module.Saved{saved},
				Undo: []undo{{Module: "file", Args: fileArgs(q, "undone\n")}}, Downloads: filepath.Join(dir, "downloads", "acme")})
			jobPath := filepath.Join(dir, "rollback", name)
			write(t, jobPath, string(data))
			h := hello("r1")
			h.Project = "acme"

			// The session of a plan shows the rollback and changes nothing.
			c := start(t, dir, "")
			if r := c.call(t, "hello", h); r.Error != "" {
				t.Fatalf("hello: %s", r.Error)
			}
			r := c.call(t, "pending", nil)
			var pending protocol.Pending
			if err := json.Unmarshal(r.Result, &pending); r.Error != "" || err != nil {
				t.Fatalf("pending: %s %v", r.Error, err)
			}
			if want := []string{"put back " + p, "file " + q}; !slices.Equal(pending.Rollback, want) {
				t.Errorf("pending rollback %q, want %q", pending.Rollback, want)
			}
			c.w.Close()
			if err := <-c.done; err != nil {
				t.Fatal(err)
			}
			if content(t, p) != "new\n" || content(t, q) != "new\n" {
				t.Errorf("after the plan's session: f %q, g %q; want both new", content(t, p), content(t, q))
			}
			if _, err := os.Lstat(jobPath); err != nil {
				t.Errorf("the job is gone after the plan's session: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(store, "1.tar")); err != nil {
				t.Errorf("the store is gone after the plan's session: %v", err)
			}

			// Apply runs it first.
			h.Run = "r2"
			c = start(t, dir, "")
			if r := c.call(t, "hello", h); r.Error != "" {
				t.Fatalf("hello: %s", r.Error)
			}
			if r := c.call(t, "due", nil); r.Error != "" {
				t.Fatalf("due: %s", r.Error)
			}
			if content(t, p) != "old\n" || content(t, q) != "undone\n" {
				t.Errorf("after the rollback: f %q, g %q; want old and undone", content(t, p), content(t, q))
			}
			for _, f := range []string{"timer.json", "timer.json.fired"} {
				if _, err := os.Lstat(filepath.Join(dir, "rollback", f)); !os.IsNotExist(err) {
					t.Errorf("%s stays: %v", f, err)
				}
			}
			if _, err := os.Lstat(store); !os.IsNotExist(err) {
				t.Errorf("the store of the earlier run stays after its rollback: %v", err)
			}
			r = c.call(t, "pending", nil)
			pending = protocol.Pending{}
			if err := json.Unmarshal(r.Result, &pending); r.Error != "" || err != nil || pending.Rollback != nil {
				t.Errorf("pending after the rollback: %+v, %s %v", pending, r.Error, err)
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
	if len(j.Restore) != 2 || len(j.Undo) != 1 || j.Undo[0].Module != "service" || string(j.Undo[0].Args) != `{"name":"ssh","restarted":true}` {
		t.Errorf("confirm_access job: %+v", j)
	}
	if _, err := startTimer(rb, protocol.Guard{Stage: "base"}, &module.File{Path: "/b"}, saved, all); err != nil {
		t.Fatal(err)
	}
	if j := read(); len(j.Restore) != 1 || j.Restore[0].Path != "/b" || len(j.Undo) != 0 {
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
	r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: failingFileArgs(l.b), Guard: g, Notify: []string{"ssh.restart"}, Then: &protocol.Then{Recipe: "ssh", Module: "file", Mains: []string{"2"}}})
	if !strings.Contains(r.Error, "validate failed, and the old file is back: false") || !strings.HasSuffix(r.Error, "; the old files are back") {
		t.Errorf("apply error %q, want the validate error and the rollback", r.Error)
	}
	if content(t, l.a) != "old\n" || content(t, l.b) != "old\n" {
		t.Errorf("after the failed step: a %q, b %q; want old", content(t, l.a), content(t, l.b))
	}
	if _, err := os.Lstat(l.job()); !os.IsNotExist(err) {
		t.Errorf("the timer job stays: %v", err)
	}
	if p := pendingAll(t, l.c); len(p.Handlers) != 0 || len(p.Then) != 0 {
		t.Errorf("records after the rollback: %+v, want none", p)
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

// spec: Running a pipeline/Lockout protection (when a rollback fails, the
// step's pending handlers and then commands stay recorded)
func TestFailedRollbackKeepsTheRecords(t *testing.T) {
	for _, how := range []string{"rollback", "failed step", "timer", "end"} {
		t.Run(how, func(t *testing.T) {
			l := startLockout(t)
			// A read-only directory fails the restore, and an apply.
			readOnly := func() {
				if err := os.Chmod(filepath.Dir(l.a), 0o500); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { os.Chmod(filepath.Dir(l.a), 0o700) }) //nolint:errcheck // the test cleans up
			if how == "failed step" {
				readOnly()
			}
			g := protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}
			r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"ssh.restart"}, Then: &protocol.Then{Recipe: "ssh", Module: "file", Mains: []string{"1"}}})
			if how != "failed step" {
				readOnly()
			}
			switch how {
			case "failed step":
				if !strings.Contains(r.Error, "; the rollback failed: ") {
					t.Fatalf("apply: %q, want the failed rollback", r.Error)
				}
			case "rollback":
				if r := l.c.call(t, "rollback", nil); r.Error == "" {
					t.Fatal("rollback passed, want the failed restore")
				}
			case "timer":
				l.expire(t, nil)
				l.waitTimer(t)
				if r := l.c.call(t, "rollback", nil); r.Error == "" {
					t.Fatal("rollback after the timer passed, want the failed restore of the timer")
				}
			case "end":
				l.c.w.Close()
				if err := <-l.c.done; err == nil {
					t.Fatal("the helper ended without an error, want the failed restore")
				}
			}
			handlers, err := records{dir: filepath.Join(l.dir, "handlers"), project: "acme"}.read()
			if err != nil {
				t.Fatal(err)
			}
			thens, err := records{dir: filepath.Join(l.dir, "then"), project: "acme"}.read()
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(handlers, []string{"ssh.restart"}) || len(thens) != 1 {
				t.Errorf("pending handlers %q, then records %q; want ssh.restart and the then record", handlers, thens)
			}
		})
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
			if err := rb.start(job{Deadline: time.Now().Add(time.Hour), Downloads: filepath.Join(rb.dir, "downloads")}); err != nil {
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

// spec: Running a pipeline/Lockout protection; Modules/download (a rollback
// drops the unpack records of the paths that it puts back, so the step
// unpacks again)
func TestRestoreDropsTheUnpackRecords(t *testing.T) {
	for _, tt := range []struct {
		name    string
		restore func(t *testing.T, l *lockout)
	}{
		{"session end", func(t *testing.T, l *lockout) {
			g := protocol.Guard{Recipe: "ssh", Save: true, Handlers: []string{"ssh.reload"}}
			if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "new\n"), Guard: g, Notify: []string{"ssh.reload"}}); r.Error != "" {
				t.Fatal(r.Error)
			}
			l.end(t)
		}},
		{"rollback timer", func(t *testing.T, l *lockout) {
			l.applyBoth(t)
			if r := l.c.call(t, "rollback", nil); r.Error != "" {
				t.Fatal(r.Error)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l := startLockout(t)
			downloads := records{dir: filepath.Join(l.dir, "downloads"), project: "acme"}
			keys := []string{l.a, l.a + "/x", filepath.Dir(l.a), l.a + "b", "/opt/other"}
			for _, k := range keys {
				if err := record(downloads, "sum:root:root", k); err != nil {
					t.Fatal(err)
				}
			}
			tt.restore(t, l)
			if got := content(t, l.a); got != "old\n" {
				t.Fatalf("a = %q, want the old file", got)
			}
			lines, err := downloads.read()
			want := []string{"sum:root:root " + l.a + "b", "sum:root:root /opt/other"}
			if err != nil || !slices.Equal(lines, want) {
				t.Errorf("unpack records %q, %v; want %q", lines, err, want)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection; Modules/download (a restore
// in an unpack tree changes the tree; one of the attributes of a directory
// above it does not)
func TestRestoreDropsTheRecordsOfTheTreesItChanges(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		saved module.Saved
		want  []string
	}{
		{"a file in the tree", module.Saved{Path: filepath.Join(app, "conf"), Missing: true}, []string{"sum:root:root /opt/other"}},
		{"the attributes of a directory above", module.Saved{Path: dir, Dir: &module.Attrs{UID: os.Getuid(), GID: os.Getgid(), Mode: 0o700}}, []string{"sum:root:root " + app, "sum:root:root /opt/other"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			downloads := downloadRecords(filepath.Join(t.TempDir(), "acme"))
			for _, k := range []string{app, "/opt/other"} {
				if err := record(downloads, "sum:root:root", k); err != nil {
					t.Fatal(err)
				}
			}
			if err := restore(t.Context(), downloads, []module.Saved{tt.saved}); err != nil {
				t.Fatal(err)
			}
			lines, err := downloads.read()
			if err != nil || !slices.Equal(lines, tt.want) {
				t.Errorf("unpack records %q, %v; want %q", lines, err, tt.want)
			}
		})
	}
}

// fakeSystemd puts a systemctl on PATH that keeps the active and enabled
// state of each unit in a file of its own, and sets the given states. A
// start of one SSH unit fails while the other one runs: both use port 22.
func fakeSystemd(t *testing.T, states map[string]string) func(unit string) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
d=` + dir + `
u=$(eval echo \${$#})
case $u in *.*) ;; *) u=$u.service ;; esac
case "$1" in
show)
	echo "Id=$u"
	echo LoadState=loaded
	echo "ActiveState=$(cat "$d/$u.active" 2>/dev/null || echo inactive)"
	echo "UnitFileState=$(cat "$d/$u.file" 2>/dev/null || echo disabled)"
	echo Type=notify
	echo InvocationID=1
	;;
start)
	case $u in ssh.service) o=ssh.socket ;; ssh.socket) o=ssh.service ;; esac
	if [ -n "$o" ] && grep -qx active "$d/$o.active" 2>/dev/null; then
		echo "$o holds port 22" >&2
		exit 1
	fi
	echo active > "$d/$u.active"
	;;
restart) echo active > "$d/$u.active" ;;
stop) echo inactive > "$d/$u.active" ;;
enable) echo enabled > "$d/$u.file" ;;
disable) echo disabled > "$d/$u.file" ;;
esac
`
	bin := filepath.Join(dir, "bin")
	write(t, filepath.Join(bin, "systemctl"), script)
	if err := os.Chmod(filepath.Join(bin, "systemctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	for unit, state := range states {
		active, file, _ := strings.Cut(state, " ")
		write(t, filepath.Join(dir, unit+".active"), active+"\n")
		write(t, filepath.Join(dir, unit+".file"), file+"\n")
	}
	return func(unit string) string {
		return strings.TrimSpace(content(t, filepath.Join(dir, unit+".active"))) + " " + strings.TrimSpace(content(t, filepath.Join(dir, unit+".file")))
	}
}

// spec: Running a pipeline/Lockout protection (the rollback of a switch
// between ssh.service and ssh.socket starts and enables the unit that the
// run stopped or disabled)
func TestRollbackOfASwitchOfTheSSHUnits(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		name              string
		off, guarded      module.Service
		service, socket   string
		wantSvc, wantSock string
	}{
		{"start", module.Service{Name: "ssh", Running: &no, Enabled: &no}, module.Service{Name: "ssh.socket", Running: &yes, Enabled: &yes}, "active enabled", "inactive disabled", "active enabled", "inactive enabled"},
		{"stop only", module.Service{Name: "ssh", Running: &no}, module.Service{Name: "ssh.socket", Running: &yes, Enabled: &yes}, "active disabled", "inactive disabled", "active disabled", "inactive enabled"},
		{"to ssh.service", module.Service{Name: "ssh.socket", Running: &no, Enabled: &no}, module.Service{Name: "ssh", Running: &yes, Enabled: &yes}, "inactive disabled", "active enabled", "inactive enabled", "active enabled"},
		// The socket stays up after the rollback of a restart, and holds
		// the port of ssh.service.
		{"restart", module.Service{Name: "ssh", Running: &no, Enabled: &no}, module.Service{Name: "ssh.socket", Restarted: true}, "active enabled", "active enabled", "inactive disabled", "active enabled"},
	} {
		t.Run(c.name, func(t *testing.T) {
			state := fakeSystemd(t, map[string]string{"ssh.service": c.service, "ssh.socket": c.socket})
			l := startLockout(t)
			off, _ := json.Marshal(c.off)
			if r := l.c.call(t, "apply", protocol.Step{Module: "service", Args: off, Guard: protocol.Guard{Recipe: "ssh", Save: true}}); r.Error != "" {
				t.Fatal(r.Error)
			}
			start, _ := json.Marshal(c.guarded)
			if r := l.c.call(t, "apply", protocol.Step{Module: "service", Args: start, Guard: protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}}); r.Error != "" {
				t.Fatal(r.Error)
			}
			if r := l.c.call(t, "rollback", nil); r.Error != "" {
				t.Fatalf("rollback: %s", r.Error)
			}
			if got := state("ssh.service"); got != c.wantSvc {
				t.Errorf("ssh.service after the rollback: %s, want %s", got, c.wantSvc)
			}
			if got := state("ssh.socket"); got != c.wantSock {
				t.Errorf("ssh.socket after the rollback: %s, want %s", got, c.wantSock)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (a dead timer whose rollback
// changes nothing does not stay due)
func TestDeadTimerWithoutChanges(t *testing.T) {
	dir := t.TempDir()
	q := filepath.Join(t.TempDir(), "g")
	write(t, q, "undone\n")
	write(t, filepath.Join(dir, "rollback", "acme", "recipe-ssh", "index"), "version 1\n")
	data, _ := json.Marshal(job{Version: jobVersion, Deadline: time.Now().Add(-time.Minute),
		Undo: []undo{{Module: "file", Args: fileArgs(q, "undone\n")}}, Downloads: filepath.Join(dir, "downloads", "acme")})
	write(t, filepath.Join(dir, "rollback", "timer.json"), string(data))
	h := hello("r1")
	h.Project = "acme"
	c := start(t, dir, "")
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatalf("hello: %s", r.Error)
	}
	r := c.call(t, "pending", nil)
	var pending protocol.Pending
	if err := json.Unmarshal(r.Result, &pending); r.Error != "" || err != nil || pending.Rollback != nil {
		t.Fatalf("pending: %+v, %s %v", pending, r.Error, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "rollback", "timer.json")); !os.IsNotExist(err) {
		t.Errorf("the job stays: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "rollback", "acme", "recipe-ssh")); !os.IsNotExist(err) {
		t.Errorf("the store of the earlier run stays: %v", err)
	}
}

// spec: Running a pipeline/Lockout protection (a damaged job of a dead timer
// cannot run: the session fails and names it)
func TestDamagedDeadTimer(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rollback", "timer.json")
	write(t, p, "{")
	c := start(t, dir, "")
	if r := c.call(t, "hello", hello("r1")); !strings.HasPrefix(r.Error, "the rollback timer of an earlier run ended without its process: read the rollback timer "+p) {
		t.Errorf("hello: %q", r.Error)
	}
}

// spec: State on the host (winch reads every older version of a file in
// rollback/<project>/: the timer job of a helper with one undo step and no
// version)
func TestDeadTimerOfVersion1(t *testing.T) {
	dir := t.TempDir()
	p, q := filepath.Join(t.TempDir(), "f"), filepath.Join(t.TempDir(), "g")
	write(t, p, "old\n")
	write(t, q, "old\n")
	saved, err := module.Save(module.Touch{Path: p, Tree: true}, filepath.Join(t.TempDir(), "1.tar"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, p, "new\n")
	data, _ := json.Marshal(map[string]any{
		"deadline":  time.Now().Add(-time.Minute),
		"restore":   []module.Saved{saved},
		"undo":      map[string]any{"module": "file", "args": fileArgs(q, "undone\n")},
		"downloads": filepath.Join(dir, "downloads", "acme"),
	})
	write(t, filepath.Join(dir, "rollback", "timer.json"), string(data))
	c := start(t, dir, "")
	if r := c.call(t, "hello", hello("r1")); r.Error != "" {
		t.Fatalf("hello: %s", r.Error)
	}
	if r := c.call(t, "due", nil); r.Error != "" {
		t.Fatalf("due: %s", r.Error)
	}
	if content(t, p) != "old\n" || content(t, q) != "undone\n" {
		t.Errorf("after the dead timer: f %q, g %q; want old and undone", content(t, p), content(t, q))
	}
}

// spec: State on the host (a version newer than winch knows fails the host)
func TestHelloFailsOnANewerTimerJob(t *testing.T) {
	for _, c := range []struct{ name, file, data string }{
		{"undo", "timer.json", `{"version":99,"deadline":"2000-01-01T00:00:00Z","undo":{"module":"file"}}`},
		{"restore", "timer.json", `{"version":99,"deadline":946684800,"restore":{"paths":[]}}`},
		{"fired", "timer.json.fired", `{"version":99,"deadline":"2000-01-01T00:00:00Z"}`},
		{"before its deadline", "timer.json", `{"version":99,"deadline":"2999-01-01T00:00:00Z"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			job := filepath.Join(dir, "rollback", c.file)
			write(t, job, c.data)
			cl := start(t, dir, "")
			if r := cl.call(t, "hello", hello("r1")); !strings.Contains(r.Error, "upgrade winch to read "+job) {
				t.Errorf("hello: %q, want the upgrade error", r.Error)
			}
			if _, err := os.Lstat(job); err != nil {
				t.Errorf("the job of the newer winch is gone: %v", err)
			}
		})
	}
}

// spec: Running a pipeline/Lockout protection (a step that changes sshd's
// config saves in the store of each later step with confirm_access that
// reloads or restarts sshd)
func TestRollbackPutsBackTheSSHDConfigOfOtherRecipes(t *testing.T) {
	l := startLockout(t)
	dropIn := filepath.Join(filepath.Dir(l.a), "drop-in.conf")
	g := protocol.Guard{Recipe: "hardening", SSHD: []string{"ssh", "site\tbase"}}
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(dropIn, "DenyUsers *\n"), Guard: g}); r.Error != "" {
		t.Fatal(r.Error)
	}
	rb := &rollbacks{dir: filepath.Join(l.dir, "rollback"), project: "acme"}
	for name, want := range map[string]int{"hardening": 0, "ssh": 1, "site\tbase": 1} {
		if saved, err := readIndex(rb.store(name)); err != nil || len(saved) != want {
			t.Errorf("the store of %q holds %+v, %v; want %d paths", name, saved, err, want)
		}
	}
	r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.b, "new\n"), Guard: protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}})
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Fatalf("rollback: %s", r.Error)
	}
	if _, err := os.Lstat(dropIn); !os.IsNotExist(err) {
		t.Errorf("the drop-in stays after the rollback: %v", err)
	}
	if content(t, l.b) != "old\n" {
		t.Errorf("b = %q after the rollback, want old", content(t, l.b))
	}
}

// spec: Running a pipeline/Lockout protection (the run of a host ends before
// a guarded sshd reload that holds saved sshd files ran)
func TestEndPutsBackTheSSHDFilesOfAReloadThatDidNotRun(t *testing.T) {
	for _, tt := range []struct {
		name string
		// reload is the guard of a later step, or nil when none runs.
		reload *protocol.Guard
		stays  bool
	}{
		{"no reload ran", nil, false},
		{"the reload ran", &protocol.Guard{Recipe: "ssh", Save: true, Confirm: true, LoadsSSHD: true}, true},
		{"the reload of another store ran", &protocol.Guard{Pipeline: "site", Stage: "late", Save: true, Confirm: true, LoadsSSHD: true}, true},
		{"another guarded step of the store ran", &protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}, false},
		{"the reload of a store without the file ran", &protocol.Guard{Pipeline: "site", Stage: "other", Save: true, Confirm: true, LoadsSSHD: true}, false},
	} {
		l := startLockout(t)
		dropIn := filepath.Join(filepath.Dir(l.a), "drop-in.conf")
		g := protocol.Guard{Recipe: "hardening", SSHD: []string{"ssh", "site\tlate"}}
		if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(dropIn, "DenyUsers *\n"), Guard: g}); r.Error != "" {
			t.Fatal(r.Error)
		}
		if tt.reload != nil {
			if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.b, "new\n"), Guard: *tt.reload}); r.Error != "" {
				t.Fatal(r.Error)
			}
			if r := l.c.call(t, "confirm", nil); r.Error != "" {
				t.Fatal(r.Error)
			}
		}
		l.end(t)
		if _, err := os.Lstat(dropIn); (err == nil) != tt.stays {
			t.Errorf("%s: the drop-in after the session: %v, want it to stay: %t", tt.name, err, tt.stays)
		}
		// The end puts back only the untested sshd files.
		if tt.reload != nil && content(t, l.b) != "new\n" {
			t.Errorf("%s: b = %q after the session, want the tested file", tt.name, content(t, l.b))
		}
		rb := &rollbacks{dir: filepath.Join(l.dir, "rollback"), project: "acme"}
		if lines, err := rb.sshd().read(); err != nil || len(lines) != 0 {
			t.Errorf("%s: sshd records after the session: %q, %v; want none", tt.name, lines, err)
		}
	}
}

// spec: Running a pipeline/Lockout protection (the run of a host ends before
// a guarded sshd reload that holds saved sshd files ran)
func TestEndPutsBackAnUntestedTreeAfterItsAttributes(t *testing.T) {
	d := filepath.Join(t.TempDir(), "conf.d")
	write(t, filepath.Join(d, "x.conf"), "x\n")
	rb := &rollbacks{dir: t.TempDir(), project: "acme"}
	store := rb.store("ssh")
	if _, _, err := rb.save(store, &module.Dir{Path: d}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rb.save(store, &module.Dir{Path: d, Absent: true}); err != nil {
		t.Fatal(err)
	}
	line, _ := json.Marshal(untestedFile{Store: "ssh", Path: d})
	if _, err := rb.sshd().add([]string{string(line)}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(d); err != nil {
		t.Fatal(err)
	}
	if err := rb.putBackUntested(t.Context()); err != nil {
		t.Fatal(err)
	}
	if content(t, filepath.Join(d, "x.conf")) != "x\n" {
		t.Error("x.conf is not back")
	}
	if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("conf.d after the put-back: %v, %v; want mode 0700", fi, err)
	}
}

// spec: Running a pipeline/Lockout protection (the rollback of a switch
// between ssh.service and ssh.socket, after a change of sshd's config of
// another recipe)
func TestRollbackOfASwitchPutsBackTheSSHDConfigOfOtherRecipes(t *testing.T) {
	yes, no := true, false
	state := fakeSystemd(t, map[string]string{"ssh.service": "inactive disabled", "ssh.socket": "active enabled"})
	l := startLockout(t)
	dropIn := filepath.Join(filepath.Dir(l.a), "drop-in.conf")
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(dropIn, "DenyUsers *\n"), Guard: protocol.Guard{Recipe: "hardening", SSHD: []string{"ssh"}}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	off, _ := json.Marshal(module.Service{Name: "ssh.socket", Running: &no, Enabled: &no})
	if r := l.c.call(t, "apply", protocol.Step{Module: "service", Args: off, Guard: protocol.Guard{Recipe: "ssh", Save: true}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	start, _ := json.Marshal(module.Service{Name: "ssh", Running: &yes, Enabled: &yes})
	if r := l.c.call(t, "apply", protocol.Step{Module: "service", Args: start, Guard: protocol.Guard{Recipe: "ssh", Save: true, Confirm: true, LoadsSSHD: true}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Fatalf("rollback: %s", r.Error)
	}
	if _, err := os.Lstat(dropIn); !os.IsNotExist(err) {
		t.Errorf("the drop-in stays after the rollback: %v", err)
	}
	if got := state("ssh.socket"); got != "active enabled" {
		t.Errorf("ssh.socket after the rollback: %s, want active enabled", got)
	}
	if got := state("ssh.service"); got != "inactive enabled" {
		t.Errorf("ssh.service after the rollback: %s, want inactive enabled", got)
	}
}

// spec: Running a pipeline/Lockout protection (an untested sshd file never
// stays on the host)
func TestRestartOfAStoppedUnitTestsNoSSHDFile(t *testing.T) {
	for _, tt := range []struct {
		state string
		stays bool
	}{
		{"active enabled", true},
		{"inactive disabled", false},
	} {
		fakeSystemd(t, map[string]string{"ssh.socket": tt.state})
		l := startLockout(t)
		dropIn := filepath.Join(filepath.Dir(l.a), "drop-in.conf")
		if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(dropIn, "DenyUsers *\n"), Guard: protocol.Guard{Recipe: "hardening", SSHD: []string{"ssh"}}}); r.Error != "" {
			t.Fatal(r.Error)
		}
		restart, _ := json.Marshal(module.Service{Name: "ssh.socket", Restarted: true})
		if r := l.c.call(t, "apply", protocol.Step{Module: "service", Args: restart, Guard: protocol.Guard{Recipe: "ssh", Save: true, Confirm: true, LoadsSSHD: true}}); r.Error != "" {
			t.Fatal(r.Error)
		}
		if r := l.c.call(t, "confirm", nil); r.Error != "" {
			t.Fatal(r.Error)
		}
		l.end(t)
		if _, err := os.Lstat(dropIn); (err == nil) != tt.stays {
			t.Errorf("ssh.socket %s: the drop-in after the session: %v, want it to stay: %t", tt.state, err, tt.stays)
		}
	}
}
