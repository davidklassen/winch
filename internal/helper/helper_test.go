package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"reflect"
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

type client struct {
	w    *io.PipeWriter
	r    *bufio.Scanner
	done chan error
	// exited closes when Serve returns.
	exited chan struct{}
	id     int
}

func start(t *testing.T, dir, self string) *client {
	t.Helper()
	return startAs(t, dir, self, 1000)
}

// startAs starts a helper whose session has the login user with the ID uid.
func startAs(t *testing.T, dir, self string, uid uint32) *client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &client{w: inW, r: bufio.NewScanner(outR), done: make(chan error, 1), exited: make(chan struct{})}
	go func() {
		err := Serve(context.Background(), inR, outW, dir, self, module.State{LoginUID: uid})
		close(c.exited)
		outW.Close()
		c.done <- err
	}()
	// The helper puts back files when its input closes, so the test waits
	// before its directories go.
	t.Cleanup(func() {
		inW.Close()
		<-c.exited
	})
	return c
}

func (c *client) call(t *testing.T, method string, params any) protocol.Response {
	t.Helper()
	c.id++
	p, _ := json.Marshal(params)
	req, _ := json.Marshal(protocol.Request{ID: c.id, Method: method, Params: p})
	go c.w.Write(append(req, '\n')) //nolint:errcheck // a failed write shows as a missing response
	var resp protocol.Response
	for resp.ID == 0 || resp.Note != "" || resp.Progress != "" {
		if !c.r.Scan() {
			t.Fatalf("no response: %v", c.r.Err())
		}
		resp = protocol.Response{}
		if err := json.Unmarshal(c.r.Bytes(), &resp); err != nil {
			t.Fatalf("bad response %q: %v", c.r.Bytes(), err)
		}
	}
	if resp.ID != c.id {
		t.Fatalf("response id %d, want %d", resp.ID, c.id)
	}
	return resp
}

func hello(run string) protocol.Hello {
	return protocol.Hello{Run: run, User: "alice", Machine: "laptop", Started: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
}

// spec: Remote execution/Helper
func TestLock(t *testing.T) {
	dir := t.TempDir()
	first := start(t, dir, "")
	if r := first.call(t, "hello", hello("r1")); r.Error != "" {
		t.Fatalf("first hello: %s", r.Error)
	}
	// Both helpers run in this process, so the record gets a PID that is not ours.
	lock := filepath.Join(dir, "lock")
	data, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec["pid"] != float64(os.Getpid()) {
		t.Errorf("lock file pid = %v, want %d", rec["pid"], os.Getpid())
	}
	rec["pid"] = 4242
	data, _ = json.Marshal(rec)
	if err := os.WriteFile(lock, data, 0o600); err != nil {
		t.Fatal(err)
	}
	second := start(t, dir, "")
	r := second.call(t, "hello", hello("r2"))
	want := "locked by run r1 (alice@laptop, since 2026-10-24T12:00:00Z, helper process 4242); if that run is gone, end it with: sudo kill 4242"
	if !strings.Contains(r.Error, want) {
		t.Errorf("second hello error = %q, want %q", r.Error, want)
	}
	first.w.Close()
	if err := <-first.done; err != nil {
		t.Fatal(err)
	}
	third := start(t, dir, "")
	if r := third.call(t, "hello", hello("r3")); r.Error != "" {
		t.Errorf("hello after release: %s", r.Error)
	}
}

// spec: Running a pipeline/Plan
func TestHelloReportsLogin(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	r := startAs(t, t.TempDir(), "", uint32(os.Getuid())).call(t, "hello", hello("r1"))
	var w protocol.Welcome
	if err := json.Unmarshal(r.Result, &w); r.Error != "" || err != nil || w.Login != me.Username {
		t.Errorf("hello = %s, %q; want the login %s", r.Result, r.Error, me.Username)
	}
}

// spec: Running a pipeline/Plan
func TestHelloReportsUnknownLogin(t *testing.T) {
	const uid = 3999999999
	r := startAs(t, t.TempDir(), "", uid).call(t, "hello", hello("r1"))
	var w protocol.Welcome
	if err := json.Unmarshal(r.Result, &w); r.Error != "" || err != nil || w != (protocol.Welcome{LoginUID: uid}) {
		t.Errorf("hello = %s, %q; want the login UID %d", r.Result, r.Error, uid)
	}
}

// spec: Remote execution/Helper
func TestLockWithoutPID(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
	}{
		{"empty", "", "locked by another run that is starting; run winch again to see which one"},
		{"half written", `{"run":"r2"}ne","started":"2026-10-24T12:00:00Z"}`, "locked by another run that is starting; run winch again to see which one"},
		{"no pid", `{"run":"r1","user":"alice","machine":"laptop","started":"2026-10-24T12:00:00Z"}`, "locked by run r1 (alice@laptop, since 2026-10-24T12:00:00Z)"},
		{"pid not a number", `{"run":"r1","user":"alice","machine":"laptop","started":"2026-10-24T12:00:00Z","pid":"x"}`, "locked by run r1 (alice@laptop, since 2026-10-24T12:00:00Z)"},
		{"pid 0", `{"run":"r1","user":"alice","machine":"laptop","started":"2026-10-24T12:00:00Z","pid":0}`, "locked by run r1 (alice@laptop, since 2026-10-24T12:00:00Z)"},
		{"pid -1", `{"run":"r1","user":"alice","machine":"laptop","started":"2026-10-24T12:00:00Z","pid":-1}`, "locked by run r1 (alice@laptop, since 2026-10-24T12:00:00Z)"},
		{"pid 1", `{"run":"r1","user":"alice","machine":"laptop","started":"2026-10-24T12:00:00Z","pid":1}`, "locked by run r1 (alice@laptop, since 2026-10-24T12:00:00Z)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f, err := os.Create(filepath.Join(dir, "lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteString(tc.content); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			r := start(t, dir, "").call(t, "hello", hello("r1"))
			if r.Error != tc.want {
				t.Errorf("hello error = %q, want %q", r.Error, tc.want)
			}
		})
	}
}

// TestLockHolder is not a test: it is the process that holds the lock for
// TestTakeOverLock.
func TestLockHolder(t *testing.T) {
	dir := os.Getenv("WINCH_TEST_LOCK_DIR")
	if dir == "" {
		return
	}
	if os.Getenv("WINCH_TEST_IGNORE_TERM") == "true" {
		signal.Ignore(syscall.SIGTERM)
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("WINCH_TEST_BUSY") == "true" {
		d, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := json.Marshal(lockRecord{Hello: hello(os.Getenv("WINCH_TEST_RUN")), PID: os.Getpid()})
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	os.Stdout.WriteString("ready\n") //nolint:errcheck // a failed write shows as a test that waits
	time.Sleep(time.Minute)
}

type holder struct {
	pid int
	// exited closes when the holder ends, with err its exit status.
	exited chan struct{}
	err    error
}

// startHolder starts a process that holds the lock of dir with the record of
// run.
func startHolder(t *testing.T, dir, run string, busy, ignoreTerm bool) *holder {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHolder$")
	cmd.Env = append(os.Environ(), "WINCH_TEST_LOCK_DIR="+dir, "WINCH_TEST_RUN="+run,
		"WINCH_TEST_BUSY="+strconv.FormatBool(busy), "WINCH_TEST_IGNORE_TERM="+strconv.FormatBool(ignoreTerm))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "ready\n" {
		cmd.Process.Kill() //nolint:errcheck // the test fails anyway
		t.Fatalf("lock holder: %q, %v", line, err)
	}
	h := &holder{pid: cmd.Process.Pid, exited: make(chan struct{})}
	go func() {
		h.err = cmd.Wait()
		close(h.exited)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck // the holder can be gone
		<-h.exited
	})
	return h
}

func (h *holder) wantSignal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	<-h.exited
	var exit *exec.ExitError
	if !errors.As(h.err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != sig {
		t.Errorf("holder ended with %v, want signal %v", h.err, sig)
	}
}

// spec: Remote execution/Sessions (the session kept through the question)
func TestTakeOverLock(t *testing.T) {
	for _, tc := range []struct {
		name     string
		run      string
		busy     bool
		takeOver bool
	}{
		{name: "idle helper of the same run", run: "r1", takeOver: true},
		{name: "busy helper of the same run", run: "r1", busy: true},
		{name: "idle helper of another run", run: "r2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			h := startHolder(t, dir, tc.run, tc.busy, false)
			r := start(t, dir, "").call(t, "hello", hello("r1"))
			if tc.takeOver {
				if r.Error != "" {
					t.Fatalf("hello: %s", r.Error)
				}
				h.wantSignal(t, syscall.SIGTERM)
				return
			}
			want := "locked by run " + tc.run + " (alice@laptop, since 2026-10-24T12:00:00Z, helper process " + strconv.Itoa(h.pid) + ")"
			if !strings.HasPrefix(r.Error, want) {
				t.Errorf("hello error = %q, want %q", r.Error, want)
			}
			select {
			case <-h.exited:
				t.Errorf("the holder ended: %v", h.err)
			default:
			}
		})
	}
}

// spec: Remote execution/Sessions (the session kept through the question)
func TestTakeOverKillsAfterGrace(t *testing.T) {
	dir := t.TempDir()
	h := startHolder(t, dir, "r1", false, true)
	f, err := os.Open(filepath.Join(dir, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if locked, err := takeOver(t.Context(), f, h.pid, 100*time.Millisecond); !locked || err != nil {
		t.Errorf("takeOver = %v, %v; want the lock", locked, err)
	}
	h.wantSignal(t, syscall.SIGKILL)
}

// spec: Remote execution/Sessions (the session kept through the question)
func TestLockBusyDuringRequest(t *testing.T) {
	dir := t.TempDir()
	busy := func() (bool, error) {
		d, err := os.Open(dir)
		if err != nil {
			return false, err
		}
		defer d.Close()
		locked, err := tryLock(d)
		return !locked, err
	}
	c := start(t, dir, "")
	c.call(t, "hello", hello("r1"))
	if b, err := busy(); b || err != nil {
		t.Errorf("after hello: busy %v, %v", b, err)
	}
	ready, done := filepath.Join(dir, "ready"), filepath.Join(dir, "done")
	during := make(chan error, 1)
	go func() {
		defer os.WriteFile(done, nil, 0o600) //nolint:errcheck // a failed write shows as a test that waits
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				during <- errors.New("exec did not start")
				return
			}
		}
		if b, err := busy(); !b || err != nil {
			during <- fmt.Errorf("not busy: %v", err)
			return
		}
		during <- nil
	}()
	if r := c.call(t, "exec", protocol.Exec{Command: ": > " + ready + "; while [ ! -e " + done + " ]; do sleep 0.01; done"}); r.Error != "" {
		t.Errorf("exec: %s", r.Error)
	}
	if err := <-during; err != nil {
		t.Errorf("during exec: %v", err)
	}
	if b, err := busy(); b || err != nil {
		t.Errorf("after exec: busy %v, %v", b, err)
	}
}

// spec: Remote execution/Helper
func TestHelloDeletesOldHelpers(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -31)
	for _, name := range []string{"old", "new", "self"} {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		if name != "new" {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := start(t, dir, filepath.Join(bin, "self"))
	if r := c.call(t, "hello", hello("r1")); r.Error != "" {
		t.Fatal(r.Error)
	}
	entries, _ := os.ReadDir(bin)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"new", "self"}) {
		t.Errorf("bin holds %v, want [new self]", names)
	}
	if fi, err := os.Stat(filepath.Join(bin, "self")); err != nil || time.Since(fi.ModTime()) > time.Hour {
		t.Errorf("the helper did not update the modification time of its own file")
	}
}

// spec: Remote execution/Helper (the check of every entry under the state
// directory)
func TestCheckTree(t *testing.T) {
	me := uint32(os.Getuid())
	tests := []struct {
		name  string
		owner uint32
		setup func(t *testing.T, dir string)
		want  string
	}{
		{"a correct tree", me, func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "handlers", "demo"), "version 1\n")
			write(t, filepath.Join(dir, "lock"), "")
			if err := os.Chmod(filepath.Join(dir, "handlers", "demo"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, ""},
		{"a rollback directory of another user", me + 1, func(t *testing.T, dir string) {
			mkdir(t, filepath.Join(dir, "rollback"))
		}, "rollback is not owned by root, or the group or others can write it"},
		{"a record the group can write", me, func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "handlers", "demo"), "version 1\n")
			if err := os.Chmod(filepath.Join(dir, "handlers", "demo"), 0o620); err != nil {
				t.Fatal(err)
			}
		}, "handlers/demo is not owned by root, or the group or others can write it"},
		{"a directory others can write", me, func(t *testing.T, dir string) {
			mkdir(t, filepath.Join(dir, "then"))
			if err := os.Chmod(filepath.Join(dir, "then"), 0o703); err != nil {
				t.Fatal(err)
			}
		}, "then is not owned by root, or the group or others can write it"},
		{"a symbolic link", me, func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "rollback", "a"), "")
			if err := os.Symlink("a", filepath.Join(dir, "rollback", "timer.json")); err != nil {
				t.Fatal(err)
			}
		}, "rollback/timer.json is not a directory or a regular file"},
		{"a pipe", me, func(t *testing.T, dir string) {
			if err := syscall.Mkfifo(filepath.Join(dir, "lock"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "lock is not a directory or a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)
			err := checkTree(dir, tt.owner)
			if tt.want == "" {
				if err != nil {
					t.Errorf("error = %v, want none", err)
				}
				return
			}
			want := filepath.Join(dir, tt.want)
			if err == nil || err.Error() != want {
				t.Errorf("error = %v, want %q", err, want)
			}
		})
	}
}

// spec: Remote execution/Helper (a wrong entry fails hello before it reads a
// record)
func TestHelloChecksTheTree(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rollback", "timer.json")
	data, _ := json.Marshal(job{Deadline: time.Now().Add(-time.Minute)})
	write(t, p, string(data))
	if err := os.Chmod(p, 0o660); err != nil {
		t.Fatal(err)
	}
	c := start(t, dir, "")
	r := c.call(t, "hello", hello("r1"))
	if want := p + " is not owned by root, or the group or others can write it"; !strings.Contains(r.Error, want) {
		t.Errorf("hello error = %q, want %q", r.Error, want)
	}
	if _, err := os.Lstat(p); err != nil {
		t.Errorf("the job ran: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "lock")); !os.IsNotExist(err) {
		t.Errorf("hello opened the lock: %v", err)
	}
}

// spec: Remote execution/Helper
func TestExitsOnEOF(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.w.Close()
	select {
	case err := <-c.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not exit")
	}
}

// spec: CLI (winch exec)
func TestExecStopsOnEOF(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.call(t, "hello", hello("r1"))
	ready := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan bool, 1)
	defer func() {
		cancel()
		if !<-done {
			t.Error("exec did not become ready")
		}
	}()
	go func() {
		seen := false
		defer func() {
			c.w.Close()
			done <- seen
		}()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err := os.Stat(ready); err == nil {
				seen = true
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	// Keep execution in the ready shell so SIGINT cannot race a child startup.
	r := c.call(t, "exec", protocol.Exec{Command: ": > " + ready + "; while :; do :; done"})
	var res module.ExecResult
	if err := json.Unmarshal(r.Result, &res); err != nil || r.Error != "" || res.Signal != 2 {
		t.Errorf("exec = %s, %q, want killed by signal 2", r.Result, r.Error)
	}
}

// spec: Modules (time limit)
func TestCommandFinishesAfterEOF(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.call(t, "hello", hello("r1"))
	time.AfterFunc(200*time.Millisecond, func() { c.w.Close() })
	if r := c.call(t, "command", protocol.Command{Command: "sleep 1"}); r.Error != "" {
		t.Errorf("command: %s", r.Error)
	}
}

func TestRequestsBeforeHello(t *testing.T) {
	c := start(t, t.TempDir(), "")
	r := c.call(t, "check", protocol.Step{Module: "file"})
	if r.Error != "the first request must be hello" {
		t.Errorf("error = %q", r.Error)
	}
}

func TestUnknownModule(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.call(t, "hello", hello("r1"))
	r := c.call(t, "check", protocol.Step{Module: "nope", Args: json.RawMessage(`{}`)})
	if r.Error != `unknown module "nope"` {
		t.Errorf("error = %q", r.Error)
	}
}

// spec: Modules/pkg
func TestStateRoundTrip(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.call(t, "hello", hello("r1"))
	args, _ := json.Marshal(module.File{Path: filepath.Join(t.TempDir(), "f"), Absent: true})
	r := c.call(t, "check", protocol.Step{Module: "file", Args: args, State: module.State{IndexFresh: true}})
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	var res protocol.StepResult
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if !res.State.IndexFresh || res.Status != module.OK {
		t.Errorf("result = %+v, want ok with the state of the request", res)
	}
}

func pendingAll(t *testing.T, c *client) protocol.Pending {
	t.Helper()
	r := c.call(t, "pending", nil)
	if r.Error != "" {
		t.Fatalf("pending: %s", r.Error)
	}
	var p protocol.Pending
	if err := json.Unmarshal(r.Result, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func pending(t *testing.T, c *client) []string {
	t.Helper()
	return pendingAll(t, c).Handlers
}

// spec: Handlers; Remote execution/State on the host
func TestPendingHandlers(t *testing.T) {
	dir := t.TempDir()
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	work := t.TempDir()
	remove := func(name string) json.RawMessage {
		p := filepath.Join(work, name)
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		args, _ := json.Marshal(module.File{Path: p, Absent: true})
		return args
	}

	// A check records nothing, also for a change.
	if r := c.call(t, "check", protocol.Step{Module: "file", Args: remove("a"), Notify: []string{"web.check"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	// An apply that finds nothing to change records nothing.
	gone, _ := json.Marshal(module.File{Path: filepath.Join(work, "gone"), Absent: true})
	if r := c.call(t, "apply", protocol.Step{Module: "file", Args: gone, Notify: []string{"web.ok"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got := pending(t, c); len(got) != 0 {
		t.Fatalf("pending after a check and an ok apply = %v, want none", got)
	}

	args := remove("b")
	if r := c.call(t, "apply", protocol.Step{Module: "file", Args: args, Notify: []string{"nginx.reload", "nginx.restart"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := c.call(t, "apply", protocol.Step{Module: "file", Args: remove("b"), Notify: []string{"nginx.reload"}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got, want := pending(t, c), []string{"nginx.reload", "nginx.restart"}; !slices.Equal(got, want) {
		t.Fatalf("pending = %v, want %v", got, want)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "handlers", "acme")); err != nil || string(data) != "version 1\nnginx.reload\nnginx.restart\n" {
		t.Errorf("handlers/acme = %q, %v", data, err)
	}

	if r := c.call(t, "handled", protocol.Handled{Name: "nginx.reload"}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got, want := pending(t, c), []string{"nginx.restart"}; !slices.Equal(got, want) {
		t.Errorf("pending after handled = %v, want %v", got, want)
	}

	// Another project keeps its own records.
	c.w.Close()
	if err := <-c.done; err != nil {
		t.Fatal(err)
	}
	other := start(t, dir, "")
	h.Project = "other"
	other.call(t, "hello", h)
	if got := pending(t, other); len(got) != 0 {
		t.Errorf("pending of another project = %v, want none", got)
	}
}

// spec: Steps; Remote execution/State on the host
func TestPendingThen(t *testing.T) {
	dir := t.TempDir()
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	work := t.TempDir()
	remove := func(name string) json.RawMessage {
		p := filepath.Join(work, name)
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		args, _ := json.Marshal(module.File{Path: p, Absent: true})
		return args
	}
	postmap := protocol.Then{Recipe: "postfix", Module: "file", Mains: []string{"1"}}
	reload := protocol.Then{Stage: "postfix", Module: "file", Mains: []string{"2"}}

	if r := c.call(t, "check", protocol.Step{Module: "file", Args: remove("a"), Then: &postmap}); r.Error != "" {
		t.Fatal(r.Error)
	}
	gone, _ := json.Marshal(module.File{Path: filepath.Join(work, "gone"), Absent: true})
	if r := c.call(t, "apply", protocol.Step{Module: "file", Args: gone, Then: &postmap}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got := pendingAll(t, c).Then; len(got) != 0 {
		t.Fatalf("then records after a check and an ok apply = %v, want none", got)
	}

	// Two elements of a loop record the then once.
	for _, name := range []string{"b", "c"} {
		if r := c.call(t, "apply", protocol.Step{Module: "file", Args: remove(name), Then: &postmap}); r.Error != "" {
			t.Fatal(r.Error)
		}
	}
	if r := c.call(t, "apply", protocol.Step{Module: "file", Args: remove("d"), Then: &reload}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got, want := pendingAll(t, c).Then, []protocol.Then{postmap, reload}; !reflect.DeepEqual(got, want) {
		t.Fatalf("then records = %v, want %v", got, want)
	}
	if got := pending(t, c); len(got) != 0 {
		t.Errorf("pending handlers = %v, want none", got)
	}

	// A failed command keeps its record; a command that succeeds removes it.
	failing := protocol.Then{Recipe: "postfix", Module: "file", Mains: []string{"3"}}
	done := protocol.Then{Recipe: "postfix", Module: "file", Mains: []string{"4"}}
	for _, th := range []protocol.Then{failing, done} {
		if r := c.call(t, "apply", protocol.Step{Module: "file", Args: remove("e"), Then: &th}); r.Error != "" {
			t.Fatal(r.Error)
		}
	}
	if r := c.call(t, "command", protocol.Command{Command: "false", Then: failing}); r.Error == "" {
		t.Fatal("command false succeeded")
	}
	if r := c.call(t, "command", protocol.Command{Command: "true\necho '<a &b>' >/dev/null", Then: done}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got, want := pendingAll(t, c).Then, []protocol.Then{postmap, reload, failing}; !reflect.DeepEqual(got, want) {
		t.Errorf("then records after the commands = %v, want %v", got, want)
	}
	b, err := os.ReadFile(filepath.Join(dir, "then", "acme"))
	if err != nil {
		t.Fatal(err)
	}
	want := `version 1
{"recipe":"postfix","module":"file","mains":["1"]}
{"stage":"postfix","module":"file","mains":["2"]}
{"recipe":"postfix","module":"file","mains":["3"]}
`
	if string(b) != want {
		t.Errorf("then/acme = %q, want %q", b, want)
	}
}

// spec: Modules; Steps
func TestCommand(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.call(t, "hello", hello("r1"))
	if r := c.call(t, "command", protocol.Command{Command: "true"}); r.Error != "" {
		t.Errorf("true: %s", r.Error)
	}
	r := c.call(t, "command", protocol.Command{Command: "echo broken; exit 3"})
	if !strings.Contains(r.Error, "exit status 3") || !strings.Contains(r.Error, "broken") {
		t.Errorf("error = %q, want the exit status and the output", r.Error)
	}
}

// spec: Remote execution/State on the host
func TestPendingStaysInTheStateDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("root:x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "handlers"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "../secret"
	c.call(t, "hello", h)
	if r := c.call(t, "pending", nil); r.Error == "" {
		t.Errorf("pending of project ../secret = %s, want an error", r.Result)
	}
}

// spec: Handlers; Remote execution/State on the host
func TestEmptyLinesInRecords(t *testing.T) {
	dir := t.TempDir()
	for sub, data := range map[string]string{"handlers": "version 1\nnginx.reload\n\napp.restart\n", "then": "version 1\n\n{\"recipe\":\"a\",\"module\":\"file\",\"mains\":[\"1\"]}\n"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sub, "acme"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "acme"
	c.call(t, "hello", h)
	p := pendingAll(t, c)
	if want := []string{"nginx.reload", "app.restart"}; !slices.Equal(p.Handlers, want) {
		t.Errorf("handlers = %q, want %q", p.Handlers, want)
	}
	if want := []protocol.Then{{Recipe: "a", Module: "file", Mains: []string{"1"}}}; !reflect.DeepEqual(p.Then, want) {
		t.Errorf("then = %v, want %v", p.Then, want)
	}
}

// spec: Handlers; Steps; Remote execution/State on the host
func TestDamagedState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{"truncated then record", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "then", "acme"), "version 1\n{\"recipe\":\"a\",\"step\":1}\n\n{\"recipe\":\n")
		}, "read the pending then records: DIR/then/acme:4: unexpected end of JSON input"},
		{"then line that is not JSON", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "then", "acme"), "version 1\npostmap /etc/postfix/virtual\n")
		}, "read the pending then records: DIR/then/acme:2: invalid character 'p' looking for beginning of value"},
		{"truncated check record", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "checks", "acme"), "version 1\n{\"pipeline\":\n")
		}, "read the pending health gates and asserts: DIR/checks/acme:2: unexpected end of JSON input"},
		{"newer version", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "handlers", "acme"), "version 2\napp.restart\n")
		}, "upgrade winch to read DIR/handlers/acme"},
		{"no version", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "handlers", "acme"), "app.restart\n")
		}, "read the pending handlers: DIR/handlers/acme: no format version"},
		{"directory in place of the handlers", func(t *testing.T, dir string) {
			mkdir(t, filepath.Join(dir, "handlers", "acme"))
		}, "read the pending handlers: read DIR/handlers/acme: is a directory"},
		{"directory in place of the then records", func(t *testing.T, dir string) {
			mkdir(t, filepath.Join(dir, "then", "acme"))
		}, "read the pending then records: read DIR/then/acme: is a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			c := start(t, dir, "")
			h := hello("r1")
			h.Project = "acme"
			if r := c.call(t, "hello", h); r.Error != "" {
				t.Fatal(r.Error)
			}
			want := strings.ReplaceAll(tc.want, "DIR", dir)
			if r := c.call(t, "pending", nil); r.Error != want {
				t.Errorf("pending error = %q, want %q", r.Error, want)
			}
		})
	}
}

// spec: Remote execution/Helper
func TestEmptyLockFile(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "lock"), "")
	c := start(t, dir, "")
	if r := c.call(t, "hello", hello("r1")); r.Error != "" {
		t.Fatalf("hello with an empty lock file: %s", r.Error)
	}
	data, err := os.ReadFile(filepath.Join(dir, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	var rec lockRecord
	if err := json.Unmarshal(data, &rec); err != nil || rec.Run != "r1" || rec.PID != os.Getpid() {
		t.Errorf("lock file = %q, %v; want the record of run r1", data, err)
	}
}

// spec: Handlers; Steps
func TestRecordsBeforeApply(t *testing.T) {
	dir := t.TempDir()
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	// The validate command runs inside Apply and sees the records.
	validate := "grep -qxF nginx.reload '" + filepath.Join(dir, "handlers", "acme") + "' && grep -qF '\"mains\":[\"1\"]' '" + filepath.Join(dir, "then", "acme") + "'"
	uid, gid := yamlx.NameOrID(strconv.Itoa(os.Getuid())), yamlx.NameOrID(strconv.Itoa(os.Getgid()))
	args, _ := json.Marshal(module.File{Path: filepath.Join(t.TempDir(), "f"), Data: []byte("x\n"), Owner: uid, Group: gid, Validation: &validate})
	r := c.call(t, "apply", protocol.Step{Module: "file", Args: args, Notify: []string{"nginx.reload"}, Then: &protocol.Then{Recipe: "nginx", Module: "file", Mains: []string{"1"}}})
	if r.Error != "" {
		t.Errorf("apply: %s", r.Error)
	}
}

// spec: Handlers; Steps
func TestFailedApplyRemovesItsRecords(t *testing.T) {
	dir := t.TempDir()
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	uid, gid := yamlx.NameOrID(strconv.Itoa(os.Getuid())), yamlx.NameOrID(strconv.Itoa(os.Getgid()))
	path := filepath.Join(t.TempDir(), "f")
	file := func(validate string) json.RawMessage {
		args, _ := json.Marshal(module.File{Path: path, Data: []byte(validate + "\n"), Owner: uid, Group: gid, Validation: &validate})
		return args
	}
	earlier := protocol.Then{Recipe: "nginx", Module: "file", Mains: []string{"1"}}
	if r := c.call(t, "apply", protocol.Step{Module: "file", Args: file("true"), Notify: []string{"nginx.reload"}, Then: &earlier}); r.Error != "" {
		t.Fatal(r.Error)
	}

	failing := protocol.Then{Recipe: "nginx", Module: "file", Mains: []string{"2"}}
	if r := c.call(t, "apply", protocol.Step{Module: "file", Args: file("false"), Notify: []string{"nginx.reload", "nginx.restart"}, Then: &failing}); !strings.Contains(r.Error, "validate: false") {
		t.Fatalf("apply error = %q, want the validate error", r.Error)
	}
	// A failed apply of the same then keeps the record of the earlier apply.
	if r := c.call(t, "apply", protocol.Step{Module: "file", Args: file("false"), Then: &earlier}); !strings.Contains(r.Error, "validate: false") {
		t.Fatalf("apply error = %q, want the validate error", r.Error)
	}
	p := pendingAll(t, c)
	if want := []string{"nginx.reload"}; !slices.Equal(p.Handlers, want) {
		t.Errorf("pending handlers = %v, want %v", p.Handlers, want)
	}
	if want := []protocol.Then{earlier}; !reflect.DeepEqual(p.Then, want) {
		t.Errorf("then records = %v, want %v", p.Then, want)
	}
}

func write(t *testing.T, name, data string) {
	t.Helper()
	mkdir(t, filepath.Dir(name))
	if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.MkdirAll(name, 0o700); err != nil {
		t.Fatal(err)
	}
}

// spec: Running a pipeline/Apply
func TestApplyUnknown(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.call(t, "hello", hello("r1"))
	out := filepath.Join(t.TempDir(), "ran")
	args, _ := json.Marshal(module.Cmd{Command: "touch " + out})
	r := c.call(t, "check", protocol.Step{Module: "cmd", Args: args})
	var res protocol.StepResult
	if err := json.Unmarshal(r.Result, &res); err != nil || r.Error != "" || res.Status != module.Unknown {
		t.Fatalf("check = %s %q, want unknown", r.Result, r.Error)
	}
	r = c.call(t, "apply", protocol.Step{Module: "cmd", Args: args})
	if err := json.Unmarshal(r.Result, &res); err != nil || r.Error != "" || res.Status != module.Unknown {
		t.Errorf("apply = %s %q, want unknown", r.Result, r.Error)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("apply did not run the command: %v", err)
	}
}

// spec: Handlers; Modules/assert
func TestDeferredRecordsNothing(t *testing.T) {
	c := start(t, t.TempDir(), "")
	h := hello("r1")
	h.Project = "acme"
	c.call(t, "hello", h)
	args, _ := json.Marshal(module.Assert{Command: "true", Message: "x"})
	if r := c.call(t, "apply", protocol.Step{Module: "assert", Args: args, Notify: []string{"app.reload"}, Then: &protocol.Then{Recipe: "app", Module: "assert", Mains: []string{"1"}}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if p := pendingAll(t, c); len(p.Handlers) != 0 || len(p.Then) != 0 {
		t.Errorf("records after an assert: %+v", p)
	}
}

// spec: Running a pipeline/Apply (the second check decides)
func TestApplyChecksAgain(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.call(t, "hello", hello("r1"))
	dir := t.TempDir()
	made, ran := filepath.Join(dir, "made"), filepath.Join(dir, "ran")
	args, _ := json.Marshal(module.Cmd{Command: "touch " + ran, Creates: made})
	write(t, made, "")
	if r := c.call(t, "apply", protocol.Step{Module: "cmd", Args: args}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("the command ran although its creates exists")
	}
}

// spec: Modules/assert
func TestApplyDeferred(t *testing.T) {
	c := start(t, t.TempDir(), "")
	c.call(t, "hello", hello("r1"))
	out := filepath.Join(t.TempDir(), "ran")
	args, _ := json.Marshal(module.Assert{Command: "touch " + out, Message: "x"})
	r := c.call(t, "apply", protocol.Step{Module: "assert", Args: args})
	var res protocol.StepResult
	if err := json.Unmarshal(r.Result, &res); err != nil || r.Error != "" || res.Status != module.OK {
		t.Errorf("apply = %s %q, want ok", r.Result, r.Error)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("apply did not run the command: %v", err)
	}
	args, _ = json.Marshal(module.Assert{Command: "exit 1", Message: "the port is blocked"})
	if r := c.call(t, "apply", protocol.Step{Module: "assert", Args: args}); r.Error != "the port is blocked" {
		t.Errorf("a failing assert: error %q, want the message", r.Error)
	}
}

// spec: Modules/download
func TestForget(t *testing.T) {
	downloads := records{dir: t.TempDir(), project: "acme", what: "download records"}
	if err := downloads.write([]string{"a /opt/a", "b /opt/b"}); err != nil {
		t.Fatal(err)
	}
	if err := forget(downloads, "/opt/a"); err != nil {
		t.Fatal(err)
	}
	if err := forget(downloads, "/opt/missing"); err != nil {
		t.Fatal(err)
	}
	if lines, err := downloads.read(); err != nil || !slices.Equal(lines, []string{"b /opt/b"}) {
		t.Errorf("records = %q, %v; want only the record of /opt/b", lines, err)
	}
}

// spec: Modules/download; Handlers
func TestDownloadOKRecordsNothing(t *testing.T) {
	c := start(t, t.TempDir(), "")
	h := hello("r1")
	h.Project = "acme"
	c.call(t, "hello", h)
	p := filepath.Join(t.TempDir(), "tool")
	write(t, p, "tool\n")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(module.Download{URL: "http://127.0.0.1:1/tool", SHA256: "67948dd9afd6afe5043b0029d5aa7cf0f8b2824baf16f4f097d40d830edb686d", Path: p,
		Owner: yamlx.NameOrID(strconv.Itoa(os.Getuid())), Group: yamlx.NameOrID(strconv.Itoa(os.Getgid()))})
	r := c.call(t, "apply", protocol.Step{Module: "download", Args: args, Notify: []string{"app.reload"}, Then: &protocol.Then{Recipe: "app", Module: "download", Mains: []string{"1"}}})
	var res protocol.StepResult
	if err := json.Unmarshal(r.Result, &res); err != nil || r.Error != "" || res.Status != module.OK || len(res.Changes) != 0 {
		t.Fatalf("apply = %s %q, want ok without a record", r.Result, r.Error)
	}
	if p := pendingAll(t, c); len(p.Handlers) != 0 || len(p.Then) != 0 {
		t.Errorf("records after an unchanged download: %+v", p)
	}
	if r := c.call(t, "check", protocol.Step{Module: "download", Args: args}); !strings.Contains(string(r.Result), `"status":"ok"`) {
		t.Errorf("check after apply = %s %q, want ok", r.Result, r.Error)
	}
}

// spec: Running a pipeline/Health gates; Modules/assert; Remote execution/State on the host
func TestPendingChecks(t *testing.T) {
	dir := t.TempDir()
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	gate := protocol.Check{Pipeline: "site", Stage: "base"}
	assert := protocol.Check{Recipe: "mail", Step: 3}
	for _, ch := range []protocol.Check{gate, assert, gate} {
		if r := c.call(t, "pend", ch); r.Error != "" {
			t.Fatal(r.Error)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "checks", "acme")); err != nil || string(data) != "version 1\n{\"pipeline\":\"site\",\"stage\":\"base\"}\n{\"recipe\":\"mail\",\"step\":3}\n" {
		t.Errorf("checks/acme = %q, %v", data, err)
	}
	if r := c.call(t, "passed", gate); r.Error != "" {
		t.Fatal(r.Error)
	}
	r := c.call(t, "pending", nil)
	var p protocol.Pending
	if err := json.Unmarshal(r.Result, &p); err != nil || r.Error != "" {
		t.Fatalf("pending: %v %s", err, r.Error)
	}
	if !slices.Equal(p.Checks, []protocol.Check{assert}) {
		t.Errorf("pending checks = %v, want %v", p.Checks, []protocol.Check{assert})
	}
}

// spec: Running a pipeline/Health gates; Modules/assert
func TestChecksRunAgain(t *testing.T) {
	dir := t.TempDir()
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	marker := filepath.Join(t.TempDir(), "open")
	args, _ := json.Marshal(module.Assert{Command: "test -e " + marker, Message: "closed"})
	assert := protocol.Check{Pipeline: "site", Stage: "base", Step: 2}
	gate := protocol.Check{Pipeline: "site", Stage: "base"}
	checks := func() []protocol.Check {
		t.Helper()
		var p protocol.Pending
		if err := json.Unmarshal(c.call(t, "pending", nil).Result, &p); err != nil {
			t.Fatal(err)
		}
		return p.Checks
	}
	if r := c.call(t, "apply", protocol.Step{Module: "assert", Args: args, Check: &assert}); r.Error != "closed" {
		t.Fatalf("failing assert: error %q", r.Error)
	}
	if r := c.call(t, "pend", gate); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got, want := checks(), []protocol.Check{assert, gate}; !slices.Equal(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := c.call(t, "apply", protocol.Step{Module: "assert", Args: args, Check: &assert}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := c.call(t, "health", protocol.Health{Command: "true", Timeout: 5 * time.Second, Check: gate}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got := checks(); len(got) != 0 {
		t.Errorf("records after the assert and the gate passed = %v", got)
	}
}

// spec: Steps
func TestThenRecordsMatchAndDrop(t *testing.T) {
	dir := t.TempDir()
	// The second line is a record of an earlier format.
	write(t, filepath.Join(dir, "then", "acme"), `version 1
{"recipe":"site","module":"file","mains":["/a","/b"]}
{"recipe":"old","step":2,"module":"file","main":"/x"}
{"recipe":"site","module":"file","mains":["/c"]}
`)
	c := start(t, dir, "")
	h := hello("r1")
	h.Project = "acme"
	if r := c.call(t, "hello", h); r.Error != "" {
		t.Fatal(r.Error)
	}
	// The loop lost its element /b; the record still matches.
	if r := c.call(t, "command", protocol.Command{Command: "true", Then: protocol.Then{Recipe: "site", Module: "file", Mains: []string{"/a"}}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := c.call(t, "dropthen", protocol.Then{Recipe: "old", Module: "file"}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if got, want := pendingAll(t, c).Then, []protocol.Then{{Recipe: "site", Module: "file", Mains: []string{"/c"}}}; !reflect.DeepEqual(got, want) {
		t.Errorf("then records = %v, want %v", got, want)
	}
}
