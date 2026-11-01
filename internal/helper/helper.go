// Package helper is the program that runs on the host. It reads requests on
// stdin and answers on stdout until stdin closes.
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

// Serve answers requests. dir is the state directory, self the path of the
// running helper binary in dir/bin, and login the login user and the
// connection of the session. When in closes, a running exec command stops;
// other requests finish.
func Serve(ctx context.Context, in io.Reader, out io.Writer, dir, self string, login module.State) (err error) {
	reqs := make(chan protocol.Request)
	inCtx, inClosed := context.WithCancel(ctx)
	defer inClosed()
	var readErr error
	go func() {
		defer close(reqs)
		defer inClosed()
		dec := json.NewDecoder(in)
		for {
			var req protocol.Request
			if readErr = dec.Decode(&req); readErr != nil {
				return
			}
			reqs <- req
		}
	}()
	enc := json.NewEncoder(out)
	var lock *lockFile
	var handlers, thens, downloads, certbotHooks, checks records
	var rb *rollbacks
	var loginUser *module.Login
	// After a reboot, the same run goes on in a new session. A session that
	// finds the host not rebooted yet is a try to reconnect.
	rebooting := false
	defer func() {
		if lock == nil {
			return
		}
		err = errors.Join(err, lock.mark(false))
		if !rebooting {
			err = errors.Join(err, rb.end(ctx, handlers, thens))
		}
		lock.close()
	}()
	for {
		req, ok := <-reqs
		if !ok {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("read request: %w", readErr)
		}
		markErr := lock.mark(false)
		var result any
		var err error
		say := sayer{enc: enc, id: req.ID}
		switch {
		case markErr != nil:
			err = markErr
		case req.Method == "hello" && lock != nil:
			err = errors.New("hello was already sent")
		case req.Method == "hello":
			var project string
			lock, project, err = takeLock(ctx, req.Params, dir, self)
			handlers = records{dir: filepath.Join(dir, "handlers"), project: project, what: "pending handlers"}
			thens = records{dir: filepath.Join(dir, "then"), project: project, what: "pending then records"}
			downloads = downloadRecords(filepath.Join(dir, "downloads", project))
			certbotHooks = records{dir: filepath.Join(dir, "certbot-hooks"), project: project, what: "pending certbot hooks"}
			checks = records{dir: filepath.Join(dir, "checks"), project: project, what: "pending health gates and asserts"}
			rb = &rollbacks{dir: filepath.Join(dir, "rollback"), project: project, self: self, downloads: downloads}
			if err == nil {
				loginUser, err = module.LookupLogin(login.LoginUID)
			}
			if err == nil {
				w := protocol.Welcome{LoginUID: login.LoginUID}
				if loginUser != nil {
					w.Login = loginUser.Name()
				}
				result = w
			}
			if err == nil {
				err = rb.idle(ctx)
			}
			if err == nil && !resumed(req.Params) {
				err = rb.clear(handlers)
			}
			if err != nil && lock != nil {
				lock.close()
				lock = nil
			}
		case lock == nil:
			err = errors.New("the first request must be hello")
		case req.Method == "facts":
			result, err = readFacts()
		case req.Method == "pending":
			result, err = readPending(handlers, thens, checks)
		case req.Method == "handled":
			err = handled(req.Params, handlers)
		case req.Method == "pend":
			var line string
			if line, err = checkLine(req.Params); err == nil {
				_, err = checks.add([]string{line})
			}
		case req.Method == "passed":
			var line string
			if line, err = checkLine(req.Params); err == nil {
				err = checks.remove(line)
			}
		case req.Method == "command":
			err = command(ctx, req.Params, thens)
		case req.Method == "dropthen":
			err = dropThen(req.Params, thens)
		case req.Method == "exec":
			result, err = execCommand(inCtx, req.Params)
		case req.Method == "health":
			err = runHealth(ctx, req.Params, checks)
		case req.Method == "check":
			result, err = step(ctx, req.Params, false, login, loginUser, handlers, thens, downloads, certbotHooks, checks, rb, say)
		case req.Method == "apply":
			result, err = step(ctx, req.Params, true, login, loginUser, handlers, thens, downloads, certbotHooks, checks, rb, say)
		case req.Method == "confirm":
			err = confirmStep(ctx, rb, handlers, thens)
		case req.Method == "rollback":
			err = rollbackStep(ctx, rb, handlers, thens)
		case req.Method == "reboot":
			result, err = reboot(filepath.Join(dir, rebootRecord))
			rebooting = err == nil
		case req.Method == "booted":
			var b protocol.Boot
			b, err = booted(ctx, req.Params, filepath.Join(dir, rebootRecord))
			result, rebooting = b, b.Same
		default:
			err = fmt.Errorf("unknown method %q", req.Method)
		}
		// Idle before the answer, which can be the last that the controller
		// reads before a question. A failed unlock keeps the lock busy.
		_ = lock.mark(true)
		resp := protocol.Response{ID: req.ID}
		if err != nil {
			resp.Error = err.Error()
			resp.NeedContent = errors.Is(err, module.ErrNeedContent)
		} else if resp.Result, err = json.Marshal(result); err != nil {
			return fmt.Errorf("encode result: %w", err)
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
	}
}

type lockRecord struct {
	protocol.Hello
	PID int `json:"pid"`
}

// takeLock takes the lock of the state directory, and returns it with the
// project of the session. The returned lock is busy.
func takeLock(ctx context.Context, params json.RawMessage, dir, self string) (_ *lockFile, project string, err error) {
	var h protocol.Hello
	if err := json.Unmarshal(params, &h); err != nil {
		return nil, "", fmt.Errorf("decode hello: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create state directory: %w", err)
	}
	if err := checkTree(dir, uint32(os.Geteuid())); err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("open lock: %w", err)
	}
	busy, err := os.Open(dir)
	if err != nil {
		f.Close()
		return nil, "", fmt.Errorf("open lock: %w", err)
	}
	l := &lockFile{f: f, busy: busy}
	defer func() {
		if err != nil {
			l.close()
		}
	}()
	// Busy before the lock, so that the record of the last holder, until this
	// helper writes its own, never looks idle. The flock of busy also keeps
	// an idle holder from starting a request until it ends.
	idle, err := tryLock(busy)
	if err != nil {
		return nil, "", err
	}
	locked, err := tryLock(f)
	if err != nil {
		return nil, "", err
	}
	var held lockRecord
	if !locked {
		data, _ := io.ReadAll(f)
		_ = json.Unmarshal(data, &held)
	}
	// A new lock file is empty until its holder writes it. A kill with a PID
	// below 2 signals a process group or init, not one helper.
	if !locked && idle && held.PID > 1 && held.Run != "" && held.Run == h.Run {
		if locked, err = takeOver(ctx, f, held.PID, module.KillDelay); err != nil {
			return nil, "", err
		}
	}
	if !locked {
		// The record is empty, or half written, until its holder writes it.
		if held.Run == "" {
			return nil, "", errors.New("locked by another run that is starting; run winch again to see which one")
		}
		msg := fmt.Sprintf("locked by run %s (%s@%s, since %s", held.Run, held.User, held.Machine, held.Started.UTC().Format(time.RFC3339))
		if held.PID <= 1 {
			return nil, "", fmt.Errorf("%s); if that run is gone, end the process that holds %s", msg, f.Name())
		}
		return nil, "", fmt.Errorf("%s, helper process %d); if that run is gone, end it with: sudo kill %d", msg, held.PID, held.PID)
	}
	if err := l.mark(false); err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(lockRecord{Hello: h, PID: os.Getpid()})
	if err != nil {
		return nil, "", err
	}
	// Write before truncate, so a reader never sees an empty file.
	if _, err := f.WriteAt(data, 0); err != nil {
		return nil, "", fmt.Errorf("write lock: %w", err)
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return nil, "", fmt.Errorf("write lock: %w", err)
	}
	if err := deleteOld(filepath.Join(dir, "bin"), self); err != nil {
		return nil, "", err
	}
	return l, h.Project, nil
}

// tryLock reports whether it took the flock of f.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock: %w", err)
	}
	return true, nil
}

// takeOver ends the helper pid, which holds the lock of f for the same run
// and runs no request: its session died, as after a laptop sleep, and sshd
// has not seen it yet. It sends SIGTERM, then SIGKILL after grace, and
// reports whether it took the lock.
func takeOver(ctx context.Context, f *os.File, pid int, grace time.Duration) (bool, error) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		if err := syscall.Kill(pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
			return false, fmt.Errorf("end helper process %d: %w", pid, err)
		}
		for deadline := time.Now().Add(grace); time.Now().Before(deadline); {
			if locked, err := tryLock(f); locked || err != nil {
				return locked, err
			}
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-tick.C:
			}
		}
	}
	return false, nil
}

// lockFile is the held lock of the state directory. The helper holds the
// flock of busy, the state directory, while it runs a request.
type lockFile struct {
	f, busy *os.File
}

// mark takes or releases busy. A nil lock, before hello, does nothing.
func (l *lockFile) mark(idle bool) error {
	if l == nil {
		return nil
	}
	how := syscall.LOCK_EX
	if idle {
		how = syscall.LOCK_UN
	}
	if err := syscall.Flock(int(l.busy.Fd()), how); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	return nil
}

func (l *lockFile) close() {
	l.f.Close()
	l.busy.Close()
}

// checkTree fails on the first entry under dir that is not a directory or a
// regular file of owner, or that the group or others can write. A user who
// once owned dir can have left records and rollback jobs, which the helper
// runs as root. The start script checks dir itself.
func checkTree(dir string, owner uint32) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if p == dir {
			return err
		}
		var info fs.FileInfo
		if err == nil {
			info, err = d.Info()
		}
		// A rollback timer, or a helper that holds the lock, removes files.
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a directory or a regular file", p)
		}
		if !ok || st.Uid != owner || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not owned by root, or the group or others can write it", p)
		}
		return nil
	})
}

// deleteOld keeps the helpers of other winch versions in use, and their
// uploads in progress. An upload renames its file when it ends.
func deleteOld(bin, self string) error {
	entries, err := os.ReadDir(bin)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	now := time.Now()
	for _, e := range entries {
		p := filepath.Join(bin, e.Name())
		if e.Name() == filepath.Base(self) {
			if err := os.Chtimes(p, now, now); err != nil {
				return fmt.Errorf("touch helper: %w", err)
			}
			continue
		}
		info, err := e.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if now.Sub(info.ModTime()) <= 30*24*time.Hour {
			continue
		}
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("delete old helper: %w", err)
		}
	}
	return nil
}

// sayer sends the lines of a step as responses before the answer to request
// id. A failed write fails the answer that follows.
type sayer struct {
	enc *json.Encoder
	id  int
}

func (s sayer) Note(text string) { _ = s.enc.Encode(protocol.Response{ID: s.id, Note: text}) }

func (s sayer) Warn(text string) { _ = s.enc.Encode(protocol.Response{ID: s.id, Warning: text}) }

func (s sayer) Progress(text string) { _ = s.enc.Encode(protocol.Response{ID: s.id, Progress: text}) }

// step checks a step. With apply, it then records the handlers that the step
// notifies and its then, and makes the changes the check found, or runs a
// deferred step. When the changes fail, it removes the records that it added.
// After a successful unpack, it records the checksum, owner, and group.
func step(ctx context.Context, params json.RawMessage, apply bool, login module.State, loginUser *module.Login, handlers, thens, downloads, certbotHooks, checks records, rb *rollbacks, say module.Say) (protocol.StepResult, error) {
	var s protocol.Step
	if err := json.Unmarshal(params, &s); err != nil {
		return protocol.StepResult{}, fmt.Errorf("decode step: %w", err)
	}
	s.State.LoginUID, s.State.SSHConnection = login.LoginUID, login.SSHConnection
	m, ok := module.New(s.Module)
	if !ok {
		return protocol.StepResult{}, fmt.Errorf("unknown module %q", s.Module)
	}
	if err := json.Unmarshal(s.Args, m); err != nil {
		return protocol.StepResult{}, fmt.Errorf("decode %s arguments: %w", s.Module, err)
	}
	d, isDownload := m.(*module.Download)
	unpack := isDownload && d.Unpack != ""
	if unpack {
		sum, err := recorded(downloads, d.Unpack)
		if err != nil {
			return protocol.StepResult{}, err
		}
		d.Recorded = sum
	}
	c, isCertbot := m.(*module.Certbot)
	if isCertbot {
		hooks, err := recorded(certbotHooks, c.Name)
		if err != nil {
			return protocol.StepResult{}, err
		}
		if hooks != "" {
			c.PendingHooks = strings.Split(hooks, ",")
		}
	}
	res, err := m.Check(ctx, &s.State, say)
	var socket bool
	if err == nil && res.Status == module.Change {
		touches := module.Touches(m)
		if line := module.Guard(touches, loginUser); line != "" {
			res.Guard = true
			res.Changes = append([]string{line}, res.Changes...)
		}
		socket, err = module.SSHSocket(ctx, touches)
		if socket {
			res.Changes = append(res.Changes, "daemon-reload", "restart ssh.socket")
			if !res.Guard {
				res.Guard = true
				res.Changes = append([]string{module.SSHSocketNote(m, res)}, res.Changes...)
			}
		}
	}
	out := protocol.StepResult{Result: res, State: s.State}
	if err != nil || !apply || res.Status == module.OK && !res.Deferred {
		return out, err
	}
	// A deferred step changes nothing, so it notifies nothing.
	if res.Status == module.OK {
		err := m.Apply(ctx, say)
		if s.Check == nil {
			return out, err
		}
		line, jerr := json.Marshal(s.Check)
		if jerr != nil {
			return out, errors.Join(err, jerr)
		}
		if err != nil {
			_, rerr := checks.add([]string{string(line)})
			return out, errors.Join(err, rerr)
		}
		return out, checks.remove(string(line))
	}
	if isCertbot {
		if hooks := c.HooksToRun(); len(hooks) > 0 {
			if err := record(certbotHooks, strings.Join(hooks, ","), c.Name); err != nil {
				return out, err
			}
		}
	}
	// The plan has shown the diff already.
	out.Old, out.OldReason = nil, ""
	// A failed unpack leaves the unpack directory, so only the record shows
	// that the unpack is not done.
	if unpack {
		if err := forget(downloads, d.Unpack); err != nil {
			return out, err
		}
	}
	notified, err := handlers.add(s.Notify)
	if err != nil {
		return out, err
	}
	var thenLines []string
	if s.Then != nil {
		line, err := json.Marshal(s.Then)
		if err != nil {
			return out, err
		}
		if thenLines, err = thens.add([]string{string(line)}); err != nil {
			return out, err
		}
	}
	guard := s.Guard.Confirm || res.Guard
	var deadline time.Time
	for _, h := range s.Guard.Handlers {
		if _, _, err := rb.save(rb.handlerStore(h), m); err != nil {
			return out, errors.Join(err, handlers.remove(notified...), thens.remove(thenLines...))
		}
	}
	if _, err := rb.notified().add(s.Guard.Handlers); err != nil {
		return out, errors.Join(err, handlers.remove(notified...), thens.remove(thenLines...))
	}
	if s.Guard.Save || guard {
		saved, all, err := rb.save(rb.scope(s.Guard), m)
		if err == nil && guard {
			deadline, err = startTimer(rb, s.Guard, m, saved, all)
		}
		if err != nil {
			return out, errors.Join(err, handlers.remove(notified...), thens.remove(thenLines...))
		}
	}
	err = m.Apply(ctx, say)
	if err == nil && socket {
		err = module.RestartSSHSocket(ctx)
	}
	if isCertbot {
		var recordErr error
		if len(c.PendingHooks) == 0 {
			recordErr = forget(certbotHooks, c.Name)
		} else {
			recordErr = record(certbotHooks, strings.Join(c.PendingHooks, ","), c.Name)
		}
		err = errors.Join(err, recordErr)
	}
	if err != nil {
		if guard {
			if rerr := rb.rollback(ctx); rerr != nil {
				return out, fmt.Errorf("%w; the rollback failed: %w", err, rerr)
			}
			err = fmt.Errorf("%w; the old files are back", err)
		}
		return out, errors.Join(err, handlers.remove(notified...), thens.remove(thenLines...))
	}
	if guard {
		out.Timer = time.Until(deadline)
		rb.running = &guarded{handlers: notified, thens: thenLines}
	}
	if unpack {
		return out, record(downloads, d.Record(), d.Unpack)
	}
	return out, nil
}

// resumed reports whether the params of hello are those of the connect
// after a reboot.
func resumed(params json.RawMessage) bool {
	var h protocol.Hello
	return json.Unmarshal(params, &h) == nil && h.Resume
}

// startTimer starts the rollback timer of the guarded step m. A step with
// confirm_access puts back the whole store of its recipe or stage, and its
// undo step; another guarded step puts back only what it saved.
func startTimer(rb *rollbacks, g protocol.Guard, m module.Module, saved, all []module.Saved) (time.Time, error) {
	j := job{Deadline: time.Now().Add(TimerTime), Restore: saved, Downloads: filepath.Join(rb.downloads.dir, rb.downloads.project)}
	if u, ok := m.(*module.User); ok {
		if un := u.Undo(); un != nil {
			args, err := json.Marshal(un)
			if err != nil {
				return time.Time{}, err
			}
			j.Undo = &undo{Module: "user", Args: args}
		}
	}
	if g.Confirm {
		j.Restore = all
		if sv, ok := m.(*module.Service); ok {
			if u := sv.Undo(); u != nil {
				args, err := json.Marshal(u)
				if err != nil {
					return time.Time{}, err
				}
				j.Undo = &undo{Module: "service", Args: args}
			}
		}
	}
	return j.Deadline, rb.start(j)
}

func readFacts() (facts.Facts, error) {
	f, err := facts.Read("/etc/os-release", "/usr/lib/os-release")
	if err != nil {
		return f, err
	}
	f.RebootRequired, err = module.RebootRequired()
	if err != nil {
		return f, fmt.Errorf("read facts: %w", err)
	}
	return f, nil
}

func readPending(handlers, thens, checks records) (protocol.Pending, error) {
	names, err := handlers.read()
	if err != nil {
		return protocol.Pending{}, err
	}
	lines, err := thens.read()
	if err != nil {
		return protocol.Pending{}, err
	}
	p := protocol.Pending{Handlers: slices.DeleteFunc(names, func(n string) bool { return n == "" }), Then: []protocol.Then{}}
	for i, l := range lines {
		if l == "" {
			continue
		}
		var t protocol.Then
		if err := json.Unmarshal([]byte(l), &t); err != nil {
			return protocol.Pending{}, fmt.Errorf("read the pending then records: %s:%d is not a record; delete the file, and the records in it are lost", filepath.Join(thens.dir, thens.project), i+2)
		}
		p.Then = append(p.Then, t)
	}
	lines, err = checks.read()
	if err != nil {
		return protocol.Pending{}, err
	}
	for i, l := range lines {
		if l == "" {
			continue
		}
		var c protocol.Check
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			return protocol.Pending{}, fmt.Errorf("read the pending health gates and asserts: %s:%d is not a record; delete the file, and the records in it are lost", filepath.Join(checks.dir, checks.project), i+2)
		}
		p.Checks = append(p.Checks, c)
	}
	return p, nil
}

// checkLine returns the record line of the gate or assert in params.
func checkLine(params json.RawMessage) (string, error) {
	var c protocol.Check
	if err := json.Unmarshal(params, &c); err != nil {
		return "", fmt.Errorf("decode check: %w", err)
	}
	line, err := json.Marshal(c)
	return string(line), err
}

func handled(params json.RawMessage, handlers records) error {
	var h protocol.Handled
	if err := json.Unmarshal(params, &h); err != nil {
		return fmt.Errorf("decode handled: %w", err)
	}
	return handlers.remove(h.Name)
}

// command runs the command of a then, and then removes the records that
// match it.
func command(ctx context.Context, params json.RawMessage, thens records) error {
	var c protocol.Command
	if err := json.Unmarshal(params, &c); err != nil {
		return fmt.Errorf("decode command: %w", err)
	}
	if err := module.Shell(ctx, c.Command); err != nil {
		return err
	}
	return removeThens(thens, c.Then.Matches)
}

// dropThen removes the record of a then that matches no step.
func dropThen(params json.RawMessage, thens records) error {
	var t protocol.Then
	if err := json.Unmarshal(params, &t); err != nil {
		return fmt.Errorf("decode dropthen: %w", err)
	}
	return removeThens(thens, func(o protocol.Then) bool { return reflect.DeepEqual(t, o) })
}

// removeThens removes the then records for which drop returns true.
func removeThens(thens records, drop func(protocol.Then) bool) error {
	lines, err := thens.read()
	if err != nil {
		return err
	}
	var gone []string
	for _, l := range lines {
		var t protocol.Then
		if json.Unmarshal([]byte(l), &t) == nil && drop(t) {
			gone = append(gone, l)
		}
	}
	return thens.remove(gone...)
}

func execCommand(ctx context.Context, params json.RawMessage) (module.ExecResult, error) {
	var e protocol.Exec
	if err := json.Unmarshal(params, &e); err != nil {
		return module.ExecResult{}, fmt.Errorf("decode exec: %w", err)
	}
	return module.Exec(ctx, e.Command)
}
