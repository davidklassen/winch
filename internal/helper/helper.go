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
	var reacts, downloads, certbotHooks, checks records
	var old []string
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
			err = errors.Join(err, rb.end(ctx, reacts))
		}
		err = errors.Join(err, os.RemoveAll(filepath.Join(dir, module.FetchedDir)))
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
			var h protocol.Hello
			if err = json.Unmarshal(req.Params, &h); err != nil {
				err = fmt.Errorf("decode hello: %w", err)
			} else {
				lock, err = takeLock(ctx, h, dir, self)
			}
			reacts = records{dir: filepath.Join(dir, "react"), project: h.Project, what: "pending steps"}
			old = []string{filepath.Join(dir, "handlers", h.Project), filepath.Join(dir, "then", h.Project)}
			downloads = downloadRecords(filepath.Join(dir, "downloads", h.Project))
			certbotHooks = records{dir: filepath.Join(dir, "certbot-hooks"), project: h.Project, what: "pending certbot hooks"}
			checks = records{dir: filepath.Join(dir, "checks"), project: h.Project, what: "pending health gates"}
			rb = &rollbacks{dir: filepath.Join(dir, "rollback"), project: h.Project, self: self, downloads: downloads, masked: maskedRecords{dir: filepath.Join(dir, "masked", h.Project)}}
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
				err = rb.idle()
			}
			if err == nil && !h.Resume && len(rb.due) == 0 {
				err = rb.clear(reacts)
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
			var p protocol.Pending
			p, err = readPending(reacts, checks)
			if err == nil {
				p.Old, err = oldRecords(old)
			}
			if err == nil {
				p.Rollback, err = rb.dueChanges(ctx)
			}
			// A due job that changes nothing would stay due with no plan line.
			if err == nil && p.Rollback == nil && len(rb.due) > 0 {
				err = rb.runDue(ctx, reacts)
			}
			result = p
		case req.Method == "due":
			err = rb.runDue(ctx, reacts)
		case req.Method == "dropold":
			err = dropOld(old)
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
			err = command(ctx, req.Params, reacts)
		case req.Method == "reacted":
			err = reacted(req.Params, reacts)
		case req.Method == "drop":
			err = drop(req.Params, reacts)
		case req.Method == "exec":
			result, err = execCommand(inCtx, req.Params)
		case req.Method == "health":
			err = runHealth(ctx, req.Params, checks)
		case req.Method == "check":
			result, err = step(ctx, req.Params, false, login, loginUser, reacts, downloads, certbotHooks, rb, say)
		case req.Method == "apply":
			result, err = step(ctx, req.Params, true, login, loginUser, reacts, downloads, certbotHooks, rb, say)
		case req.Method == "confirm":
			err = confirmStep(ctx, rb, reacts)
		case req.Method == "rollback":
			err = rollbackStep(ctx, rb, reacts)
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

// takeLock takes the lock of the state directory for the session of h. The
// returned lock is busy.
func takeLock(ctx context.Context, h protocol.Hello, dir, self string) (_ *lockFile, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := checkTree(dir, uint32(os.Geteuid())); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	busy, err := os.Open(dir)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("open lock: %w", err)
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
		return nil, err
	}
	locked, err := tryLock(f)
	if err != nil {
		return nil, err
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
			return nil, err
		}
	}
	if !locked {
		// The record is empty, or half written, until its holder writes it.
		if held.Run == "" {
			return nil, errors.New("locked by another run that is starting; run winch again to see which one")
		}
		msg := fmt.Sprintf("locked by run %s (%s@%s, since %s", held.Run, held.User, held.Machine, held.Started.UTC().Format(time.RFC3339))
		if held.PID <= 1 {
			return nil, fmt.Errorf("%s); if that run is gone, end the process that holds %s", msg, f.Name())
		}
		return nil, fmt.Errorf("%s, helper process %d); if that run is gone, end it with: sudo kill %d", msg, held.PID, held.PID)
	}
	if err := l.mark(false); err != nil {
		return nil, err
	}
	data, err := json.Marshal(lockRecord{Hello: h, PID: os.Getpid()})
	if err != nil {
		return nil, err
	}
	// Write before truncate, so a reader never sees an empty file.
	if _, err := f.WriteAt(data, 0); err != nil {
		return nil, fmt.Errorf("write lock: %w", err)
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return nil, fmt.Errorf("write lock: %w", err)
	}
	if err := deleteOld(filepath.Join(dir, "bin"), self); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(filepath.Join(dir, module.FetchedDir)); err != nil {
		return nil, err
	}
	return l, nil
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
// runs as root. The start script checks dir itself. In winch's package index,
// a symbolic link of owner passes: apt links the index of a file: or
// mirror+file: source. The mode of a link has no meaning.
func checkTree(dir string, owner uint32) error {
	lists := filepath.Join(dir, module.ListsDir) + string(filepath.Separator)
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
		link := info.Mode()&fs.ModeSymlink != 0 && strings.HasPrefix(p, lists)
		if !info.IsDir() && !info.Mode().IsRegular() && !link {
			return fmt.Errorf("%s is not a directory or a regular file", p)
		}
		if !ok || st.Uid != owner || !link && info.Mode().Perm()&0o022 != 0 {
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

// step checks a step. With apply, it then records the later steps that react
// to the step, and makes the changes the check found. When the changes fail,
// it removes the records that it added.
// After a successful unpack, it records the checksum, owner, and group.
func step(ctx context.Context, params json.RawMessage, apply bool, login module.State, loginUser *module.Login, reacts, downloads, certbotHooks records, rb *rollbacks, say module.Say) (protocol.StepResult, error) {
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
	var kept *string
	if err == nil && (apply || res.Old != nil) {
		kept, err = rb.masked.read(m)
	}
	if !apply {
		res.Masked = kept
	}
	if err == nil && apply && res.Status == module.OK && s.Masked != nil {
		err = rb.masked.keep(m, kept, *s.Masked)
	}
	// The apply of this step installs them, so a later check reads dpkg: the
	// refresh can have replaced the versions that the check recorded.
	if apply {
		s.State.Packages = nil
	}
	var socket bool
	if err == nil && (res.Status == module.Change || res.Status == module.Unknown) {
		touches := module.Touches(m)
		if line := module.Guard(touches, loginUser); line != "" {
			res.Guard = true
			res.Changes = append([]string{line}, res.Changes...)
		}
		socket, err = module.SSHSocket(ctx, touches)
		if socket {
			res.Changes = append(res.Changes, "daemon-reload", module.SSHSocketRestart)
			if !res.Guard {
				res.Guard = true
				res.Changes = append([]string{module.SSHSocketNote(m, res)}, res.Changes...)
			}
		}
	}
	out := protocol.StepResult{Result: res, State: s.State}
	if err != nil || !apply || res.Status == module.OK {
		return out, err
	}
	if isCertbot {
		if hooks := c.HooksToRun(); len(hooks) > 0 {
			if err := record(certbotHooks, strings.Join(hooks, ","), c.Name); err != nil {
				return out, err
			}
		}
	}
	// The plan has shown the diff already.
	out.Old, out.New, out.OldReason = nil, nil, ""
	// A failed unpack leaves the unpack directory, so only the record shows
	// that the unpack is not done.
	if unpack {
		if err := forget(downloads, d.Unpack); err != nil {
			return out, err
		}
	}
	var lines []string
	for _, r := range s.React {
		lines = append(lines, r.Line())
	}
	added, err := reacts.add(lines)
	if err != nil {
		return out, err
	}
	if err := recordSSHOff(rb, m, res.Changes); err != nil {
		return out, errors.Join(err, reacts.remove(added...))
	}
	guard := s.Guard.Confirm || res.Guard
	var deadline time.Time
	var guarded []string
	for i, g := range s.Guard.Guarded {
		saved, _, err := rb.save(rb.store(g.Store()), m)
		if err != nil {
			return out, errors.Join(err, reacts.remove(added...))
		}
		guarded = append(guarded, g.Line())
		// Each store saves the same paths. The record of masked content
		// is winch's own.
		for _, sv := range saved {
			if i == 0 && !strings.HasPrefix(sv.Path, rb.masked.dir+"/") {
				out.Saved = append(out.Saved, sv.Path)
			}
		}
	}
	var untested []string
	for _, st := range s.Guard.SSHD {
		if _, _, err := rb.save(rb.store(st), m); err != nil {
			return out, errors.Join(err, reacts.remove(added...))
		}
		for _, t := range rb.touches(m) {
			line, _ := json.Marshal(untestedFile{Store: st, Path: t.Path})
			untested = append(untested, string(line))
		}
	}
	if _, err := rb.sshd().add(untested); err != nil {
		return out, errors.Join(err, reacts.remove(added...))
	}
	if _, err := rb.notified().add(guarded); err != nil {
		return out, errors.Join(err, reacts.remove(added...))
	}
	_, isCmd := m.(*module.Cmd)
	var saved, all []module.Saved
	if guard {
		var err error
		saved, all, err = rb.save(rb.store(s.Guard.Store), m)
		// The timer of a command starts when it ends, so a long command does
		// not roll back while it runs.
		if err == nil && !isCmd {
			deadline, err = startTimer(rb, s.Guard, m, saved, all)
		}
		if err != nil {
			return out, errors.Join(err, reacts.remove(added...))
		}
	}
	// The record comes first, so that a crash in the write leaves a record that
	// hides, not a secret that shows.
	if s.Masked != nil {
		err = rb.masked.keep(m, kept, *s.Masked)
	}
	if err == nil {
		err = m.Apply(ctx, say)
	}
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
	if isCmd && guard {
		var terr error
		deadline, terr = startTimer(rb, s.Guard, m, saved, all)
		if terr != nil {
			err = errors.Join(err, terr)
			if rerr := restore(ctx, rb.downloads, saved); rerr != nil {
				err = fmt.Errorf("%w; the rollback failed: %w", err, rerr)
			} else {
				err = fmt.Errorf("%w; the old files are back", err)
			}
			return out, errors.Join(err, reacts.remove(added...))
		}
	}
	if err != nil {
		// A failed command can have changed the paths in part. The access
		// check decides whether they go back.
		if isCmd && guard {
			if reacts.remove(added...) == nil {
				out.Timer, out.Failed = time.Until(deadline), err.Error()
				rb.running = &guardedStep{}
				return out, nil
			}
		}
		if guard {
			if rerr := rb.rollback(ctx); rerr != nil {
				return out, fmt.Errorf("%w; the rollback failed: %w", err, rerr)
			}
			err = fmt.Errorf("%w; the old files are back", err)
		}
		return out, errors.Join(err, reacts.remove(added...))
	}
	if guard {
		out.Timer = time.Until(deadline)
		rb.running = &guardedStep{added: added}
	}
	// sshd now loads all its files: the access check tests them, and the
	// rollback puts back those of the store.
	sv, isService := m.(*module.Service)
	if s.Guard.LoadsSSHD && (!isService || sv.RunsAfter()) {
		if err := rb.tested(rb.store(s.Guard.Store)); err != nil {
			return out, err
		}
	}
	if unpack {
		return out, record(downloads, d.Record(), d.Unpack)
	}
	// After the write: a failure keeps the records of the step, and the next
	// run sees the file as written. A line step cannot tell that the file has
	// no secret left.
	if _, isLine := m.(*module.Line); !isLine && s.Masked == nil && res.WritesContent() {
		return out, rb.masked.remove(m)
	}
	return out, nil
}

// recordSSHOff records the stop and the disable of an SSH server unit, which
// the rollback of a start of the other unit puts back.
func recordSSHOff(rb *rollbacks, m module.Module, changes []string) error {
	sv, ok := m.(*module.Service)
	if !ok || module.SSHPair(sv.Unit()) == "" {
		return nil
	}
	var off []string
	for _, c := range changes {
		if c == "stop" || c == "disable" {
			off = append(off, c+" "+sv.Unit())
		}
	}
	_, err := rb.sshOff().add(off)
	return err
}

// startTimer starts the rollback timer of the guarded step m. A step with
// confirm_access puts back its whole store, and its undo step; another
// guarded step puts back only what it saved.
func startTimer(rb *rollbacks, g protocol.Guard, m module.Module, saved, all []module.Saved) (time.Time, error) {
	j := job{Deadline: time.Now().Add(timerTime), Restore: saved, Downloads: filepath.Join(rb.downloads.dir, rb.downloads.project)}
	add := func(name string, step any) error {
		args, err := json.Marshal(step)
		j.Undo = append(j.Undo, undo{Module: name, Args: args})
		return err
	}
	if u, ok := m.(*module.User); ok {
		if un := u.Undo(); un != nil {
			if err := add("user", un); err != nil {
				return time.Time{}, err
			}
		}
	}
	if g.Confirm {
		j.Restore = all
		if sv, ok := m.(*module.Service); ok {
			if u := sv.Undo(); u != nil {
				if err := add("service", u); err != nil {
					return time.Time{}, err
				}
				back, err := sshBack(rb, u)
				if err != nil {
					return time.Time{}, err
				}
				if back != nil {
					if err := add("service", back); err != nil {
						return time.Time{}, err
					}
				}
			}
		}
	}
	return j.Deadline, rb.start(j)
}

// sshBack returns the step that starts and enables the other SSH server unit
// again, when the undo step u stops one and the run stopped or disabled the
// other: else no unit runs sshd after the rollback. It returns nil for
// another undo step.
func sshBack(rb *rollbacks, u *module.Service) (*module.Service, error) {
	other := module.SSHPair(u.Unit())
	if other == "" || u.Running == nil || *u.Running {
		return nil, nil
	}
	off, err := rb.sshOff().read()
	if err != nil {
		return nil, err
	}
	yes := true
	back := &module.Service{Name: other}
	if slices.Contains(off, "stop "+other) {
		back.Running = &yes
	}
	if slices.Contains(off, "disable "+other) {
		back.Enabled = &yes
	}
	if back.Running == nil && back.Enabled == nil {
		return nil, nil
	}
	return back, nil
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
	if f.SSH, err = facts.ReadSSH("/etc/ssh"); err != nil {
		return f, err
	}
	f.Net = facts.ReadNet()
	return f, nil
}

func readPending(reacts, checks records) (protocol.Pending, error) {
	lines, err := reacts.read()
	if err != nil {
		return protocol.Pending{}, err
	}
	p := protocol.Pending{React: []protocol.React{}}
	for i, l := range lines {
		if l == "" {
			continue
		}
		var r protocol.React
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			return protocol.Pending{}, fmt.Errorf("read the pending steps: %s:%d is not a record; delete the file, and the records in it are lost", filepath.Join(reacts.dir, reacts.project), i+2)
		}
		p.React = append(p.React, r)
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
			return protocol.Pending{}, fmt.Errorf("read the pending health gates: %s:%d is not a record; delete the file, and the records in it are lost", filepath.Join(checks.dir, checks.project), i+2)
		}
		p.Checks = append(p.Checks, c)
	}
	return p, nil
}

// oldRecords returns those of paths that hold a record: the record files of
// an older winch. A file keeps its version line when its last record goes.
func oldRecords(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		_, rest, _ := strings.Cut(string(data), "\n")
		if strings.TrimSpace(rest) != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// dropOld removes the record files of an older winch.
func dropOld(paths []string) error {
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}

// checkLine returns the record line of the gate in params.
func checkLine(params json.RawMessage) (string, error) {
	var c protocol.Check
	if err := json.Unmarshal(params, &c); err != nil {
		return "", fmt.Errorf("decode check: %w", err)
	}
	line, err := json.Marshal(c)
	return string(line), err
}

// command runs the command of a then, and then removes the records that
// match it.
func command(ctx context.Context, params json.RawMessage, reacts records) error {
	var c protocol.Command
	if err := json.Unmarshal(params, &c); err != nil {
		return fmt.Errorf("decode command: %w", err)
	}
	if err := module.Shell(ctx, c.Command); err != nil {
		return err
	}
	return removeReacts(reacts, c.React.Matches)
}

// reacted removes the records that match the record of a step that
// succeeded.
func reacted(params json.RawMessage, reacts records) error {
	var r protocol.React
	if err := json.Unmarshal(params, &r); err != nil {
		return fmt.Errorf("decode reacted: %w", err)
	}
	return removeReacts(reacts, r.Matches)
}

// drop removes a record that matches no step.
func drop(params json.RawMessage, reacts records) error {
	var r protocol.React
	if err := json.Unmarshal(params, &r); err != nil {
		return fmt.Errorf("decode drop: %w", err)
	}
	return reacts.remove(r.Line())
}

// removeReacts removes the records for which drop returns true.
func removeReacts(reacts records, drop func(protocol.React) bool) error {
	lines, err := reacts.read()
	if err != nil {
		return err
	}
	var gone []string
	for _, l := range lines {
		var r protocol.React
		if json.Unmarshal([]byte(l), &r) == nil && drop(r) {
			gone = append(gone, l)
		}
	}
	return reacts.remove(gone...)
}

func execCommand(ctx context.Context, params json.RawMessage) (module.ExecResult, error) {
	var e protocol.Exec
	if err := json.Unmarshal(params, &e); err != nil {
		return module.ExecResult{}, fmt.Errorf("decode exec: %w", err)
	}
	return module.Exec(ctx, e.Command, e.Timeout)
}
