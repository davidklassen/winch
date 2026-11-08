package helper

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

// job is a rollback timer: at Deadline, the timer process puts back Restore
// and runs Undo, the steps that reverse what the guarded step did. Downloads
// is the file of the download records of the project.
type job struct {
	Version   int            `json:"version"`
	Deadline  time.Time      `json:"deadline"`
	Restore   []module.Saved `json:"restore"`
	Undo      []undo         `json:"undo,omitempty"`
	Downloads string         `json:"downloads"`
}

type undo struct {
	Module string          `json:"module"`
	Args   json.RawMessage `json:"args"`
}

// jobVersion is the format version of the timer job. A job of version 1 has
// no version, and at most one undo step, not a list.
const jobVersion = 2

// decodeJob decodes the timer job data of the file path. It returns the job
// with its version also when the version is newer than winch knows.
func decodeJob(path string, data []byte) (job, error) {
	// A newer version can change the type of any field.
	var head struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(data, &head) == nil && head.Version > jobVersion {
		return job{Version: head.Version}, fmt.Errorf("upgrade winch to read %s", path)
	}
	var v struct {
		job
		Undo json.RawMessage `json:"undo"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return job{}, fmt.Errorf("read the rollback timer %s: %w", path, err)
	}
	j := v.job
	var err error
	switch {
	case len(v.Undo) == 0 || string(v.Undo) == "null":
	case j.Version < 2:
		j.Undo = make([]undo, 1)
		err = json.Unmarshal(v.Undo, &j.Undo[0])
	default:
		err = json.Unmarshal(v.Undo, &j.Undo)
	}
	if err != nil {
		return job{}, fmt.Errorf("read the rollback timer %s: %w", path, err)
	}
	return j, nil
}

// timerTime is the time between the start of a rollback timer and the
// rollback.
const timerTime = 60 * time.Second

// rollbacks is the rollback store of a project: one directory per guarded
// step, with an index of the saved paths and their tar files. It also holds
// the job of the rollback timer, which belongs to no project, so that no
// session starts while a timer runs.
type rollbacks struct {
	dir     string
	project string
	// self is the helper binary, which runs the timer process.
	self      string
	downloads records
	masked    maskedRecords
	// running holds the records that the guarded step added, while its timer
	// runs.
	running *guardedStep
	// timer is closed when the timer process of this session ends. It is nil
	// when no timer process of this session runs.
	timer chan struct{}
	// due are the jobs of earlier runs whose timer process is gone. They run
	// only on the due request; until then, the stores stay.
	due []string
}

type guardedStep struct {
	added []string
}

func (r *rollbacks) job() string { return filepath.Join(r.dir, "timer.json") }

// result is the file where the timer process writes the error of its
// rollback, empty after a rollback without an error.
func result(job string) string { return job + ".result" }

// sshd holds the sshd files that the run changed after its last guarded
// restart or reload of sshd, as untested lines, each with a store that keeps
// its old state.
func (r *rollbacks) sshd() records {
	return records{dir: filepath.Join(r.dir, r.project), project: "sshd", what: "untested sshd files"}
}

// untestedFile is a line of the untested sshd files: Store names a store as
// Guard.SSHD does.
type untestedFile struct {
	Store string `json:"store"`
	Path  string `json:"path"`
}

// store returns the directory of the store that protocol.React.Store names.
func (r *rollbacks) store(name string) string {
	return filepath.Join(r.dir, r.project, name)
}

// notified holds the records of the steps with confirm_access that react to
// a change of the run. The reconnect after a reboot keeps it; the next run's
// first session removes it with the stores.
func (r *rollbacks) notified() records {
	return records{dir: filepath.Join(r.dir, r.project), project: "notified", what: "guarded steps that react to a change"}
}

// sshOff holds the stops and disables of the SSH server units that the steps
// of the run applied, as "stop <unit>" and "disable <unit>".
func (r *rollbacks) sshOff() records {
	return records{dir: filepath.Join(r.dir, r.project), project: "ssh-off", what: "stopped SSH units"}
}

// idle fails while a rollback timer runs or puts back files. A job whose lock
// is free has no process left, for example after a power cycle: idle adds it to
// the due jobs.
func (r *rollbacks) idle() error {
	for _, p := range []string{r.job(), r.job() + ".fired"} {
		live, err := timerLive(p)
		if err != nil {
			return fmt.Errorf("read the rollback timer: %w", err)
		}
		// A timer that ended since the lock check has removed its job.
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read the rollback timer: %w", err)
		}
		j, err := decodeJob(p, data)
		if j.Version > jobVersion {
			return err
		}
		if err != nil {
			return fmt.Errorf("the rollback timer of an earlier run ended without its process: %w", errors.Join(err, os.Remove(p)))
		}
		if !live {
			r.due = append(r.due, p)
			continue
		}
		deadline := j.Deadline.UTC().Format(time.RFC3339)
		if time.Now().After(j.Deadline) {
			return fmt.Errorf("a rollback timer of an earlier run started its rollback at %s; run winch again after it ends", deadline)
		}
		return fmt.Errorf("a rollback timer of an earlier run runs until %s; run winch again after it ends", deadline)
	}
	return nil
}

// timerLive reports whether a process holds the flock of the job file p. The
// flock follows the file through its rename when the timer fires.
func timerLive(p string) (bool, error) {
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	free, err := tryLock(f)
	return !free, err
}

// dueChanges returns what the due jobs do, as plan lines: the paths that they
// put back or remove, the commands of the restore, and the changes of their
// undo steps.
func (r *rollbacks) dueChanges(ctx context.Context) ([]string, error) {
	var out []string
	for _, p := range r.due {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read the rollback timer: %w", err)
		}
		j, err := decodeJob(p, data)
		if err != nil {
			return nil, err
		}
		for _, s := range j.Restore {
			switch {
			// The job can be of another project.
			case filepath.Dir(filepath.Dir(s.Path)) == filepath.Dir(r.masked.dir):
			case s.Missing:
				out = append(out, "remove "+s.Path)
			case s.Dir != nil:
				out = append(out, "put back the owner, group, and mode of "+s.Path)
			default:
				out = append(out, "put back "+s.Path)
			}
		}
		after, err := module.AfterRestore(ctx, j.Restore)
		if err != nil {
			return nil, err
		}
		out = append(out, after...)
		for _, u := range j.Undo {
			m, res, err := checkUndo(ctx, u)
			if err != nil {
				return nil, err
			}
			if res.Status == module.OK {
				continue
			}
			line := u.Module + " " + m.Main()
			if len(res.Changes) > 0 {
				line += ": " + strings.Join(res.Changes, ", ")
			}
			out = append(out, line)
		}
	}
	return out, nil
}

// runDue runs the due jobs, then clears the stores of the project, as the
// hello of a session without due jobs does.
func (r *rollbacks) runDue(ctx context.Context, reacts records) error {
	for i, p := range r.due {
		if err := errors.Join(runJob(ctx, p), os.Remove(p)); err != nil {
			r.due = r.due[i:]
			return err
		}
	}
	r.due = nil
	return r.clear(reacts)
}

// index returns the records of the saved paths of the store in dir.
func index(dir string) records {
	return records{dir: dir, project: "index", what: "rollback store"}
}

// readIndex returns the saved paths of the store in dir.
func readIndex(dir string) ([]module.Saved, error) {
	lines, err := index(dir).read()
	if err != nil {
		return nil, err
	}
	var out []module.Saved
	for _, l := range lines {
		var s module.Saved
		if err := json.Unmarshal([]byte(l), &s); err != nil {
			return nil, fmt.Errorf("read the rollback store %s: %w", dir, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// touches returns the paths that a rollback puts back for the step m. It puts
// back a file with an old secret, so also its record.
func (r *rollbacks) touches(m module.Module) []module.Touch {
	touches := module.Touches(m)
	if p := r.masked.path(m); p != "" {
		if _, err := os.Lstat(p); err == nil {
			touches = append(touches, module.Touch{Path: p, Tree: true})
		}
	}
	return touches
}

// save keeps the old state of the paths that the checked step m changes in
// the store in dir. It returns the saved state of each, and the whole store.
// A path that the store has keeps its first state: the state before the first
// change.
func (r *rollbacks) save(dir string, m module.Module) (saved, all []module.Saved, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	all, err = readIndex(dir)
	if err != nil {
		return nil, nil, err
	}
	have := len(all)
	for _, t := range r.touches(m) {
		// A tree is saved again after the attributes of its directory: the
		// restore of the tree comes first, then that of the attributes.
		i := slices.IndexFunc(all, func(s module.Saved) bool {
			return s.Path == t.Path && (s.Dir == nil || !t.Tree) || strings.HasPrefix(t.Path, s.Path+"/") && s.Missing
		})
		if i >= 0 {
			saved = append(saved, all[i])
			continue
		}
		s, err := module.Save(t, filepath.Join(dir, rand.Text()+".tar"))
		if err != nil {
			return nil, nil, err
		}
		all = append(all, s)
		saved = append(saved, s)
	}
	if len(all) == have {
		return saved, all, nil
	}
	var lines []string
	for _, s := range all {
		line, err := json.Marshal(s)
		if err != nil {
			return nil, nil, err
		}
		lines = append(lines, string(line))
	}
	return saved, all, index(dir).write(lines)
}

// timerLock is the descriptor of the timer process that holds the flock of its
// job.
const timerLock = 3

// start writes the job of a rollback timer and starts the timer process in a
// session of its own, so it outlives the helper and the SSH connection. The
// flock of the job passes to the process with its start, so no session sees a
// started timer with a free lock.
func (r *rollbacks) start(j job) error {
	j.Version = jobVersion
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := os.Remove(result(r.job())); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := writeJob(r.job(), data); err != nil {
		return err
	}
	if err := r.spawnTimer(); err != nil {
		os.Remove(r.job())
		return fmt.Errorf("start the rollback timer: %w", err)
	}
	return nil
}

func (r *rollbacks) spawnTimer() error {
	lock, err := os.Open(r.job())
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	cmd := exec.Command(r.self, "--rollback", r.job())
	cmd.ExtraFiles = []*os.File{lock}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		cmd.Wait() //nolint:errcheck // the timer reports through its result file
		close(done)
	}()
	r.timer = done
	return nil
}

// confirm stops the timer. It fails when the timer ended first.
func (r *rollbacks) confirm(ctx context.Context) error {
	r.running = nil
	if err := os.Remove(r.job()); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := r.timerResult(ctx); err != nil {
			return fmt.Errorf("the rollback timer ended first; the rollback failed: %w", err)
		}
		return errTimerFirst
	}
	return r.ended(ctx)
}

var errTimerFirst = errors.New("the rollback timer ended first; the old files are back")

// rollback ends the timer at once: it puts back the files and runs the undo
// step. When the timer took the job first, it returns the result of the
// timer's rollback.
func (r *rollbacks) rollback(ctx context.Context) error {
	r.running = nil
	taken, err := fire(ctx, r.job())
	if !taken {
		return r.timerResult(ctx)
	}
	return errors.Join(err, r.ended(ctx))
}

// fire takes the job from the timer and runs it. It returns false when the
// job is gone: a confirm or the timer took it first.
func fire(ctx context.Context, path string) (bool, error) {
	fired := path + ".fired"
	if err := os.Rename(path, fired); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return true, err
	}
	return true, errors.Join(runJob(ctx, fired), os.Remove(fired))
}

// ended waits until the timer process of this session ends. A stopped timer
// ends at its next poll; until then, it would take the job of the next
// guarded step.
func (r *rollbacks) ended(ctx context.Context) error {
	if r.timer == nil {
		return nil
	}
	select {
	case <-r.timer:
	case <-ctx.Done():
		return ctx.Err()
	}
	r.timer = nil
	return nil
}

// timerResult waits until the timer process of this session ends, and
// returns the error of the rollback that it ran.
func (r *rollbacks) timerResult(ctx context.Context) error {
	if r.timer == nil {
		return nil
	}
	if err := r.ended(ctx); err != nil {
		return err
	}
	data, err := os.ReadFile(result(r.job()))
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("the rollback timer ended without a result")
	}
	if err != nil {
		return err
	}
	if err := os.Remove(result(r.job())); err != nil {
		return err
	}
	if len(data) > 0 {
		return errors.New(string(data))
	}
	return nil
}

// clear removes the stores of the project, except those of pending steps.
// The caller checks that no timer runs.
func (r *rollbacks) clear(reacts records) error {
	// A damaged file of pending steps fails the pending request; until then
	// the stores stay.
	pending, err := reacts.read()
	if err != nil {
		return nil
	}
	dir := filepath.Join(r.dir, r.project)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, l := range pending {
		var rec protocol.React
		if json.Unmarshal([]byte(l), &rec) == nil {
			keep[rec.Store()] = true
		}
	}
	for _, e := range entries {
		if keep[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// end runs when the session ends. The run of the host ended before each step
// with confirm_access that reacts to a change of the run and that is still
// pending: end puts back the store of the step and drops its record. A step
// whose store does not come back stays pending. A timer that still runs rolls
// back first. While jobs are due, the stores and records are those of the
// earlier run, and end changes nothing.
func (r *rollbacks) end(ctx context.Context, reacts records) error {
	if len(r.due) > 0 {
		return nil
	}
	errs := []error{rollbackStep(ctx, r, reacts), r.putBackUntested(ctx)}
	notified, err := r.notified().read()
	if err != nil || len(notified) == 0 {
		return errors.Join(append(errs, err)...)
	}
	pending, err := reacts.read()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	var drop []string
	for _, line := range notified {
		if !slices.Contains(pending, line) {
			continue
		}
		var rec protocol.React
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			errs = append(errs, fmt.Errorf("read the guarded steps that react to a change: %w", err))
			continue
		}
		saved, err := readIndex(r.store(rec.Store()))
		if err == nil {
			err = restore(ctx, r.downloads, saved)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("put back the files of a %s step that did not run: %w", rec.Module, err))
			continue
		}
		drop = append(drop, line)
	}
	return errors.Join(append(errs, reacts.remove(drop...))...)
}

// tested drops the lines of the untested sshd files that the store in dir
// holds: the rollback of a guarded sshd reload with that store puts them
// back.
func (r *rollbacks) tested(dir string) error {
	saved, err := readIndex(dir)
	if err != nil {
		return err
	}
	lines, err := r.sshd().read()
	if err != nil {
		return err
	}
	var drop []string
	for _, line := range lines {
		var u untestedFile
		if json.Unmarshal([]byte(line), &u) == nil && slices.ContainsFunc(saved, func(s module.Saved) bool { return s.Path == u.Path }) {
			drop = append(drop, line)
		}
	}
	return r.sshd().remove(drop...)
}

// putBackUntested puts back the sshd files that no guarded restart or
// reload of sshd tested, each from the store of its first line, and drops
// the lines.
func (r *rollbacks) putBackUntested(ctx context.Context) error {
	lines, err := r.sshd().read()
	if err != nil || len(lines) == 0 {
		return err
	}
	var back []module.Saved
	for _, line := range lines {
		var u untestedFile
		if err := json.Unmarshal([]byte(line), &u); err != nil {
			return fmt.Errorf("read the untested sshd files: %w", err)
		}
		if slices.ContainsFunc(back, func(s module.Saved) bool { return s.Path == u.Path }) {
			continue
		}
		saved, err := readIndex(r.store(u.Store))
		if err != nil {
			return err
		}
		// A tree can follow the attributes of its directory.
		for _, s := range saved {
			if s.Path == u.Path {
				back = append(back, s)
			}
		}
	}
	if err := restore(ctx, r.downloads, back); err != nil {
		return fmt.Errorf("put back the sshd files that no guarded sshd reload tested: %w", err)
	}
	return r.sshd().write(nil)
}

// rollbackStep ends the timer of the guarded step at once, and drops the
// records that the step added. When the rollback fails, the records stay, so
// that the next run applies them under the access check.
func rollbackStep(ctx context.Context, r *rollbacks, reacts records) error {
	g := r.running
	if err := r.rollback(ctx); err != nil || g == nil {
		return err
	}
	return reacts.remove(g.added...)
}

// confirmStep stops the timer of the guarded step. When the timer ended first
// and put back the files, it drops the records that the step added, as
// rollbackStep does.
func confirmStep(ctx context.Context, r *rollbacks, reacts records) error {
	g := r.running
	err := r.confirm(ctx)
	if g == nil || !errors.Is(err, errTimerFirst) {
		return err
	}
	return errors.Join(err, reacts.remove(g.added...))
}

// RunTimer is the timer process: it waits until the job is gone, which
// stops the timer, or until its deadline. Then it puts back the files, runs
// the undo step, and writes the result for the helper.
func RunTimer(ctx context.Context, path string, poll time.Duration) error {
	// A process that a command of the rollback leaves must not look like a live
	// timer.
	syscall.CloseOnExec(timerLock)
	for {
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		j, err := decodeJob(path, data)
		if err != nil {
			return err
		}
		if !time.Now().Before(j.Deadline) {
			taken, err := fire(ctx, path)
			if !taken {
				return nil
			}
			var text string
			if err != nil {
				text = err.Error()
			}
			return os.WriteFile(result(path), []byte(text), 0o600)
		}
		time.Sleep(poll)
	}
}

func runJob(ctx context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	j, err := decodeJob(path, data)
	if err != nil {
		return err
	}
	errs := []error{restore(ctx, downloadRecords(j.Downloads), j.Restore)}
	for _, u := range j.Undo {
		errs = append(errs, runUndo(ctx, u))
	}
	return errors.Join(errs...)
}

func runUndo(ctx context.Context, u undo) error {
	m, res, err := checkUndo(ctx, u)
	if err == nil && res.Status != module.OK {
		if err = m.Apply(ctx, module.Silent{}); err != nil {
			err = fmt.Errorf("%s %s: %w", u.Module, m.Main(), err)
		}
	}
	return err
}

func checkUndo(ctx context.Context, u undo) (module.Module, module.Result, error) {
	m, ok := module.New(u.Module)
	if !ok {
		return nil, module.Result{}, fmt.Errorf("unknown module %q", u.Module)
	}
	if err := json.Unmarshal(u.Args, m); err != nil {
		return nil, module.Result{}, err
	}
	// The timer has no session, so no login user: uid -1 is no user.
	res, err := m.Check(ctx, &module.State{LoginUID: math.MaxUint32}, module.Silent{})
	if err != nil {
		return nil, module.Result{}, fmt.Errorf("%s %s: %w", u.Module, m.Main(), err)
	}
	return m, res, nil
}

// restore puts back the saved paths. It first drops the unpack records of the
// trees that the restore changes, so that the unpack runs again: at and above
// each path, and below a path whose content comes back.
func restore(ctx context.Context, downloads records, saved []module.Saved) error {
	err := forgetIf(downloads, func(key string) bool {
		return slices.ContainsFunc(saved, func(s module.Saved) bool {
			return key == s.Path || strings.HasPrefix(s.Path, key+"/") || s.Dir == nil && strings.HasPrefix(key, s.Path+"/")
		})
	})
	return errors.Join(err, module.Restore(ctx, saved))
}

// writeJob writes the job of a timer through a rename.
func writeJob(path string, data []byte) error {
	return writeFile(filepath.Dir(path), filepath.Base(path), "rollback timer", string(data)+"\n")
}
