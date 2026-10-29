package helper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
// and runs Undo, a step that reverses what the guarded step did.
type job struct {
	Deadline time.Time      `json:"deadline"`
	Restore  []module.Saved `json:"restore"`
	Undo     *undo          `json:"undo,omitempty"`
}

type undo struct {
	Module string          `json:"module"`
	Args   json.RawMessage `json:"args"`
}

// TimerTime is the time between the start of a rollback timer and the
// rollback.
const TimerTime = 60 * time.Second

// rollbacks is the rollback store of a project: one directory per recipe or
// stage, with an index of the saved paths and their tar files. It also holds
// the job of the rollback timer, which belongs to no project, so that no
// session starts while a timer runs.
type rollbacks struct {
	dir     string
	project string
	// self is the helper binary, which runs the timer process.
	self string
	// running holds the records that the guarded step added, while its timer
	// runs.
	running *guarded
}

type guarded struct {
	handlers, thens []string
}

func (r *rollbacks) job() string { return filepath.Join(r.dir, "timer.json") }

// scope returns the directory of the store of g.
func (r *rollbacks) scope(g protocol.Guard) string {
	name := "recipe-" + g.Recipe
	if g.Recipe == "" {
		name = stageStore(g.Pipeline + "\t" + g.Stage)
	}
	return filepath.Join(r.dir, r.project, name)
}

// notified holds the records of the handlers with confirm_access that the
// steps of the run notified. The reconnect after a reboot keeps it; the next
// run's first session removes it with the stores.
func (r *rollbacks) notified() records {
	return records{dir: filepath.Join(r.dir, r.project), project: "notified", what: "notified handlers"}
}

func (r *rollbacks) handlerStore(h string) string {
	return filepath.Join(r.dir, r.project, handlerStoreName(h))
}

// handlerStoreName is the directory name of the store of the handler with the
// record h. A handler of a stage is <pipeline>\t<stage>\t<handler>, one of a
// recipe <recipe>.<handler>.
func handlerStoreName(h string) string {
	if i := strings.LastIndex(h, "\t"); i >= 0 {
		return stageStore(h[:i])
	}
	recipe, _, _ := strings.Cut(h, ".")
	return "recipe-" + recipe
}

// stageStore is the directory name of the store of a stage, from
// <pipeline>\t<stage>.
func stageStore(stage string) string {
	sum := sha256.Sum256([]byte(stage))
	return "stage-" + hex.EncodeToString(sum[:8])
}

// idle fails while a rollback timer runs or puts back files. A job that is
// past its deadline by more than deadGrace has no process left, for example
// after a power cycle: idle runs it.
func (r *rollbacks) idle(ctx context.Context) error {
	for _, p := range []string{r.job(), r.job() + ".fired"} {
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read the rollback timer: %w", err)
		}
		var j job
		_ = json.Unmarshal(data, &j)
		if time.Since(j.Deadline) < deadGrace {
			return fmt.Errorf("a rollback timer of an earlier run runs until %s; run winch again after it ends", j.Deadline.UTC().Format(time.RFC3339))
		}
		if err := errors.Join(runJob(ctx, p), os.Remove(p)); err != nil {
			return fmt.Errorf("the rollback timer of an earlier run ended without its process: %w", err)
		}
	}
	return nil
}

// deadGrace is the time after its deadline when a timer has surely put back
// its files.
const deadGrace = 30 * time.Second

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
	for _, t := range module.Touches(m) {
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

// start writes the job of a rollback timer and starts the timer process in a
// session of its own, so it outlives the helper and the SSH connection.
func (r *rollbacks) start(j job) error {
	if r.self == "" {
		return errors.New("the helper does not know its own binary to start the rollback timer")
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := writeJob(r.job(), data); err != nil {
		return err
	}
	cmd := exec.Command(r.self, "--rollback", r.job())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		os.Remove(r.job())
		return fmt.Errorf("start the rollback timer: %w", err)
	}
	go cmd.Wait() //nolint:errcheck // the timer reports nothing; the wait reaps it
	return nil
}

// confirm stops the timer. It fails when the timer ended first.
func (r *rollbacks) confirm() error {
	r.running = nil
	done := r.job() + ".done"
	if err := os.Rename(r.job(), done); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errors.New("the rollback timer ended first; the old files are back")
		}
		return err
	}
	return os.Remove(done)
}

// rollback ends the timer at once: it puts back the files and runs the undo
// step. When the timer took the job first, the files are back already.
func (r *rollbacks) rollback(ctx context.Context) error {
	r.running = nil
	return fire(ctx, r.job())
}

// fire takes the job from the timer and runs it. It does nothing when the
// job is gone: a confirm or the timer took it first.
func fire(ctx context.Context, path string) error {
	fired := path + ".fired"
	if err := os.Rename(path, fired); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return errors.Join(runJob(ctx, fired), os.Remove(fired))
}

// clear removes the stores of the project, except those of recipes and
// stages with a pending handler. The caller checks that no timer runs.
func (r *rollbacks) clear(handlers records) error {
	// A damaged file of pending handlers fails the pending request; until
	// then the stores stay.
	pending, err := handlers.read()
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
	for _, h := range pending {
		keep[handlerStoreName(h)] = true
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

// end runs when the session ends. The run of the host ended before each
// handler with confirm_access that the run notified and that is still
// pending: end puts back the store of the handler and drops its record. A
// handler whose store does not come back stays pending. A timer that still
// runs rolls back first.
func (r *rollbacks) end(ctx context.Context, handlers, thens records) error {
	errs := []error{rollbackStep(ctx, r, handlers, thens)}
	notified, err := r.notified().read()
	if err != nil || len(notified) == 0 {
		return errors.Join(append(errs, err)...)
	}
	pending, err := handlers.read()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	var drop []string
	restored := map[string]error{}
	for _, h := range notified {
		if !slices.Contains(pending, h) {
			continue
		}
		dir := r.handlerStore(h)
		err, done := restored[dir]
		if !done {
			saved, rerr := readIndex(dir)
			if rerr == nil {
				rerr = module.Restore(ctx, saved)
			}
			err, restored[dir] = rerr, rerr
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("put back the files of the handler %s that did not run: %w", h, err))
			continue
		}
		drop = append(drop, h)
	}
	return errors.Join(append(errs, handlers.remove(drop...))...)
}

// rollbackStep ends the timer of the guarded step at once, and drops the
// records that the step added.
func rollbackStep(ctx context.Context, r *rollbacks, handlers, thens records) error {
	g := r.running
	err := r.rollback(ctx)
	if g != nil {
		err = errors.Join(err, handlers.remove(g.handlers...), thens.remove(g.thens...))
	}
	return err
}

// RunTimer is the timer process: it waits until the job is gone, which
// stops the timer, or until its deadline. Then it puts back the files and
// runs the undo step.
func RunTimer(ctx context.Context, path string, poll time.Duration) error {
	for {
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		var j job
		if err := json.Unmarshal(data, &j); err != nil {
			return err
		}
		if !time.Now().Before(j.Deadline) {
			return fire(ctx, path)
		}
		time.Sleep(poll)
	}
}

func runJob(ctx context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var j job
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	err = module.Restore(ctx, j.Restore)
	if j.Undo == nil {
		return err
	}
	m, ok := module.New(j.Undo.Module)
	if !ok {
		return errors.Join(err, fmt.Errorf("unknown module %q", j.Undo.Module))
	}
	if uerr := json.Unmarshal(j.Undo.Args, m); uerr != nil {
		return errors.Join(err, uerr)
	}
	// The timer has no session, so no login user: uid -1 is no user.
	res, cerr := m.Check(ctx, &module.State{LoginUID: math.MaxUint32}, func(string) {})
	if cerr == nil && res.Status != module.OK {
		cerr = m.Apply(ctx, func(string) {})
	}
	if cerr != nil {
		cerr = fmt.Errorf("%s %s: %w", j.Undo.Module, m.Main(), cerr)
	}
	return errors.Join(err, cerr)
}

// writeJob writes the job of a timer through a rename.
func writeJob(path string, data []byte) error {
	return records{dir: filepath.Dir(path), project: filepath.Base(path), what: "rollback timer"}.write([]string{string(data)})
}
