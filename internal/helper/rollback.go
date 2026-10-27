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
		sum := sha256.Sum256([]byte(g.Stage))
		name = "stage-" + hex.EncodeToString(sum[:8])
	}
	return filepath.Join(r.dir, r.project, name)
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
// the store of g. It returns the saved state of each, and the whole store. A
// path that the store has keeps its first state: the state before the first
// change.
func (r *rollbacks) save(g protocol.Guard, m module.Module) (saved, all []module.Saved, err error) {
	dir := r.scope(g)
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
// step.
func (r *rollbacks) rollback(ctx context.Context) error {
	r.running = nil
	fired, err := fire(ctx, r.job())
	if err == nil && !fired {
		return errors.New("the rollback timer ended first; the old files are back")
	}
	return err
}

// fire takes the job from the timer and runs it. It reports false when the
// job is gone: a confirm or the timer took it first.
func fire(ctx context.Context, path string) (bool, error) {
	fired := path + ".fired"
	if err := os.Rename(path, fired); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, errors.Join(runJob(ctx, fired), os.Remove(fired))
}

// clear removes the stores of the project, except those of recipes with a
// pending handler. The caller checks that no timer runs.
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
	for _, e := range entries {
		recipe, ok := strings.CutPrefix(e.Name(), "recipe-")
		if ok && slices.ContainsFunc(pending, func(h string) bool { return strings.HasPrefix(h, recipe+".") }) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
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
			_, err := fire(ctx, path)
			return err
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
	res, cerr := m.Check(ctx, &module.State{}, func(string) {})
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
