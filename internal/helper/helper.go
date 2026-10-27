// Package helper is the program that runs on the host. It reads requests on
// stdin and answers on stdout until stdin closes.
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/davidklassen/winch/internal/facts"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

// Serve answers requests. dir is the state directory, self the path of the
// running helper binary in dir/bin, and login the login user and the
// connection of the session.
func Serve(ctx context.Context, in io.Reader, out io.Writer, dir, self string, login module.State) error {
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	var lock *os.File
	defer func() {
		if lock != nil {
			lock.Close()
		}
	}()
	var handlers, thens, downloads records
	for {
		var req protocol.Request
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read request: %w", err)
		}
		var result any
		var err error
		note := func(msg string) {
			// A failed write fails the answer that follows.
			_ = enc.Encode(protocol.Response{ID: req.ID, Note: msg})
		}
		switch {
		case req.Method == "hello" && lock != nil:
			err = errors.New("hello was already sent")
		case req.Method == "hello":
			var project string
			lock, project, err = takeLock(req.Params, dir, self)
			handlers = records{dir: filepath.Join(dir, "handlers"), project: project, what: "pending handlers"}
			thens = records{dir: filepath.Join(dir, "then"), project: project, what: "pending then records"}
			downloads = records{dir: filepath.Join(dir, "downloads"), project: project, what: "download records"}
		case lock == nil:
			err = errors.New("the first request must be hello")
		case req.Method == "facts":
			result, err = facts.Read("/etc/os-release", "/usr/lib/os-release")
		case req.Method == "pending":
			result, err = readPending(handlers, thens)
		case req.Method == "handled":
			err = handled(req.Params, handlers)
		case req.Method == "command":
			err = command(ctx, req.Params, thens)
		case req.Method == "health":
			err = runHealth(ctx, req.Params)
		case req.Method == "check":
			result, err = step(ctx, req.Params, false, login, handlers, thens, downloads, note)
		case req.Method == "apply":
			result, err = step(ctx, req.Params, true, login, handlers, thens, downloads, note)
		default:
			err = fmt.Errorf("unknown method %q", req.Method)
		}
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
// project of the session.
func takeLock(params json.RawMessage, dir, self string) (_ *os.File, project string, err error) {
	var h protocol.Hello
	if err := json.Unmarshal(params, &h); err != nil {
		return nil, "", fmt.Errorf("decode hello: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create state directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("open lock: %w", err)
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			var held lockRecord
			data, _ := io.ReadAll(f)
			_ = json.Unmarshal(data, &held)
			msg := fmt.Sprintf("locked by run %s (%s@%s, since %s", held.Run, held.User, held.Machine, held.Started.UTC().Format(time.RFC3339))
			// A new lock file is empty until its holder writes it. A kill with
			// a PID below 2 signals a process group or init, not one helper.
			if held.PID <= 1 {
				return nil, "", errors.New(msg + ")")
			}
			return nil, "", fmt.Errorf("%s, helper process %d); if that run is gone, end it with: sudo kill %d", msg, held.PID, held.PID)
		}
		return nil, "", fmt.Errorf("lock: %w", err)
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
	if err := deleteOthers(filepath.Join(dir, "bin"), self); err != nil {
		return nil, "", err
	}
	return f, h.Project, nil
}

func deleteOthers(bin, self string) error {
	entries, err := os.ReadDir(bin)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(self) {
			continue
		}
		if err := os.Remove(filepath.Join(bin, e.Name())); err != nil {
			return fmt.Errorf("delete old helper: %w", err)
		}
	}
	return nil
}

// step checks a step. With apply, it then records the handlers that the step
// notifies and its then, and makes the changes the check found. When the
// changes fail, it removes the records that it added. After a download, it
// records the checksum of the path.
func step(ctx context.Context, params json.RawMessage, apply bool, login module.State, handlers, thens, downloads records, note func(string)) (protocol.StepResult, error) {
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
	if isDownload {
		sum, err := recorded(downloads, d.Path)
		if err != nil {
			return protocol.StepResult{}, err
		}
		d.Recorded = sum
	}
	res, err := m.Check(ctx, &s.State, note)
	out := protocol.StepResult{Result: res, State: s.State}
	if err != nil || !apply || res.Status == module.OK {
		return out, err
	}
	// The plan has shown the diff already.
	out.Old, out.OldReason = nil, ""
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
	if err := m.Apply(ctx, note); err != nil {
		return out, errors.Join(err, handlers.remove(notified...), thens.remove(thenLines...))
	}
	if isDownload {
		return out, record(downloads, d.SHA256, d.Path)
	}
	return out, nil
}

func readPending(handlers, thens records) (protocol.Pending, error) {
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
			return protocol.Pending{}, fmt.Errorf("read the pending then records: %s:%d: %w", filepath.Join(thens.dir, thens.project), i+1, err)
		}
		p.Then = append(p.Then, t)
	}
	return p, nil
}

func handled(params json.RawMessage, handlers records) error {
	var h protocol.Handled
	if err := json.Unmarshal(params, &h); err != nil {
		return fmt.Errorf("decode handled: %w", err)
	}
	return handlers.remove(h.Name)
}

// command runs the command of a then, and then removes its record.
func command(ctx context.Context, params json.RawMessage, thens records) error {
	var c protocol.Command
	if err := json.Unmarshal(params, &c); err != nil {
		return fmt.Errorf("decode command: %w", err)
	}
	if err := module.Shell(ctx, c.Command); err != nil {
		return err
	}
	line, err := json.Marshal(c.Then)
	if err != nil {
		return err
	}
	return thens.remove(string(line))
}
