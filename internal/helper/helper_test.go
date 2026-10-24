package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
)

type client struct {
	w    *io.PipeWriter
	r    *bufio.Scanner
	done chan error
	id   int
}

func start(t *testing.T, dir, self string) *client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &client{w: inW, r: bufio.NewScanner(outR), done: make(chan error, 1)}
	go func() {
		err := Serve(context.Background(), inR, outW, dir, self)
		outW.Close()
		c.done <- err
	}()
	t.Cleanup(func() { inW.Close() })
	return c
}

func (c *client) call(t *testing.T, method string, params any) protocol.Response {
	t.Helper()
	c.id++
	p, _ := json.Marshal(params)
	req, _ := json.Marshal(protocol.Request{ID: c.id, Method: method, Params: p})
	go c.w.Write(append(req, '\n')) //nolint:errcheck // a failed write shows as a missing response
	if !c.r.Scan() {
		t.Fatalf("no response: %v", c.r.Err())
	}
	var resp protocol.Response
	if err := json.Unmarshal(c.r.Bytes(), &resp); err != nil {
		t.Fatalf("bad response %q: %v", c.r.Bytes(), err)
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

// spec: Remote execution/Helper
func TestHelloDeletesOtherVersions(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"old1", "old2", "self"} {
		if err := os.WriteFile(filepath.Join(bin, name), nil, 0o755); err != nil {
			t.Fatal(err)
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
	if !slices.Equal(names, []string{"self"}) {
		t.Errorf("bin holds %v, want [self]", names)
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
