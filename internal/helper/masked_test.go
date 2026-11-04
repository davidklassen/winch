package helper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/yamlx"
)

func (l *lockout) maskedPath(m module.Module) string {
	return maskedRecords{dir: filepath.Join(l.dir, "masked", "acme")}.path(m)
}

func (l *lockout) step(t *testing.T, method string, s protocol.Step) protocol.StepResult {
	t.Helper()
	r := l.c.call(t, method, s)
	if r.Error != "" {
		t.Fatalf("%s: %s", method, r.Error)
	}
	var res protocol.StepResult
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// spec: Variables/Secrets in output (file diffs); Remote execution/State on
// the host
func TestMaskedRecord(t *testing.T) {
	l := startLockout(t)
	const rec = "pw=(secret)\n"
	record := l.maskedPath(&module.File{Path: l.a})
	if got := l.step(t, "check", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n")}); got.Masked != nil {
		t.Errorf("check without a record: masked %q", *got.Masked)
	}
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new(rec)})
	if got := content(t, record); got != rec {
		t.Errorf("record = %q, want %q", got, rec)
	}
	fi, err := os.Stat(record)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %o, want 0600", fi.Mode().Perm())
	}

	got := l.step(t, "check", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=two\n")})
	if got.Masked == nil || *got.Masked != rec {
		t.Errorf("check: masked = %v, want %q", got.Masked, rec)
	}
	if got := l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=two\n"), Masked: new(rec)}); got.Masked != nil {
		t.Errorf("apply result: masked %q", *got.Masked)
	}

	const next = "workers=3\npw=(secret)\n"
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "workers=3\npw=two\n"), Masked: new(next)})
	if got := content(t, record); got != next {
		t.Errorf("record after another mask = %q, want %q", got, next)
	}

	// A step that sets only attributes does not write the content.
	uid, gid := yamlx.NameOrID(strconv.Itoa(os.Getuid())), yamlx.NameOrID(strconv.Itoa(os.Getgid()))
	attrs, _ := json.Marshal(module.File{Path: l.a, Owner: uid, Group: gid, Mode: "0640"})
	l.step(t, "apply", protocol.Step{Module: "file", Args: attrs})
	if got := content(t, record); got != next {
		t.Errorf("record after a step with attributes = %q, want %q", got, next)
	}

	// A failed write keeps the record, so the secret that stays in the file
	// stays masked.
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: failingFileArgs(l.a)}); r.Error == "" {
		t.Fatal("apply with a failing validate: no error")
	}
	if got := content(t, record); got != next {
		t.Errorf("record after a failed write = %q, want %q", got, next)
	}
	// With a secret, the record comes first, so a crash in the write hides
	// the old lines.
	if r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: failingFileArgs(l.a), Masked: new(rec)}); r.Error == "" {
		t.Fatal("apply with a failing validate: no error")
	}
	if got := content(t, record); got != rec {
		t.Errorf("record after a failed write with a secret = %q, want %q", got, rec)
	}

	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "plain\n")})
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Errorf("the record stays after a write without a secret: %v", err)
	}
}

// spec: Variables/Secrets in output (file diffs)
func TestMaskedRecordOfAnOKStep(t *testing.T) {
	l := startLockout(t)
	const rec = "pw=(secret)\n"
	record := l.maskedPath(&module.File{Path: l.a})
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n")})
	if got := l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new(rec)}); got.Status != module.OK {
		t.Fatalf("status %s, want ok", got.Status)
	}
	if got := content(t, record); got != rec {
		t.Errorf("record of an ok step = %q, want %q", got, rec)
	}
	// A plan writes no record.
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	l.step(t, "check", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new(rec)})
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Errorf("a check wrote the record: %v", err)
	}
	// An ok step without a secret leaves the record: it writes nothing.
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new(rec)})
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n")})
	if got := content(t, record); got != rec {
		t.Errorf("record after an ok step without a secret = %q, want %q", got, rec)
	}
}

// spec: Variables/Secrets in output (file diffs)
func TestMaskedRecordOfAStepThatSetsAttributes(t *testing.T) {
	l := startLockout(t)
	const rec = "pw=(secret)\n"
	record := l.maskedPath(&module.File{Path: l.a})
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n")})
	uid, gid := yamlx.NameOrID(strconv.Itoa(os.Getuid())), yamlx.NameOrID(strconv.Itoa(os.Getgid()))
	args, _ := json.Marshal(module.File{Path: l.a, Data: []byte("pw=one\n"), Owner: uid, Group: gid, Mode: "0640"})
	if got := l.step(t, "apply", protocol.Step{Module: "file", Args: args, Masked: new(rec)}); got.Status != module.Change {
		t.Fatalf("status %s, want change", got.Status)
	}
	if got := content(t, record); got != rec {
		t.Errorf("record = %q, want %q", got, rec)
	}
}

// spec: Remote execution/State on the host (a failed removal of the record
// keeps the records of the step)
func TestFailedRemovalOfTheRecordKeepsTheHandler(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove the record from a read-only directory")
	}
	l := startLockout(t)
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new("pw=(secret)\n")})
	dir := filepath.Dir(l.maskedPath(&module.File{Path: l.a}))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "plain\n"), Notify: []string{"ssh.reload"}})
	if r.Error == "" {
		t.Fatal("apply: no error from the removal of the record")
	}
	if got := content(t, l.a); got != "plain\n" {
		t.Errorf("file = %q, want the new content", got)
	}
	if p := pendingAll(t, l.c); !slices.Equal(p.Handlers, []string{"ssh.reload"}) {
		t.Errorf("pending handlers %v, want ssh.reload", p.Handlers)
	}
}

// spec: Running a pipeline/Lockout protection (a guarded step that fails puts
// back the old files)
func TestFailedRecordStopsTheTimer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write the record into a read-only directory")
	}
	l := startLockout(t)
	dir := filepath.Dir(l.maskedPath(&module.File{Path: l.a}))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	g := protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}
	r := l.c.call(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Guard: g, Masked: new("pw=(secret)\n")})
	if !strings.Contains(r.Error, "the old files are back") {
		t.Errorf("apply: error %q, want the rollback", r.Error)
	}
	if _, err := os.Lstat(l.job()); !os.IsNotExist(err) {
		t.Errorf("the timer job stays after the failed record: %v", err)
	}
	if got := content(t, l.a); got != "old\n" {
		t.Errorf("file = %q, want old", got)
	}
}

// spec: Variables/Secrets in output (file diffs)
func TestMaskedRecordOverABinaryFile(t *testing.T) {
	l := startLockout(t)
	record := l.maskedPath(&module.File{Path: l.a})
	write(t, l.a, "a\x00b")
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new("pw=(secret)\n")})
	write(t, l.a, "a\x00b")
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "plain\n")})
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Errorf("the record stays after a write without a secret over a binary file: %v", err)
	}
}

// spec: Variables/Secrets in output (file diffs)
func TestMaskedRecordOfARemovedFile(t *testing.T) {
	l := startLockout(t)
	record := l.maskedPath(&module.File{Path: l.a})
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new("pw=(secret)\n")})
	args, _ := json.Marshal(module.File{Path: l.a, Absent: true})
	l.step(t, "apply", protocol.Step{Module: "file", Args: args})
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Errorf("the record stays after the file is gone: %v", err)
	}
}

// spec: Variables/Secrets in output (file diffs)
func TestMaskedRecordOfALineStep(t *testing.T) {
	l := startLockout(t)
	write(t, l.a, "pw old\nkey old\nworkers 2\n")
	record := l.maskedPath(&module.File{Path: l.a})
	line := func(text, match string, absent bool) json.RawMessage {
		data, _ := json.Marshal(&module.Line{Path: l.a, Line: text, Match: match, Absent: absent})
		return data
	}
	l.step(t, "apply", protocol.Step{Module: "line", Args: line("pw one", "^pw ", false), Masked: new("pw (secret)\n")})
	l.step(t, "apply", protocol.Step{Module: "line", Args: line("key one", "^key ", false), Masked: new("key (secret)\n")})
	const both = "pw (secret)\nkey (secret)\n"
	if got := content(t, record); got != both {
		t.Fatalf("record of two line steps = %q, want %q", got, both)
	}
	// An ok line step adds its line to the record of the file.
	if err := os.WriteFile(record, []byte("pw (secret)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l.step(t, "apply", protocol.Step{Module: "line", Args: line("key one", "^key ", false), Masked: new("key (secret)\n")})
	if got := content(t, record); got != both {
		t.Fatalf("record after an ok line step = %q, want %q", got, both)
	}

	// A plain line step reads the record, and leaves the lines of the others.
	got := l.step(t, "check", protocol.Step{Module: "line", Args: line("workers 3", "^workers ", false)})
	if got.Masked == nil || *got.Masked != both {
		t.Errorf("check of a plain line step: masked = %v, want %q", got.Masked, both)
	}
	l.step(t, "apply", protocol.Step{Module: "line", Args: line("workers 3", "^workers ", false)})
	if got := content(t, record); got != both {
		t.Errorf("record after a plain line step = %q, want %q", got, both)
	}

	// A rotation adds nothing, and a new mask adds its line.
	l.step(t, "apply", protocol.Step{Module: "line", Args: line("pw two", "^pw ", false), Masked: new("pw (secret)\n")})
	if got := content(t, record); got != both {
		t.Errorf("record after a rotation = %q, want %q", got, both)
	}
	l.step(t, "apply", protocol.Step{Module: "line", Args: line("pw: two", "^pw", false), Masked: new("pw: (secret)\n")})
	want := both + "pw: (secret)\n"
	if got := content(t, record); got != want {
		t.Errorf("record after a new mask = %q, want %q", got, want)
	}

	// A plain or absent line step takes no line out: an old line can fit the
	// line of another step.
	l.step(t, "apply", protocol.Step{Module: "line", Args: line("", "^pw", true)})
	l.step(t, "apply", protocol.Step{Module: "line", Args: line("key open", "^key ", false)})
	if got := content(t, record); got != want {
		t.Errorf("record after plain line steps = %q, want %q", got, want)
	}
}

// spec: Variables/Secrets in output (file diffs)
func TestPlainLineStepKeepsTheRecordOfASecretLine(t *testing.T) {
	l := startLockout(t)
	write(t, l.a, "tok-old\nworkers 2\n")
	record := l.maskedPath(&module.File{Path: l.a})
	token, _ := json.Marshal(&module.Line{Path: l.a, Line: "tok-new", Match: "^tok-"})
	l.step(t, "apply", protocol.Step{Module: "line", Args: token, Masked: new("(secret)\n")})
	workers, _ := json.Marshal(&module.Line{Path: l.a, Line: "workers 3", Match: "^workers "})
	l.step(t, "apply", protocol.Step{Module: "line", Args: workers})
	if got := content(t, record); got != "(secret)\n" {
		t.Errorf("record = %q, want the line of the secret", got)
	}
}

// spec: Variables/Secrets in output (file diffs): a file has one record,
// whichever step writes it
func TestMaskedRecordOfAFile(t *testing.T) {
	l := startLockout(t)
	write(t, l.a, "pw old\n")
	u := &module.Unit{Name: "a.service"}
	if l.maskedPath(u) != l.maskedPath(&module.File{Path: u.Path()}) || l.maskedPath(&module.Line{Path: u.Path(), Match: "x"}) != l.maskedPath(u) {
		t.Error("the steps of one file have different records")
	}
	if got := l.maskedPath(&module.Dir{Path: l.a}); got != "" {
		t.Errorf("a dir step has the record %q", got)
	}
	record := l.maskedPath(&module.File{Path: l.a})
	lineArgs, _ := json.Marshal(&module.Line{Path: l.a, Line: "pw one", Match: "^pw "})
	l.step(t, "apply", protocol.Step{Module: "line", Args: lineArgs, Masked: new("pw (secret)\n")})
	// A plain file step sees the record of the line step, and removes it.
	got := l.step(t, "check", protocol.Step{Module: "file", Args: fileArgs(l.a, "plain\n")})
	if got.Masked == nil || *got.Masked != "pw (secret)\n" {
		t.Errorf("check of a file step: masked = %v", got.Masked)
	}
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "plain\n")})
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Errorf("the record stays after a plain file step: %v", err)
	}
	// A plain line step sees the record of a file step.
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw one\nworkers 2\n"), Masked: new("pw (secret)\nworkers 2\n")})
	plain, _ := json.Marshal(&module.Line{Path: l.a, Line: "pw open", Match: "^pw "})
	got = l.step(t, "check", protocol.Step{Module: "line", Args: plain})
	if got.Masked == nil || *got.Masked != "pw (secret)\nworkers 2\n" {
		t.Errorf("check of a line step: masked = %v", got.Masked)
	}
}

// spec: Variables/Secrets in output (file diffs); Running a pipeline/Lockout
// protection
func TestRollbackPutsBackTheMaskedRecord(t *testing.T) {
	l := startLockout(t)
	const rec = "pw=(secret)\n"
	record := l.maskedPath(&module.File{Path: l.a})
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new(rec)})
	g := protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "plain\n"), Guard: g})
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Fatalf("the record stays after a write without a secret: %v", err)
	}
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Fatalf("rollback: %s", r.Error)
	}
	if got := content(t, l.a); got != "pw=one\n" {
		t.Errorf("after the rollback: file %q", got)
	}
	if got := content(t, record); got != rec {
		t.Errorf("after the rollback: record %q, want %q", got, rec)
	}
}

// spec: Variables/Secrets in output (file diffs); Running a pipeline/Lockout
// protection
func TestRollbackOfARotationPutsBackTheMaskedRecord(t *testing.T) {
	l := startLockout(t)
	const rec = "pw=(secret)\n"
	record := l.maskedPath(&module.File{Path: l.a})
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new(rec)})
	g := protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "workers=2\npw=two\n"), Guard: g, Masked: new("workers=2\npw=(secret)\n")})
	if r := l.c.call(t, "rollback", nil); r.Error != "" {
		t.Fatalf("rollback: %s", r.Error)
	}
	if got := content(t, record); got != rec {
		t.Errorf("after the rollback: record %q, want %q", got, rec)
	}
}

// spec: Variables/Secrets in output (file diffs); Running a pipeline/Lockout
// protection (untested sshd files)
func TestPutBackUntestedPutsBackTheMaskedRecord(t *testing.T) {
	l := startLockout(t)
	const rec = "pw=(secret)\n"
	record := l.maskedPath(&module.File{Path: l.a})
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new(rec)})
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "plain\n"), Guard: protocol.Guard{SSHD: []string{"ssh"}}})
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Fatalf("the record stays after a write without a secret: %v", err)
	}
	l.end(t)
	if got := content(t, l.a); got != "pw=one\n" {
		t.Errorf("after the session: file %q", got)
	}
	if got := content(t, record); got != rec {
		t.Errorf("after the session: record %q, want %q", got, rec)
	}
}

// spec: Running a pipeline/Lockout protection (the plan of a due rollback)
func TestDueRollbackDoesNotListTheMaskedRecord(t *testing.T) {
	l := startLockout(t)
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "pw=one\n"), Masked: new("pw=(secret)\n")})
	g := protocol.Guard{Recipe: "ssh", Save: true, Confirm: true}
	l.step(t, "apply", protocol.Step{Module: "file", Args: fileArgs(l.a, "plain\n"), Guard: g})
	for _, project := range []string{"acme", "other"} {
		rb := &rollbacks{dir: filepath.Join(l.dir, "rollback"), project: project, masked: maskedRecords{dir: filepath.Join(l.dir, "masked", project)}, due: []string{l.job()}}
		got, err := rb.dueChanges(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"put back " + l.a}; !slices.Equal(got, want) {
			t.Errorf("due changes in project %s: %q, want %q", project, got, want)
		}
	}
	if r := l.c.call(t, "confirm", nil); r.Error != "" {
		t.Fatal(r.Error)
	}
}
