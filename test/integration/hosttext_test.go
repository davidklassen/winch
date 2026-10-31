package integration

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: CLI/Output; CLI/JSON output; CLI (winch exec); Modules/file, dir, link (dir purge)
func TestHostNamesNotUTF8(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "hosttext")
	// The names are "caf" with the Latin-1 byte of é, and "x" with the C1
	// byte of CSI, which a terminal in Latin-1 reads as an escape.
	vm.MustRun(t, `mkdir /etc/wn && touch "/etc/wn/$(printf 'caf\351')" "/etc/wn/$(printf 'x\233y')"`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: text\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  hosttext: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: s\n    hosts: all\n    steps:\n      - dir:\n          path: /etc/wn\n          purge: true\n",
	})
	removes := []string{"remove file /etc/wn/caf\uFFFD", "remove file /etc/wn/x\uFFFDy"}

	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 {
		t.Errorf("plan: exit %d, stderr %q", r.Code, r.Stderr)
	}
	for _, want := range removes {
		if !strings.Contains(r.Stdout, want+"\n") {
			t.Errorf("plan: no %q in stdout %q", want, r.Stdout)
		}
	}
	r = lab.Winch(t, dir, "plan", "site", "--json")
	if r.Code != 0 {
		t.Errorf("plan --json: exit %d, stderr %q", r.Code, r.Stderr)
	}
	rawOK(t, "plan --json", r.Stdout)
	got := decoded(t, r.Stdout)
	for _, want := range removes {
		if !strings.Contains(got, want) {
			t.Errorf("plan --json: no %q in %q", want, r.Stdout)
		}
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes", "--json")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	rawOK(t, "apply --json", r.Stdout)
	if out := vm.MustRun(t, "ls -A /etc/wn"); out != "" {
		t.Errorf("/etc/wn after apply: %q", out)
	}
	if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after apply: exit %d, stdout %q", r.Code, r.Stdout)
	}

	vm.MustRun(t, `touch "/etc/wn/$(printf 'caf\351')"`)
	r = lab.Winch(t, dir, "exec", "all", "--", "ls /etc/wn")
	if r.Code != 0 || r.Stdout != "hosttext\n  caf�\n\n" {
		t.Errorf("exec: exit %d, stdout %q", r.Code, r.Stdout)
	}
	r = lab.Winch(t, dir, "exec", "all", "--json", "--", "ls /etc/wn")
	rawOK(t, "exec --json", r.Stdout)
	if got := decoded(t, r.Stdout); r.Code != 0 || !strings.Contains(got, "caf�\n") {
		t.Errorf("exec --json: exit %d, stdout %q", r.Code, r.Stdout)
	}
}

// rawOK fails when out is not valid UTF-8 or holds the C1 byte of CSI.
func rawOK(t *testing.T, what, out string) {
	t.Helper()
	if !utf8.ValidString(out) || strings.Contains(out, "\x9b") {
		t.Errorf("%s: the output has bytes from the host: %q", what, out)
	}
}
