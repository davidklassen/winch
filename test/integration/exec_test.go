package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: CLI (winch exec); CLI/JSON output; CLI/Exit codes; Modules (the command environment)
func TestExec(t *testing.T) {
	t.Parallel()
	vms := []*vmtest.VM{lab.StartVM(t, "exec-a"), lab.StartVM(t, "exec-b")}
	vms[0].MustRun(t, "echo a > /root/name")
	vms[1].MustRun(t, "echo b > /root/name")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  exec-a: {}\n  exec-b: {}\n",
	})

	t.Run("equal output shares a block", func(t *testing.T) {
		r := lab.Winch(t, dir, "exec", "all", "--", "echo", "same")
		if r.Code != 0 || r.Stdout != "exec-a, exec-b (2 hosts)\n  same\n\n" {
			t.Errorf("exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("other output shows a block per host", func(t *testing.T) {
		r := lab.Winch(t, dir, "exec", "all", "--", "cat /root/name")
		if r.Code != 0 || r.Stdout != "exec-a\n  a\n\nexec-b\n  b\n\n" {
			t.Errorf("exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("a non-zero exit shows its status and exits 1", func(t *testing.T) {
		r := lab.Winch(t, dir, "exec", "all", "--", "grep -q a /root/name || exit 3")
		if r.Code != 1 || r.Stdout != "exec-a\n\nexec-b\n  exit status 3\n\n" {
			t.Errorf("exit %d, stdout %q", r.Code, r.Stdout)
		}
	})

	t.Run("the command runs as every host command runs", func(t *testing.T) {
		r := lab.Winch(t, dir, "exec", "exec-a", "--", `pwd; id -u; echo "$HOME $LC_ALL $PATH"; umask; cat`)
		want := "exec-a\n  /\n  0\n  /root C.UTF-8 /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n  0022\n\n"
		if r.Code != 0 || r.Stdout != want {
			t.Errorf("exit %d, stdout %q, want %q", r.Code, r.Stdout, want)
		}
	})

	t.Run("--json gives one exec event per host", func(t *testing.T) {
		r := lab.Winch(t, dir, "exec", "all", "--json", "--", "cat /root/name; exit 2")
		var types []string
		outputs := map[string]string{}
		for line := range strings.Lines(r.Stdout) {
			var ev struct {
				Type     string `json:"type"`
				Host     string `json:"host"`
				Output   string `json:"output"`
				ExitCode *int   `json:"exit_code"`
			}
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("line %q: %v", line, err)
			}
			types = append(types, ev.Type)
			if ev.Type == "exec" && ev.ExitCode != nil && *ev.ExitCode == 2 {
				outputs[ev.Host] = ev.Output
			}
		}
		if r.Code != 1 || strings.Join(types, " ") != "version exec exec summary" || outputs["exec-a"] != "a\n" || outputs["exec-b"] != "b\n" {
			t.Errorf("exit %d, events %q, outputs %q", r.Code, types, outputs)
		}
	})
}
