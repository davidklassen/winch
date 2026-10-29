package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: CLI/Output (progress without a terminal)
func TestProgressStillRunning(t *testing.T) {
	t.Parallel()
	lab.StartVM(t, "progress")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: progress\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  progress: {}\n",
		"pipelines/site.yaml": `stages:
  - name: s
    hosts: all
    steps:
      - cmd:
          command: sleep 65
`,
	})
	r := lab.Winch(t, dir, "apply", "site", "--yes")
	want := "progress: s: cmd sleep 65: still running (30s)\nprogress: s: cmd sleep 65: still running (60s)\n"
	if r.Code != 0 || !strings.Contains(r.Stderr, want) || strings.Count(r.Stderr, "cmd sleep 65: still running") != 2 {
		t.Errorf("apply: exit %d, stderr %q; want two still running lines", r.Code, r.Stderr)
	}
	if strings.Contains(r.Stdout, "still running") {
		t.Errorf("progress on stdout: %q", r.Stdout)
	}
}
