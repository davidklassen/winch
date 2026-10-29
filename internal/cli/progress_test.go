package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/progress"
	"github.com/davidklassen/winch/internal/secret"
)

// spec: CLI/Output (progress)
func TestProgressOnStderr(t *testing.T) {
	h := fakehost.New()
	filter := secret.NewFilter()
	var out, errOut strings.Builder
	d := progress.New(&errOut, filter.Parts, true, func() int { return 80 }, fixedNow)
	code := Main(context.Background(), []string{"apply", "site", "--yes"}, Env{
		Dir: writeProject(t, motd), In: strings.NewReader(""), Out: d.Writer(&out), Err: d.Writer(&errOut),
		Connect: h.ConnectorFor, Progress: d, Filter: filter,
	})
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	if strings.Contains(out.String(), "⠋") || strings.Contains(out.String(), "\x1b") {
		t.Errorf("status text on stdout: %q", out.String())
	}
	for _, s := range []string{"⠋ web1: connecting (0:00)\n", "⠋ web2: base: file /etc/motd (0:00)\n"} {
		if !strings.Contains(errOut.String(), s) {
			t.Errorf("no %q on stderr: %q", s, errOut.String())
		}
	}
	if !strings.HasSuffix(errOut.String(), "\x1b[J") {
		t.Errorf("status lines stay at the end: %q", errOut.String())
	}
}

// spec: CLI/Output (progress)
func TestStatusLines(t *testing.T) {
	tests := []struct {
		name           string
		stdout, stderr bool
		term           string
		want           bool
	}{
		{"both terminals", true, true, "xterm", true},
		{"stdout to a pipe", false, true, "xterm", false},
		{"stderr to a file", true, false, "xterm", false},
		{"TERM=dumb", true, true, "dumb", false},
	}
	for _, tt := range tests {
		getenv := func(k string) string { return map[string]string{"TERM": tt.term}[k] }
		if got := StatusLines(tt.stdout, tt.stderr, getenv); got != tt.want {
			t.Errorf("%s: StatusLines = %v, want %v", tt.name, got, tt.want)
		}
	}
}
