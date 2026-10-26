package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/secret"
)

// spec: CLI/Output
func TestUseColor(t *testing.T) {
	tests := []struct {
		name     string
		terminal bool
		env      map[string]string
		want     bool
	}{
		{"terminal", true, map[string]string{"TERM": "xterm-256color"}, true},
		{"terminal without TERM", true, nil, true},
		{"no terminal", false, map[string]string{"TERM": "xterm"}, false},
		{"NO_COLOR", true, map[string]string{"TERM": "xterm", "NO_COLOR": "1"}, false},
		{"NO_COLOR empty", true, map[string]string{"TERM": "xterm", "NO_COLOR": ""}, true},
		{"TERM=dumb", true, map[string]string{"TERM": "dumb"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(k string) string { return tt.env[k] }
			if got := UseColor(tt.terminal, getenv); got != tt.want {
				t.Errorf("UseColor = %v, want %v", got, tt.want)
			}
		})
	}
}

// spec: CLI/Output
func TestColorStreams(t *testing.T) {
	dir := writeProject(t, motd)
	run := func(colorOut, colorErr bool, args ...string) (string, string) {
		h := fakehost.New()
		h.FailCheck("web1")
		var out, errOut bytes.Buffer
		Main(context.Background(), args, Env{
			Dir: dir, In: strings.NewReader(""), Out: &out, Err: &errOut,
			ColorOut: colorOut, ColorErr: colorErr,
			Connect: h.ConnectorFor, Filter: secret.NewFilter(), Now: fixedNow,
		})
		return out.String(), errOut.String()
	}
	const esc = "\x1b["
	out, errOut := run(true, false, "plan", "site")
	if !strings.Contains(out, "\x1b[32m+\x1b[0m file /etc/motd") || strings.Contains(errOut, esc) {
		t.Errorf("color on stdout only: stdout %q, stderr %q", out, errOut)
	}
	out, errOut = run(false, true, "plan", "site")
	if strings.Contains(out, esc) || !strings.Contains(errOut, "\x1b[31mweb1: base: file /etc/motd: permission denied\x1b[0m\n") {
		t.Errorf("color on stderr only: stdout %q, stderr %q", out, errOut)
	}
	out, _ = run(true, true, "plan", "site", "--json")
	if strings.Contains(out, esc) || !strings.Contains(out, `"type":"planned"`) {
		t.Errorf("JSON output has color, or no planned event: %q", out)
	}
	_, errOut = run(true, true, "plan", "nope")
	if !strings.HasPrefix(errOut, esc+"31m") {
		t.Errorf("a load error is not red: %q", errOut)
	}
	_, errOut = run(true, true, "plan", "site", "--nope")
	if !strings.HasPrefix(errOut, "\x1b[31mwinch plan: flag provided but not defined: -nope\x1b[0m\nRun ") {
		t.Errorf("a flag error is not red: %q", errOut)
	}
}
