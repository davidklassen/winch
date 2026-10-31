package cli

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/yamlx"
)

// output writes the results of a project command: text, or JSON events
// with --json.
type output struct {
	env Env
	// ev is nil without --json.
	ev *run.Events
	mu sync.Mutex
	// noted holds the notes that the run showed.
	noted map[run.Note]bool
}

// newOutput writes the version event with --json.
func newOutput(env Env, f *flags) *output {
	o := &output{env: env, noted: map[run.Note]bool{}}
	if f.json {
		now := env.Now
		if now == nil {
			now = time.Now
		}
		o.ev = run.NewEvents(env.stdout, now)
		o.ev.Write("version", struct {
			Version int `json:"version"`
		}{1})
	}
	return o
}

type diagnostic struct {
	Severity string `json:"severity"`
	Host     string `json:"host,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Col      int    `json:"col,omitempty"`
	Message  string `json:"message"`
	Expr     string `json:"expr,omitempty"`
	ExprCol  int    `json:"expr_col,omitempty"`
}

// fail reports an error: on stderr, or as diagnostic events.
func (o *output) fail(err error) {
	if o.ev == nil {
		o.env.fail(err)
		return
	}
	for _, e := range leaves(err) {
		o.ev.Write("diagnostic", newDiagnostic("error", e))
	}
}

// leaves returns the errors that err joins, or err.
func leaves(err error) []error {
	j, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return []error{err}
	}
	var out []error
	for _, e := range j.Unwrap() {
		out = append(out, leaves(e)...)
	}
	return out
}

func newDiagnostic(severity string, err error) diagnostic {
	d := diagnostic{Severity: severity, Message: err.Error()}
	// An error of a command-line argument has no line; its message keeps the
	// argument.
	if e, ok := err.(*yamlx.Error); ok && !commandLine(e) {
		d.File, d.Line, d.Col, d.Message = e.Pos.File, e.Pos.Line, e.Pos.Col, e.Msg
	}
	d.File, d.Message = secret.Printable(d.File), secret.PrintableLines(d.Message)
	// An !expr error ends with the expression and a line with a caret under
	// the error.
	if msg, snippet, ok := strings.Cut(d.Message, "\n | "); ok {
		expr, caret, _ := strings.Cut(snippet, "\n | ")
		d.Message, d.Expr, d.ExprCol = msg, expr, strings.Index(caret, "^")+1
	}
	return d
}

func (o *output) warn(warnings []*yamlx.Error) {
	for _, w := range warnings {
		if o.ev == nil {
			line := fmt.Sprintf("%s: warning: %s\n", w.Pos, w.Msg)
			if commandLine(w) {
				line = "winch " + o.env.name + ": " + line
			}
			fmt.Fprint(o.env.stderr, secret.PrintableLines(line))
			continue
		}
		o.ev.Write("diagnostic", newDiagnostic("warning", w))
	}
}

// plan writes the plan: the text, or the planned and host events.
func (o *output) plan(pl *run.Plan) {
	o.warn(pl.Warnings)
	if o.ev == nil {
		pl.Write(o.env.stdout, o.env.stderr)
		return
	}
	for _, n := range pl.Notes() {
		o.note(n.Host, n.Text)
	}
	pl.WriteJSON(o.ev)
}

// note shows a note about host once per run: on stderr, or as a diagnostic
// event.
func (o *output) note(host, text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := run.Note{Host: host, Text: text}
	if o.noted[n] {
		return
	}
	o.noted[n] = true
	if o.ev == nil {
		run.WriteNote(o.env.stderr, host, text)
		return
	}
	o.ev.Write("diagnostic", diagnostic{Severity: "note", Host: host, Message: secret.Printable(text)})
}

type summary struct {
	plan  *run.Plan
	apply *run.Outcome
	// command applies the plan when a confirmation is needed.
	command string
}

type planCounts struct {
	Hosts     int `json:"hosts"`
	Change    int `json:"change"`
	Unchanged int `json:"unchanged"`
	Unknown   int `json:"unknown"`
	Failed    int `json:"failed"`
}

type applyCounts struct {
	Hosts     int `json:"hosts"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
	Failed    int `json:"failed"`
}

// end writes the summary event with --json, and returns code.
func (o *output) end(code int, s summary) int {
	if o.ev == nil {
		return code
	}
	ev := struct {
		Plan     *planCounts  `json:"plan,omitempty"`
		Apply    *applyCounts `json:"apply,omitempty"`
		Hash     string       `json:"hash,omitempty"`
		Command  string       `json:"command,omitempty"`
		ExitCode int          `json:"exit_code"`
	}{Command: s.command, ExitCode: code}
	if s.plan != nil {
		change, unchanged, unknown, failed := s.plan.Counts()
		ev.Plan = &planCounts{Hosts: len(s.plan.Hosts), Change: change, Unchanged: unchanged, Unknown: unknown, Failed: failed}
		ev.Hash = s.plan.Hash()
	}
	if a := s.apply; a != nil {
		ev.Apply = &applyCounts{Hosts: a.Hosts, Changed: len(a.Changed), Unchanged: a.Unchanged(), Failed: len(a.Failed)}
	}
	o.ev.Write("summary", ev)
	return code
}
