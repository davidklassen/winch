// Package progress shows on stderr what each host does now.
package progress

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// shown is the number of hosts with a status line.
	shown = 5
	// slow is the time between two still running lines.
	slow = 30 * time.Second
	// frame is the time of one spinner frame.
	frame = 100 * time.Millisecond
)

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Display shows the busy hosts. On a terminal it keeps one status line per
// busy host at the bottom of w, and writes other output above them. Without
// a terminal, it writes a line every 30 seconds for a slow step.
type Display struct {
	mu       sync.Mutex
	w        io.Writer
	filter   func([]string) []string
	terminal bool
	width    func() int
	now      func() time.Time
	start    time.Time
	busy     []*task
	// drawn is the number of status lines on the screen.
	drawn int
	// held is the number of holds that did not end.
	held int
}

type task struct {
	host, text string
	start      time.Time
	// reported is the number of still running lines of the task.
	reported int
}

// New returns a display that writes to w, stderr. filter masks the secrets
// of each part. width returns the width of the terminal, or 0.
func New(w io.Writer, filter func([]string) []string, terminal bool, width func() int, now func() time.Time) *Display {
	return &Display{w: w, filter: filter, terminal: terminal, width: width, now: now, start: now()}
}

// Busy shows that host does text now, from now on.
func (d *Display) Busy(host, text string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := &task{host: host, text: text, start: d.now()}
	if i := slices.IndexFunc(d.busy, func(t *task) bool { return t.host == host }); i >= 0 {
		d.busy[i] = t
	} else {
		d.busy = append(d.busy, t)
	}
	d.redraw()
}

// Idle removes the status of host.
func (d *Display) Idle(host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.busy = slices.DeleteFunc(d.busy, func(t *task) bool { return t.host == host })
	d.redraw()
}

// Hold removes the status lines and stops the still running lines until the
// returned function runs, so that ssh can ask a question on the terminal.
func (d *Display) Hold() func() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.clear()
	d.held++
	return func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.held--
		d.draw()
	}
}

// Writer returns a writer to w that writes above the status lines.
func (d *Display) Writer(w io.Writer) io.Writer { return writer{d, w} }

type writer struct {
	d *Display
	w io.Writer
}

func (w writer) Write(p []byte) (int, error) {
	w.d.mu.Lock()
	defer w.d.mu.Unlock()
	w.d.clear()
	defer w.d.draw()
	return w.w.Write(p)
}

// Start starts the clock of the display. The returned function stops it and
// removes the status lines.
func (d *Display) Start() func() {
	every := time.Second
	if d.terminal {
		every = frame
	}
	ticker := time.NewTicker(every)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-ticker.C:
				d.tick()
			case <-done:
				return
			}
		}
	})
	return func() {
		ticker.Stop()
		close(done)
		wg.Wait()
		d.mu.Lock()
		defer d.mu.Unlock()
		d.clear()
		d.busy = nil
	}
}

func (d *Display) tick() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.terminal {
		d.redraw()
		return
	}
	if d.held > 0 {
		return
	}
	now := d.now()
	for _, t := range d.busy {
		n := int(now.Sub(t.start) / slow)
		if n <= t.reported {
			continue
		}
		t.reported = n
		line := fmt.Sprintf("%s: %s: still running (%ds)\n", t.host, t.text, n*int(slow/time.Second))
		fmt.Fprint(d.w, d.filter([]string{line})[0])
	}
}

func (d *Display) redraw() {
	d.clear()
	d.draw()
}

// clear removes the status lines. The \r goes back to the start of the line
// after them: the terminal can echo a key there, such as ^C.
func (d *Display) clear() {
	if d.drawn > 0 {
		fmt.Fprintf(d.w, "\r\x1b[%dA\x1b[J", d.drawn)
		d.drawn = 0
	}
}

func (d *Display) draw() {
	if !d.terminal || d.held > 0 || len(d.busy) == 0 {
		return
	}
	now := d.now()
	sp := spinner[int(now.Sub(d.start)/frame)%len(spinner)]
	width := d.width()
	// Without line wrap, a line wider than the terminal, such as one with
	// wide characters, stays one row, and clear removes it.
	var b strings.Builder
	b.WriteString("\x1b[?7l")
	for _, t := range d.busy[:min(len(d.busy), shown)] {
		s := int(now.Sub(t.start) / time.Second)
		suffix := fmt.Sprintf(" (%d:%02d)", s/60, s%60)
		body := []rune(strings.ReplaceAll(d.filter([]string{t.host + ": " + t.text})[0], "\t", " "))
		if limit := width - 1 - len([]rune(sp+" "+suffix)); width > 0 && len(body) > limit {
			body = append(body[:max(limit-1, 0)], '…')
		}
		b.WriteString(sp + " " + string(body) + suffix + "\n")
		d.drawn++
	}
	if n := len(d.busy) - shown; n > 0 {
		host := "hosts"
		if n == 1 {
			host = "host"
		}
		fmt.Fprintf(&b, "and %d more %s\n", n, host)
		d.drawn++
	}
	b.WriteString("\x1b[?7h")
	fmt.Fprint(d.w, b.String())
}
