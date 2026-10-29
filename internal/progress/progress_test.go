package progress

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/secret"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newDisplay(terminal bool) (*Display, *bytes.Buffer, *clock) {
	d, b, c, _ := newDisplayFilter(terminal)
	return d, b, c
}

func newDisplayFilter(terminal bool) (*Display, *bytes.Buffer, *clock, *secret.Filter) {
	f := secret.NewFilter()
	f.Add("hunter2")
	var b bytes.Buffer
	c := &clock{time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	return New(&b, f.Parts, terminal, func() int { return 60 }, c.now), &b, c, f
}

const clear1 = "\r\x1b[1A\x1b[J"

// lines are status lines as the display draws them: without line wrap, so
// that a line wider than the terminal stays one row.
func lines(s ...string) string {
	return "\x1b[?7l" + strings.Join(s, "") + "\x1b[?7h"
}

// spec: CLI/Output (progress in a terminal)
func TestTerminalOneHost(t *testing.T) {
	d, b, c := newDisplay(true)
	out := d.Writer(b)
	d.Busy("demo", "caddy: Install: pkg")
	c.add(23400 * time.Millisecond)
	d.tick()
	fmt.Fprint(out, "demo: caddy: + Install: pkg\n")
	d.Idle("demo")
	want := lines("⠋ demo: caddy: Install: pkg (0:00)\n") +
		clear1 + lines("⠼ demo: caddy: Install: pkg (0:23)\n") +
		clear1 + "demo: caddy: + Install: pkg\n" + lines("⠼ demo: caddy: Install: pkg (0:23)\n") +
		clear1
	if b.String() != want {
		t.Errorf("terminal:\n%q\nwant\n%q", b.String(), want)
	}
}

// spec: CLI/Output (progress in a terminal)
func TestTerminalSixHosts(t *testing.T) {
	d, b, c := newDisplay(true)
	for i := range 6 {
		d.Busy(fmt.Sprintf("web%d", i+1), "nginx: file /etc/motd")
	}
	b.Reset()
	c.add(65 * time.Second)
	d.tick()
	var status []string
	for i := range 5 {
		status = append(status, fmt.Sprintf("⠋ web%d: nginx: file /etc/motd (1:05)\n", i+1))
	}
	want := "\r\x1b[6A\x1b[J" + lines(append(status, "and 1 more host\n")...)
	if b.String() != want {
		t.Errorf("terminal:\n%q\nwant\n%q", b.String(), want)
	}
	b.Reset()
	d.Busy("web7", "nginx: file /etc/motd")
	if !strings.HasSuffix(b.String(), lines("and 2 more hosts\n")[len(lines()):]) {
		t.Errorf("seven hosts: %q", b.String())
	}
	for i := range 7 {
		d.Idle(fmt.Sprintf("web%d", i+1))
	}
	if !strings.HasSuffix(b.String(), clear1) {
		t.Errorf("status lines stay after the last host: %q", b.String())
	}
}

// spec: CLI/Output (progress in a terminal)
func TestTerminalStop(t *testing.T) {
	d, b, _ := newDisplay(true)
	stop := d.Start()
	d.Busy("demo", "caddy: Install: pkg")
	stop()
	if !strings.HasSuffix(b.String(), clear1) {
		t.Errorf("status lines stay after the end: %q", b.String())
	}
}

// spec: CLI/Output (progress in a terminal)
func TestTerminalHold(t *testing.T) {
	d, b, _ := newDisplay(true)
	d.Busy("web1", "nginx: file /etc/motd")
	resume := d.Hold()
	resume2 := d.Hold()
	d.Busy("web2", "nginx: file /etc/motd")
	d.tick()
	resume()
	want := lines("⠋ web1: nginx: file /etc/motd (0:00)\n") + clear1
	if b.String() != want {
		t.Errorf("held:\n%q\nwant\n%q", b.String(), want)
	}
	resume2()
	want += lines("⠋ web1: nginx: file /etc/motd (0:00)\n", "⠋ web2: nginx: file /etc/motd (0:00)\n")
	if b.String() != want {
		t.Errorf("resumed:\n%q\nwant\n%q", b.String(), want)
	}
}

// spec: CLI/Output (progress in a terminal)
func TestTerminalWidth(t *testing.T) {
	d, b, _ := newDisplay(true)
	d.Busy("demo", "a\tb"+strings.Repeat("x", 100))
	want := lines("⠋ demo: a b" + strings.Repeat("x", 40) + "… (0:00)\n")
	if b.String() != want {
		t.Errorf("long line:\n%q\nwant\n%q", b.String(), want)
	}
}

// spec: CLI/Output (progress without a terminal)
func TestStillRunning(t *testing.T) {
	d, b, c := newDisplay(false)
	out := d.Writer(b)
	d.Busy("demo", "caddy: Install: pkg")
	c.add(29 * time.Second)
	d.tick()
	fmt.Fprint(out, "a line\n")
	c.add(time.Second)
	d.tick()
	d.tick()
	c.add(30 * time.Second)
	d.tick()
	d.Busy("demo", "caddy: then")
	c.add(20 * time.Second)
	d.Busy("demo", "caddy: then")
	c.add(20 * time.Second)
	d.tick()
	fmt.Fprint(out, "after 20s\n")
	c.add(10 * time.Second)
	d.tick()
	resume := d.Hold()
	c.add(30 * time.Second)
	d.tick()
	resume()
	d.Idle("demo")
	c.add(30 * time.Second)
	d.tick()
	want := "a line\n" +
		"demo: caddy: Install: pkg: still running (30s)\n" +
		"demo: caddy: Install: pkg: still running (60s)\n" +
		"after 20s\n" +
		"demo: caddy: then: still running (30s)\n"
	if b.String() != want {
		t.Errorf("without a terminal:\n%q\nwant\n%q", b.String(), want)
	}
}

// spec: CLI/Output (progress text passes the filter for secrets)
func TestSecret(t *testing.T) {
	for _, terminal := range []bool{true, false} {
		d, b, c := newDisplay(terminal)
		d.Busy("demo", "app: file /etc/hunter2")
		c.add(30 * time.Second)
		d.tick()
		if strings.Contains(b.String(), "hunter2") || !strings.Contains(b.String(), "demo: app: file /etc/(secret)") {
			t.Errorf("terminal %v: %q", terminal, b.String())
		}
	}
}

// spec: CLI/Output (progress text passes the filter for secrets)
func TestSecretLearnedLater(t *testing.T) {
	for _, terminal := range []bool{true, false} {
		d, b, c, f := newDisplayFilter(terminal)
		d.Busy("demo", "app: file /etc/swordfish")
		f.Add("swordfish")
		b.Reset()
		c.add(30 * time.Second)
		d.tick()
		if strings.Contains(b.String(), "swordfish") || !strings.Contains(b.String(), "demo: app: file /etc/(secret)") {
			t.Errorf("terminal %v: %q", terminal, b.String())
		}
	}
}
