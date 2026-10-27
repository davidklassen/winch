package color

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/secret"
)

func mask() func([]string) []string {
	f := secret.NewFilter()
	f.Add("hunter2")
	return f.Parts
}

// spec: CLI/Output
func TestPrint(t *testing.T) {
	text := Text{
		{Plain, "  "},
		{Yellow, "~"},
		{Plain, " file /etc/motd\n      "},
		{Green, "+a\n\nb\n"},
		{Bold, "web"},
		{Plain, "\n"},
	}
	tests := []struct {
		name string
		on   bool
		want string
	}{
		{"color on", true,
			"  \x1b[33m~\x1b[0m file /etc/motd\n      \x1b[32m+a\x1b[0m\n\n\x1b[32mb\x1b[0m\n\x1b[1mweb\x1b[0m\n"},
		{"color off", false,
			"  ~ file /etc/motd\n      +a\n\nb\nweb\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			Fprint(NewWriter(&b, mask(), tt.on), text)
			if b.String() != tt.want {
				t.Errorf("Fprint = %q, want %q", b.String(), tt.want)
			}
		})
	}
}

// spec: CLI/Output (the text filter runs before winch adds color)
func TestFilterBeforeColor(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b, mask(), true)
	Fprint(w, Text{{Red, "-pass hun"}, {Green, "ter2\n"}, {Plain, "x hunter2\n"}})
	want := "\x1b[31m-pass (secret)\x1b[0m\nx (secret)\n"
	if b.String() != want {
		t.Errorf("Fprint = %q, want %q", b.String(), want)
	}
	b.Reset()
	if n, err := w.Write([]byte("echo hunter2\n")); n != 13 || err != nil {
		t.Errorf("Write = %d, %v; want the length of the input", n, err)
	}
	if b.String() != "echo (secret)\n" {
		t.Errorf("Write wrote %q", b.String())
	}
}

// spec: Variables/Secrets in output (text filter)
func TestWriterFilters(t *testing.T) {
	f := secret.NewFilter()
	var b bytes.Buffer
	w := NewWriter(&b, f.Parts, false)
	f.Add("hunter2")
	fmt.Fprintf(w, "web1: failed: %s\n", "echo hunter2")
	fmt.Fprint(w, "-----BEGIN PRIVATE KEY-----\nMIIE")
	fmt.Fprint(w, "after the write\n")
	want := "web1: failed: echo (secret)\n(secret)\n(secret)after the write\n"
	if b.String() != want {
		t.Errorf("written %q, want %q", b.String(), want)
	}
}

// spec: CLI/Output (the text filter runs before winch adds color)
func TestKeyBlockColor(t *testing.T) {
	key, err := os.ReadFile(filepath.Join("..", "secret", "testdata", "fake_secrets", "rsa.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var text Text
	for line := range strings.Lines(string(key)) {
		text.Add(Plain, "    ")
		text.Add(Green, "+"+strings.TrimSuffix(line, "\n"))
		text.Add(Plain, "\n")
	}
	var b bytes.Buffer
	Fprint(NewWriter(&b, secret.NewFilter().Parts, true), text)
	want := "    \x1b[32m+(secret)\x1b[0m\n    \x1b[32m(secret)\x1b[0m\n    \x1b[32m(secret)\x1b[0m\n"
	if b.String() != want {
		t.Errorf("Fprint = %q, want %q", b.String(), want)
	}
}
