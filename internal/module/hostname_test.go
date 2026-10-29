package module

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// spec: Modules/hostname and timezone
func TestHostnameValidate(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
	}{
		{"mail", ""},
		{"mail-1", ""},
		{"1", ""},
		{strings.Repeat("a", 63), ""},
		{strings.Repeat("a", 64), "is not a short host name"},
		{"", "is not a short host name"},
		{"Mail", "is not a short host name"},
		{"mail_1", "is not a short host name"},
		{"-mail", "is not a short host name"},
		{"mail-", "is not a short host name"},
		{"mail.example.com", "use !expr host.short"},
	}
	for _, tt := range tests {
		err := (&Hostname{Name: tt.name}).Validate()
		if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
			t.Errorf("Validate(%q) = %v, want %q", tt.name, err, tt.wantErr)
		}
	}
}

// spec: Modules/hostname and timezone
func TestStaticHostname(t *testing.T) {
	tests := []struct {
		data, want string
	}{
		{"mail\n", "mail"},
		{"mail", "mail"},
		{"  mail  \n", "mail"},
		{"# Hetzner Online GmbH\nmail\n", "mail"},
		{"\n#a\n  # b\n\nmail\nother\n", "mail"},
		{"# only a comment\n", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := staticHostname([]byte(tt.data)); got != tt.want {
			t.Errorf("staticHostname(%q) = %q, want %q", tt.data, got, tt.want)
		}
	}
}

// spec: Modules/hostname and timezone
func TestTimezoneValidate(t *testing.T) {
	for _, ok := range []string{"UTC", "Etc/UTC", "Europe/Berlin", "America/Argentina/Buenos_Aires", "Etc/GMT+5", "Etc/GMT-14"} {
		if err := (&Timezone{Name: ok}).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/Etc/UTC", "Etc/UTC/", "Etc//UTC", "../etc/passwd", "Etc/../UTC", "Europe/Ber lin", "Etc/UTC\n"} {
		if err := (&Timezone{Name: bad}).Validate(); err == nil || !strings.Contains(err.Error(), "is not a time zone name") {
			t.Errorf("Validate(%q) = %v", bad, err)
		}
	}
}

// spec: Modules/hostname and timezone
func TestCurrentZone(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name, target string
		want         string
	}{
		{"absolute", "/usr/share/zoneinfo/Etc/UTC", "Etc/UTC"},
		{"relative", "../usr/share/zoneinfo/Europe/Berlin", "Europe/Berlin"},
		{"short", "/usr/share/zoneinfo/UTC", "UTC"},
		{"elsewhere", "/opt/zone", ""},
	}
	for _, tt := range tests {
		p := filepath.Join(dir, tt.name)
		if err := os.Symlink(tt.target, p); err != nil {
			t.Fatal(err)
		}
		if got, err := currentZone(p); err != nil || got != tt.want {
			t.Errorf("currentZone(link to %s) = %q, %v; want %q", tt.target, got, err, tt.want)
		}
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{file, filepath.Join(dir, "missing")} {
		if got, err := currentZone(p); err != nil || got != "" {
			t.Errorf("currentZone(%s) = %q, %v; want no zone", p, got, err)
		}
	}
}

// spec: Modules/reboot
func TestReboot(t *testing.T) {
	no, yes := false, true
	if got := (&Reboot{IfRequired: &yes}).Main(); got != "if required" {
		t.Errorf("Main = %q", got)
	}
	if got := (&Reboot{IfRequired: &no}).Main(); got != "" {
		t.Errorf("Main = %q", got)
	}
	if got := (&Reboot{IfRequired: &no}).Wait(); got != 600*time.Second {
		t.Errorf("default wait = %d, want 600", got)
	}
	if got := (&Reboot{IfRequired: &no, Timeout: new(30)}).Wait(); got != 30*time.Second {
		t.Errorf("wait = %d, want 30", got)
	}
	for _, timeout := range []int{-1, 0} {
		if err := (&Reboot{IfRequired: &no, Timeout: &timeout}).Validate(); err == nil {
			t.Errorf("timeout %d validates", timeout)
		}
	}
	res, err := (&Reboot{IfRequired: &no}).Check(t.Context(), &State{}, func(string) {})
	if err != nil || res.Status != Change || res.Deferred {
		t.Errorf("Check without if_required = %+v, %v; want a change", res, err)
	}
}
