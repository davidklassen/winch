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
func TestZoneMissing(t *testing.T) {
	dir := t.TempDir() + "/"
	if err := os.WriteFile(dir+"UTC", []byte("TZif2\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"leapseconds", []byte("# leap seconds\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"Short", []byte("TZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir+"Etc", 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		wantMissing bool
		wantErr     string
	}{
		{"UTC", false, ""},
		{"Mars", true, ""},
		{"Etc", false, "Etc is not a time zone: " + dir + "Etc is a directory"},
		{"leapseconds", false, "leapseconds is not a time zone: " + dir + "leapseconds does not start with TZif"},
		{"Short", false, "Short is not a time zone: " + dir + "Short does not start with TZif"},
	}
	for _, tt := range tests {
		missing, err := zoneMissing(dir, tt.name)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if missing != tt.wantMissing || got != tt.wantErr {
			t.Errorf("zoneMissing(%q) = %v, %v; want %v, %q", tt.name, missing, err, tt.wantMissing, tt.wantErr)
		}
	}
}

// spec: Modules/hostname and timezone; CLI/Messages
func TestUnknownZone(t *testing.T) {
	dir := t.TempDir()
	want := "unknown time zone US/Estern: " + dir + "/US/Estern does not exist; fix a typo in the name, or for an old name such as US/Eastern, install the package tzdata-legacy in an earlier pkg step"
	if err := unknownZone(dir+"/", "US/Estern"); err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
	want = "unknown time zone Europe/Berlin: " + dir + "/none does not exist; install the package tzdata in an earlier pkg step"
	if err := unknownZone(dir+"/none/", "Europe/Berlin"); err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
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
		if got, gone, err := currentZone(p); err != nil || got != tt.want || gone {
			t.Errorf("currentZone(link to %s) = %q, %v, %v; want %q", tt.target, got, gone, err, tt.want)
		}
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		p    string
		gone bool
	}{{file, false}, {filepath.Join(dir, "missing"), true}} {
		if got, gone, err := currentZone(tt.p); err != nil || got != "" || gone != tt.gone {
			t.Errorf("currentZone(%s) = %q, %v, %v; want no zone, gone %v", tt.p, got, gone, err, tt.gone)
		}
	}
}

// spec: Modules/reboot
func TestRebootValidate(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"smallest timeout", "if_required: true\ntimeout: 1\n", ""},
		{"largest timeout", "if_required: true\ntimeout: 9223372036\n", ""},
		{"zero timeout", "if_required: true\ntimeout: 0\n", `t.yaml:2:10: timeout: 0 is below 1 second`},
		{"negative timeout", "if_required: true\ntimeout: -1\n", `t.yaml:2:10: timeout: -1 is below 1 second`},
		{"overflowing timeout", "if_required: true\ntimeout: 9223372037\n", `t.yaml:2:10: timeout: 9223372037 is above 9223372036 seconds`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Reboot{}, tt.yaml, tt.want) })
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
	res, err := (&Reboot{IfRequired: &no}).Check(t.Context(), &State{}, Silent{})
	if err != nil || res.Status != Change || res.Deferred {
		t.Errorf("Check without if_required = %+v, %v; want a change", res, err)
	}
}
