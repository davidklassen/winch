package facts

import (
	"os"
	"runtime"
	"testing"
)

// spec: Remote execution/Facts
func TestParse(t *testing.T) {
	data, err := os.ReadFile("testdata/debian-13.os-release")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		data    string
		want    OS
		wantErr string
	}{
		{"debian 13", string(data), OS{ID: "debian", Version: "13", Codename: "trixie"}, ""},
		{"quotes and comments", "# comment\nID='debian'\nVERSION_ID=\"1\\\"3\"\n\nVERSION_CODENAME=\"tri xie\"\nbad line\n", OS{ID: "debian", Version: `1"3`, Codename: "tri xie"}, ""},
		{"testing without a version", "ID=debian\nVERSION_CODENAME=forky\n", OS{ID: "debian", Codename: "forky"}, ""},
		{"empty", "", OS{}, "no ID line"},
		{"junk lines", "\x00\x01garbage\n=\nID\n", OS{}, "no ID line"},
		{"no ID", "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\n", OS{}, "no ID line"},
		{"empty ID", "ID=\nVERSION_ID=13\n", OS{}, "no ID line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.data))
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if got.OS != tt.want || gotErr != tt.wantErr {
				t.Errorf("got %+v, %q; want %+v, %q", got.OS, gotErr, tt.want, tt.wantErr)
			}
		})
	}
}

// spec: Remote execution/Facts
func TestRead(t *testing.T) {
	f, err := Read("testdata/debian-13.os-release")
	if want := (OS{ID: "debian", Version: "13", Codename: "trixie", Arch: runtime.GOARCH}); err != nil || f.OS != want {
		t.Errorf("Read = %+v, %v; want %+v", f, err, want)
	}
	f, err = Read("testdata/missing", "testdata/debian-13.os-release")
	if want := (OS{ID: "debian", Version: "13", Codename: "trixie", Arch: runtime.GOARCH}); err != nil || f.OS != want {
		t.Errorf("Read of a missing first file = %+v, %v; want %+v", f, err, want)
	}
	if _, err := Read("testdata/missing", "testdata/gone"); err == nil || err.Error() != "read facts: neither testdata/missing nor testdata/gone exists" {
		t.Errorf("Read of missing files: %v", err)
	}
	empty := t.TempDir() + "/os-release"
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(empty, "testdata/debian-13.os-release"); err == nil || err.Error() != "read facts: "+empty+": no ID line" {
		t.Errorf("Read of an empty file: %v", err)
	}
	// A first file that exists but cannot be read is an error, not a reason
	// to read the second.
	if _, err := Read("testdata", "testdata/debian-13.os-release"); err == nil || err.Error() != "read facts: read testdata: is a directory" {
		t.Errorf("Read of a directory: %v", err)
	}
}

// spec: Remote execution/Facts (reboot_required)
func TestRebootRequired(t *testing.T) {
	tests := []struct {
		name    string
		flag    bool
		kernels []string
		release string
		want    bool
	}{
		{"no flag, running the only kernel", false, []string{"6.12.43+deb13-arm64"}, "6.12.43+deb13-arm64", false},
		{"the flag file", true, []string{"6.12.43+deb13-arm64"}, "6.12.43+deb13-arm64", true},
		{"a newer kernel", false, []string{"6.12.43+deb13-arm64", "6.12.48+deb13-arm64"}, "6.12.43+deb13-arm64", true},
		{"running the newest", false, []string{"6.12.43+deb13-arm64", "6.12.48+deb13-arm64"}, "6.12.48+deb13-arm64", false},
		{"numbers, not text", false, []string{"6.12.9+deb13-arm64", "6.12.10+deb13-arm64"}, "6.12.10+deb13-arm64", false},
		{"numbers, not text, older", false, []string{"6.12.9+deb13-arm64", "6.12.10+deb13-arm64"}, "6.12.9+deb13-arm64", true},
		{"a tilde sorts first", false, []string{"6.12~rc1-arm64", "6.12-arm64"}, "6.12-arm64", false},
		{"another flavor does not count", false, []string{"6.12.43+deb13-arm64", "6.12.48+deb13-rt-arm64"}, "6.12.43+deb13-arm64", false},
		{"no kernels in boot", false, nil, "6.12.43+deb13-arm64", false},
		{"debian 12 abi", false, []string{"6.1.0-28-amd64", "6.1.0-31-amd64"}, "6.1.0-28-amd64", true},
		{"debian 12 abi, running the newest", false, []string{"6.1.0-28-cloud-amd64", "6.1.0-31-cloud-amd64"}, "6.1.0-31-cloud-amd64", false},
		{"debian 12, another flavor", false, []string{"6.1.0-28-amd64", "6.1.0-31-cloud-amd64"}, "6.1.0-28-amd64", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			boot := dir + "/boot"
			if err := os.Mkdir(boot, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, k := range append(tt.kernels, "config-x") {
				if err := os.WriteFile(boot+"/vmlinuz-"+k, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			flag := dir + "/reboot-required"
			if tt.flag {
				if err := os.WriteFile(flag, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := RebootRequired(flag, boot, tt.release)
			if tt.kernels == nil {
				got, err = RebootRequired(flag, dir+"/missing", tt.release)
			}
			if err != nil || got != tt.want {
				t.Errorf("RebootRequired = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

// spec: Modules/reboot (the running and the newest kernel)
func TestNewestKernel(t *testing.T) {
	boot := t.TempDir()
	for _, k := range []string{"6.12.43+deb13-arm64", "6.12.48+deb13-arm64", "6.12.45+deb13-arm64", "6.13.1+deb13-rt-arm64"} {
		if err := os.WriteFile(boot+"/vmlinuz-"+k, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for release, want := range map[string]string{
		"6.12.43+deb13-arm64":    "6.12.48+deb13-arm64",
		"6.12.48+deb13-arm64":    "6.12.48+deb13-arm64",
		"6.12.50+deb13-arm64":    "6.12.50+deb13-arm64",
		"6.12.43+deb13-rt-arm64": "6.13.1+deb13-rt-arm64",
	} {
		if got, err := NewestKernel(boot, release); err != nil || got != want {
			t.Errorf("NewestKernel(%q) = %q, %v; want %q", release, got, err, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0+deb13", "1.0", 1},
		{"1.0a", "1.0+", -1},
		{"6.12.43+deb13", "6.12.48+deb13", -1},
		{"1:1.0", "2.0", 1},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := compareVersions(tt.b, tt.a); got != -tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}
