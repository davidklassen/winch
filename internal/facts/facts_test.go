package facts

import (
	"os"
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
	if want := (OS{ID: "debian", Version: "13", Codename: "trixie"}); err != nil || f.OS != want {
		t.Errorf("Read = %+v, %v; want %+v", f, err, want)
	}
	f, err = Read("testdata/missing", "testdata/debian-13.os-release")
	if want := (OS{ID: "debian", Version: "13", Codename: "trixie"}); err != nil || f.OS != want {
		t.Errorf("Read of a missing first file = %+v, %v; want %+v", f, err, want)
	}
	if _, err := Read("testdata/missing", "testdata/missing"); err == nil {
		t.Error("Read of missing files: no error")
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
	if _, err := Read("testdata", "testdata/debian-13.os-release"); err == nil {
		t.Error("Read of a directory: no error")
	}
}
