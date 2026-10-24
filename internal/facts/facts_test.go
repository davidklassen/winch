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
		name string
		data string
		want OS
	}{
		{"debian 13", string(data), OS{ID: "debian", Version: "13", Codename: "trixie"}},
		{"quotes and comments", "# comment\nID='debian'\nVERSION_ID=\"1\\\"3\"\n\nVERSION_CODENAME=\"tri xie\"\nbad line\n", OS{ID: "debian", Version: `1"3`, Codename: "tri xie"}},
		{"testing without a version", "ID=debian\nVERSION_CODENAME=forky\n", OS{ID: "debian", Codename: "forky"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Parse([]byte(tt.data)).OS; got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
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
	if _, err := Read("testdata/missing"); err == nil {
		t.Error("Read of a missing file: no error")
	}
}
