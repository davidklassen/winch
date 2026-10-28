package module

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/yamlx"
)

// spec: Modules/download
func TestDownloadValidate(t *testing.T) {
	sum := "sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"file", "url: https://example.com/tool\n" + sum + "path: /usr/local/bin/tool\nmode: \"0755\"\n", ""},
		{"unpack", "url: https://example.com/a.tar.gz\n" + sum + "path: /opt/a.tar.gz\nunpack: /opt/a\nowner: app\ngroup: app\n", ""},
		{"unpack tgz", "url: http://example.com/a\n" + sum + "path: /opt/a.tgz\nunpack: /opt/a\n", ""},
		{"unpack tar.xz", "url: http://example.com/a\n" + sum + "path: /opt/a.tar.xz\nunpack: /opt/a\n", ""},
		{"unpack zip", "url: http://example.com/a\n" + sum + "path: /opt/a.zip\nunpack: /opt/a\n", ""},
		{"no sha256", "url: https://example.com/tool\npath: /x\n", `t.yaml:1:1: missing key "sha256"`},
		{"no url", sum + "path: /x\n", `t.yaml:1:1: missing key "url"`},
		{"no path", "url: https://example.com/tool\n" + sum, `t.yaml:1:1: missing key "path"`},
		{"short sha256", "url: https://example.com/tool\nsha256: abc\npath: /x\n", `t.yaml:2:9: sha256: must be 64 lowercase hexadecimal digits, as sha256sum prints them`},
		{"upper case sha256", "url: https://example.com/tool\nsha256: 0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef\npath: /x\n", `t.yaml:2:9: sha256: must be 64 lowercase hexadecimal digits, as sha256sum prints them`},
		{"ftp url", "url: ftp://example.com/tool\n" + sum + "path: /x\n", `t.yaml:1:6: url: must be an http or https URL`},
		{"url without host", "url: https:///tool\n" + sum + "path: /x\n", `t.yaml:1:6: url: must be an http or https URL`},
		{"url with control character", "url: \"https://example.com/a\\nb\"\n" + sum + "path: /x\n", `t.yaml:1:6: url: has a control character`},
		{"relative path", "url: https://example.com/tool\n" + sum + "path: x\n", `t.yaml:3:7: path: must be an absolute path`},
		{"relative unpack", "url: https://example.com/a\n" + sum + "path: /a.zip\nunpack: opt\n", `t.yaml:4:9: unpack: must be an absolute path`},
		{"unpack root", "url: https://example.com/a\n" + sum + "path: /a.zip\nunpack: /\n", `t.yaml:4:9: unpack: must not be /`},
		{"unpack unknown format", "url: https://example.com/a\n" + sum + "path: /opt/a.tar.bz2\nunpack: /opt/a\n", `t.yaml:3:7: path: unpack needs a path that ends in .tar.gz, .tgz, .tar.xz, or .zip`},
		{"unpack and mode", "url: https://example.com/a\n" + sum + "path: /opt/a.zip\nunpack: /opt/a\nmode: \"0755\"\n", `t.yaml:5:7: mode: unpack takes the modes of the archive, without write permission for group and others; it takes no mode`},
		{"unpack into the path", "url: https://example.com/a\n" + sum + "path: /opt/a.zip\nunpack: /opt/a.zip\n", `t.yaml:4:9: unpack: must differ from path`},
		{"bad mode", "url: https://example.com/a\n" + sum + "path: /x\nmode: \"0855\"\n", `t.yaml:4:7: mode: must be an octal mode such as "0755"`},
		{"bad owner", "url: https://example.com/a\n" + sum + "path: /x\nowner: \"a:b\"\n", `t.yaml:4:8: owner: "a:b" is not a name; a name has no ":", "/", or white space, and does not start with "-"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Download{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/download
func TestFetchStall(t *testing.T) {
	const stall = 200 * time.Millisecond
	tests := []struct {
		name string
		gap  time.Duration
		want string
	}{
		{"data in time", stall / 4, ""},
		{"no data", 2 * stall, "no data for 200ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for range 8 {
					if _, err := w.Write([]byte("x")); err != nil {
						return
					}
					w.(http.Flusher).Flush()
					select {
					case <-time.After(tt.gap):
					case <-r.Context().Done():
						return
					}
				}
			}))
			defer srv.Close()
			_, err := fetch(t.Context(), srv.URL, io.Discard, stall)
			if got := fmt.Sprint(err); tt.want == "" && err != nil || tt.want != "" && got != tt.want {
				t.Errorf("fetch error = %v, want %q", err, tt.want)
			}
		})
	}
}

// spec: Modules/download
func TestFetchHTTP(t *testing.T) {
	var agent string
	data := []byte("\x1f\x8b archive bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(data) //nolint:errcheck // the client sees a failed write
	}))
	defer srv.Close()
	var buf bytes.Buffer
	sum, err := fetch(t.Context(), srv.URL+"/app.tar.gz", &buf, stallLimit)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(data); sum != hex.EncodeToString(want[:]) || !bytes.Equal(buf.Bytes(), data) {
		t.Errorf("fetch saved %q with the SHA-256 %s, want the bytes as sent", buf.Bytes(), sum)
	}
	if !strings.HasPrefix(agent, "winch/") {
		t.Errorf("User-Agent = %q, want winch/<version>", agent)
	}
}

// spec: Modules/download
func TestDownloadShortBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("short")) //nolint:errcheck // the client sees a failed write
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Download{URL: srv.URL, SHA256: strings.Repeat("0", 64), Path: p,
		Owner: yamlx.NameOrID(strconv.Itoa(os.Getuid())), Group: yamlx.NameOrID(strconv.Itoa(os.Getgid()))}
	if err := d.Apply(t.Context(), func(string) {}); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("apply = %v, want an unexpected EOF", err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "old\n" {
		t.Errorf("file = %q, %v; want the old file", b, err)
	}
	if entries, err := os.ReadDir(filepath.Dir(p)); err != nil || len(entries) != 1 {
		t.Errorf("directory = %v, %v; want only the old file", entries, err)
	}
}
