package module

import "testing"

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
		{"unpack unknown format", "url: https://example.com/a\n" + sum + "path: /opt/a.tgz\nunpack: /opt/a\n", `t.yaml:3:7: path: unpack needs a path that ends in .tar.gz, .tar.xz, or .zip`},
		{"unpack and mode", "url: https://example.com/a\n" + sum + "path: /opt/a.zip\nunpack: /opt/a\nmode: \"0755\"\n", `t.yaml:5:7: mode: unpack takes the modes of the archive, without write permission for group and others; it takes no mode`},
		{"unpack into the path", "url: https://example.com/a\n" + sum + "path: /opt/a.zip\nunpack: /opt/a.zip\n", `t.yaml:4:9: unpack: must differ from path`},
		{"bad mode", "url: https://example.com/a\n" + sum + "path: /x\nmode: \"0855\"\n", `t.yaml:4:7: mode: must be an octal mode such as "0755"`},
		{"bad owner", "url: https://example.com/a\n" + sum + "path: /x\nowner: \"a:b\"\n", `t.yaml:4:8: owner: "a:b" is not a name; a name has no ":", "/", or white space, and does not start with "-"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Download{}, tt.yaml, tt.want) })
	}
}
