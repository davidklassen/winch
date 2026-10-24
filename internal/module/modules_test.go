package module

import (
	"testing"

	"github.com/davidklassen/winch/internal/yamlx"
)

func validate(t *testing.T, m Module, src, want string) {
	t.Helper()
	n, err := yamlx.Parse("t.yaml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	got := ""
	if err := yamlx.Decode(n, m); err != nil {
		got = err.Error()
	}
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// spec: Modules/pkg
func TestPkgValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"one", "name: nginx\n", ""},
		{"list", "name: [rspamd, valkey-server, libc6, g++, python3.13]\n", ""},
		{"recommends", "name: postfix\nrecommends: false\n", ""},
		{"absent", "name: exim4\nabsent: true\n", ""},
		{"purge", "name: exim4\nabsent: true\npurge: true\n", ""},
		{"no name", "absent: true\n", `t.yaml:1:1: missing key "name"`},
		{"empty list", "name: []\n", `t.yaml:1:7: name: needs at least one package`},
		{"upper case", "name: Nginx\n", `t.yaml:1:7: name: "Nginx" is not a package name`},
		{"version", "name: [curl, nginx=1.2]\n", `t.yaml:1:7: name: "nginx=1.2" is not a package name`},
		{"purge without absent", "name: exim4\npurge: true\n", `t.yaml:2:8: purge: purge: true needs absent: true`},
		{"recommends with absent", "name: exim4\nabsent: true\nrecommends: false\n", `t.yaml:3:13: recommends: absent: true takes no recommends`},
		{"unknown key", "name: x\nrecomends: false\n", `t.yaml:2:1: unknown key "recomends"; did you mean "recommends"?`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Pkg{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/file, dir, link
func TestDirValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"path", "path: /var/www\n", ""},
		{"all fields", "path: /var/www\nowner: www-data\ngroup: www-data\nmode: \"2750\"\n", ""},
		{"absent", "path: /var/www\nabsent: true\n", ""},
		{"no path", "mode: \"0755\"\n", `t.yaml:1:1: missing key "path"`},
		{"relative path", "path: var/www\n", `t.yaml:1:7: path: must be an absolute path`},
		{"unclean path", "path: /var/www/\n", `t.yaml:1:7: path: must be a clean path, such as "/var/www"`},
		{"root", "path: /\n", `t.yaml:1:7: path: must not be /`},
		{"bad mode", "path: /x\nmode: \"755\"\n", ""},
		{"not octal", "path: /x\nmode: \"0855\"\n", `t.yaml:2:7: mode: must be an octal mode such as "0755"`},
		{"mode and absent", "path: /x\nmode: \"0755\"\nabsent: true\n", `t.yaml:2:7: mode: absent: true takes no mode`},
		{"owner and absent", "path: /x\nowner: root\nabsent: true\n", `t.yaml:2:8: owner: absent: true takes no owner`},
		{"purge", "path: /x\npurge: true\n", `t.yaml:2:1: unknown key "purge"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Dir{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/file, dir, link
func TestLinkValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"absolute target", "path: /etc/nginx/sites-enabled/a\ntarget: /etc/nginx/sites-available/a\n", ""},
		{"relative target", "path: /etc/a\ntarget: ../b\n", ""},
		{"absent", "path: /etc/a\nabsent: true\n", ""},
		{"no path", "target: /b\n", `t.yaml:1:1: missing key "path"`},
		{"relative path", "path: a\ntarget: /b\n", `t.yaml:1:7: path: must be an absolute path`},
		{"no target", "path: /a\n", `t.yaml:1:1: target: a link needs a target, or absent: true`},
		{"empty target", "path: /a\ntarget: \"\"\n", `t.yaml:2:9: target: must not be empty`},
		{"target and absent", "path: /a\ntarget: /b\nabsent: true\n", `t.yaml:2:9: target: absent: true takes no target`},
		{"validate", "path: /a\ntarget: /b\nvalidate: nginx -t\n", `t.yaml:3:1: unknown key "validate"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Link{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/service and unit
func TestServiceValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"running", "name: nginx\nrunning: true\n", ""},
		{"enabled", "name: nginx.service\nenabled: false\n", ""},
		{"timer", "name: certbot.timer\nrunning: true\nenabled: true\n", ""},
		{"no name", "running: true\n", `t.yaml:1:1: missing key "name"`},
		{"empty name", "name: \"\"\nrunning: true\n", `t.yaml:1:7: name: "" is not a unit name`},
		{"glob", "name: \"ssh*\"\nrunning: false\n", `t.yaml:1:7: name: "ssh*" is not a unit name`},
		{"instance", "name: getty@tty1.service\nrunning: true\n", ""},
		{"nothing to do", "name: nginx\n", `t.yaml:1:1: a service step needs running or enabled`},
		{"restarted", "name: nginx\nrestarted: true\n", `t.yaml:2:1: unknown key "restarted"`},
		{"yes", "name: nginx\nrunning: yes\n", `t.yaml:2:10: running: expected true or false, got the string "yes"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Service{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/pkg
func TestParseDpkg(t *testing.T) {
	out := "bash\tii \nexim4\trc \nunpacked\tiU \nheld\thi \ntriggers\tit \npurged\tun \n" +
		"libc6\tii \nlibc6\trc \nlibfoo\trc \nlibfoo\tii \n"
	got := parseDpkg(out)
	want := map[string]pkgState{"bash": installed, "exim4": configFiles, "unpacked": partial, "held": installed,
		"triggers": installed, "purged": notInstalled, "libc6": installed, "libfoo": installed}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s = %v, want %v", name, got[name], w)
		}
	}
	if got["nginx"] != notInstalled {
		t.Errorf("an unknown package = %v, want notInstalled", got["nginx"])
	}
}

// spec: Modules/service and unit
func TestParseShow(t *testing.T) {
	got := parseShow("Id=nginx.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nNeedDaemonReload=yes\n")
	want := unitState{id: "nginx.service", load: "loaded", active: "active", file: "enabled", reload: true}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
