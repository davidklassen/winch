package module

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
		{"shell characters", "name: \"nginx; rm -rf /\"\n", `t.yaml:1:7: name: "nginx; rm -rf /" is not a package name`},
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
		{"names with digits", "path: /x\nowner: user1\ngroup: \"2g\"\n", ""},
		{"numeric IDs", "path: /x\nowner: 999\ngroup: 999\n", ""},
		{"quoted numeric IDs", "path: /x\nowner: \"999\"\ngroup: \"50\"\n", ""},
		{"owner ID too large", "path: /x\nowner: \"4294967296\"\n", `t.yaml:2:8: owner: an ID must be below 4294967295`},
		{"group ID too large", "path: /x\ngroup: 4294967295\n", `t.yaml:2:8: group: an ID must be below 4294967295`},
		{"purge", "path: /x\npurge: true\n", `t.yaml:2:1: unknown key "purge"`},
		{"replace", "path: /x\nreplace: true\n", ""},
		{"replace and absent", "path: /x\nabsent: true\nreplace: true\n", `t.yaml:3:10: replace: absent: true takes no replace`},
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
		{"trailing slash target", "path: /a\ntarget: /etc/nginx/\n", `t.yaml:2:9: target: must be a clean path, such as "/etc/nginx"`},
		{"dot target", "path: /a\ntarget: ./x\n", `t.yaml:2:9: target: must be a clean path, such as "x"`},
		{"double slash target", "path: /a\ntarget: a//b\n", `t.yaml:2:9: target: must be a clean path, such as "a/b"`},
		{"leading dot dot targets", "path: /a\ntarget: ../../lib/x\n", ""},
		{"dot dot only target", "path: /a\ntarget: ../..\n", ""},
		{"dot dot after a part", "path: /a\ntarget: a/../b\n", `t.yaml:2:9: target: ".." after another part is not allowed; write the target without it`},
		{"dot dot after leading dot dot", "path: /a\ntarget: ../a/../b\n", `t.yaml:2:9: target: ".." after another part is not allowed; write the target without it`},
		{"dot dot in absolute target", "path: /a\ntarget: /etc/../b\n", `t.yaml:2:9: target: ".." after another part is not allowed; write the target without it`},
		{"dot then dot dot target", "path: /a\ntarget: ./../x\n", `t.yaml:2:9: target: must be a clean path, such as "../x"`},
		{"name that starts with dot dot", "path: /a\ntarget: a/..b\n", ""},
		{"dot dot after a double slash", "path: /a\ntarget: a//../b\n", `t.yaml:2:9: target: ".." after another part is not allowed; write the target without it`},
		{"trailing dot dot", "path: /a\ntarget: a/..\n", `t.yaml:2:9: target: ".." after another part is not allowed; write the target without it`},
		{"target and absent", "path: /a\ntarget: /b\nabsent: true\n", `t.yaml:2:9: target: absent: true takes no target`},
		{"validate", "path: /a\ntarget: /b\nvalidate: nginx -t\n", ""},
		{"validate and absent", "path: /a\nabsent: true\nvalidate: nginx -t\n", `t.yaml:3:11: validate: absent: true takes no validate`},
		{"empty validate", "path: /a\ntarget: /b\nvalidate: \"\"\n", `t.yaml:3:11: validate: must not be empty`},
		{"replace", "path: /a\ntarget: /b\nreplace: true\n", ""},
		{"replace and absent", "path: /a\nabsent: true\nreplace: true\n", `t.yaml:3:10: replace: absent: true takes no replace`},
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
		{"shell characters", "name: \"a b;$(id)\"\nrunning: true\n", `t.yaml:1:7: name: "a b;$(id)" is not a unit name`},
		{"escaped instance", "name: \"winch@a\\\\x20b\"\nrunning: true\n", ""},
		{"instance", "name: getty@tty1.service\nrunning: true\n", ""},
		{"instance without suffix", "name: getty@tty1\nrunning: true\n", ""},
		{"two ats", "name: a@b@c\nrunning: true\n", ""},
		{"no instance", "name: nginx@\nrunning: true\n", `t.yaml:1:7: name: "nginx@" needs an instance name after "@"`},
		{"template", "name: getty@.service\nenabled: true\n", `t.yaml:1:7: name: "getty@.service" needs an instance name after "@"`},
		{"nothing before at", "name: \"@foo\"\nrunning: true\n", `t.yaml:1:7: name: "@foo" needs a name before "@"`},
		{"only a suffix", "name: .timer\nrunning: true\n", `t.yaml:1:7: name: ".timer" needs a name before the suffix`},
		{"unknown suffix", "name: \"a@.bar\"\nrunning: true\n", ""},
		{"longest", "name: " + strings.Repeat("a", 247) + "\nrunning: true\n", ""},
		{"too long", "name: " + strings.Repeat("a", 248) + "\nrunning: true\n", `t.yaml:1:7: name: has 256 characters with .service added; a unit name has at most 255`},
		{"longest with suffix", "name: " + strings.Repeat("a", 249) + ".timer\nrunning: true\n", ""},
		{"too long with suffix", "name: " + strings.Repeat("a", 250) + ".timer\nrunning: true\n", `t.yaml:1:7: name: has 256 characters; a unit name has at most 255`},
		{"too long with unknown suffix", "name: " + strings.Repeat("a", 244) + ".bar\nrunning: true\n", `t.yaml:1:7: name: has 256 characters with .service added; a unit name has at most 255`},
		{"nothing to do", "name: nginx\n", `t.yaml:1:1: a service step needs running or enabled`},
		{"restarted", "name: nginx\nrestarted: true\n", ""},
		{"reloaded", "name: nginx\nreloaded: true\n", ""},
		{"reloaded and restarted", "name: nginx\nreloaded: true\nrestarted: true\n", `t.yaml:3:12: restarted: a service step has one of reloaded and restarted`},
		{"reloaded with running", "name: nginx\nreloaded: true\nrunning: true\n", `t.yaml:3:10: running: reloaded takes no running`},
		{"restarted with enabled", "name: nginx\nrestarted: true\nenabled: true\n", `t.yaml:3:10: enabled: restarted takes no enabled`},
		{"restarted false", "name: nginx\nrestarted: false\n", `t.yaml:1:1: a service step needs running or enabled`},
		{"yes", "name: nginx\nrunning: yes\n", `t.yaml:2:10: running: expected true or false, got the string "yes"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Service{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/pkg
func TestParseDpkg(t *testing.T) {
	out := "bash\tamd64\tii \t5.2\nexim4\tamd64\trc \t4.98\nheld\tamd64\thi \t1\nheldrc\tamd64\thc \t1\npurged\tamd64\tun \t\n" +
		"libc6\tamd64\tii \t2.41\nlibc6\ti386\trc \t2.40\nlibfoo\tamd64\trc \t1\nlibfoo\tall\tii \t1\nheld2\tamd64\thi \t1\nheld2\ti386\trc \t1\n" +
		"nginx\tamd64\tiF \t1.26.3-3\nlibbar\tall\tii \t2\nlibbar\tamd64\tiU \t3\n" +
		"libz\tamd64\trc \t1\nlibz\ti386\tii \t1\nwine32\ti386\tii \t9\nlibheld\tamd64\tii \t1\nlibheld\ti386\thi \t1\nlibhalf\ti386\tiF \t4\n" +
		"heldnone\t\thn \t\n"
	got, err := parseDpkg(out, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]dpkgPkg{"bash": {state: installed}, "exim4": {state: configFiles},
		"held": {state: installed, held: true}, "heldrc": {state: configFiles, held: true}, "purged": {state: notInstalled},
		"libc6": {state: installed}, "libfoo": {state: installed}, "held2": {state: installed, held: true},
		"nginx": {half: 'F', version: "1.26.3-3"}, "libbar": {state: installed, half: 'U', version: "3"},
		"libz": {state: configFiles}, "libz:i386": {state: installed}, "wine32": {state: notInstalled}, "wine32:i386": {state: installed},
		"libheld": {state: installed}, "libheld:i386": {state: installed, held: true},
		"libhalf": {state: notInstalled}, "libhalf:i386": {half: 'F', version: "4"},
		"heldnone": {held: true}}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s = %+v, want %+v", name, got[name], w)
		}
	}
	if got["apache2"] != (dpkgPkg{}) {
		t.Errorf("an unknown package = %+v, want not installed", got["apache2"])
	}
}

// spec: Modules/pkg
func TestOthersHalfDone(t *testing.T) {
	pkgs, _ := parseDpkg("bash\tamd64\tii \t5.2\nnginx\tamd64\tiF \t1.26\nlibfoo\tall\tiU \t1\nlibbar\tamd64\tiHR\t1\nlibbaz\tamd64\tit \t1\nlibqux\tamd64\tiW \t1\n", "amd64")
	tests := []struct {
		name  string
		names []string
		want  string
	}{
		{"all named", []string{"nginx", "libfoo", "libbar", "libbaz", "libqux"}, ""},
		{"half configured", []string{"libfoo", "libbar", "libbaz", "libqux"}, "nginx is half configured: its configuration failed; fix the cause, then run dpkg --configure -a"},
		{"unpacked", []string{"nginx", "libbar", "libbaz", "libqux"}, "libfoo is unpacked: its configuration did not run; fix the cause, then run dpkg --configure -a"},
		{"half installed", []string{"nginx", "libfoo", "libbaz", "libqux"}, "libbar is half installed: its installation failed; fix the cause, then run apt-get install --reinstall libbar"},
		{"triggers pending", []string{"nginx", "libfoo", "libbar", "libqux"}, "libbaz is triggered: its trigger processing did not run; fix the cause, then run dpkg --configure -a"},
		{"triggers awaited", []string{"nginx", "libfoo", "libbar", "libbaz"}, "libqux is awaiting triggers: the trigger processing of another package did not run; fix the cause, then run dpkg --configure -a"},
		{"several, by name", []string{"bash", "libbaz", "libqux"}, "libbar is half installed: its installation failed; fix the cause, then run apt-get install --reinstall libbar\n" +
			"libfoo is unpacked: its configuration did not run; fix the cause, then run dpkg --configure -a\n" +
			"nginx is half configured: its configuration failed; fix the cause, then run dpkg --configure -a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			if err := othersHalfDone(pkgs, tt.names); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("err = %q, want %q", got, tt.want)
			}
		})
	}
}

// spec: Modules/pkg
func TestOthersHalfDoneNamesTheArchitecture(t *testing.T) {
	pkgs, _ := parseDpkg("libc6\tamd64\tii \t2.41\nlibc6\ti386\tiH \t2.41\n", "amd64")
	err := othersHalfDone(pkgs, []string{"libc6"})
	want := "libc6:i386 is half installed: its installation failed; fix the cause, then run apt-get install --reinstall libc6:i386"
	if err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}

// spec: Modules/service and unit
func TestParseShow(t *testing.T) {
	got, err := parseShow("Id=nginx.service\nLoadState=loaded\nActiveState=activating\nSubState=auto-restart\nUnitFileState=enabled\nNeedDaemonReload=yes\nDropInPaths=\nTriggeredBy=nginx.socket nginx.path\n")
	want := unitState{id: "nginx.service", load: "loaded", active: "activating", sub: "auto-restart", file: "enabled", reload: true, triggeredBy: []string{"nginx.socket", "nginx.path"}}
	if !reflect.DeepEqual(got, want) || err != nil {
		t.Errorf("got %+v, %v; want %+v", got, err, want)
	}
}

// spec: Modules/service and unit
func TestParseShowBadOutput(t *testing.T) {
	for _, tc := range []struct{ name, out, want string }{
		{"empty", "", "no output"},
		{"junk line", "Id=nginx.service\nLoadState=loaded\nActiveState=active\nFailed to get properties: Access denied\n", `unexpected line "Failed to get properties: Access denied"`},
		{"no Id", "LoadState=loaded\nActiveState=active\n", "no Id line"},
		{"no LoadState", "Id=nginx.service\nActiveState=active\n", "no LoadState line"},
		{"no ActiveState", "Id=nginx.service\nLoadState=loaded\n", "no ActiveState line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseShow(tc.out); err == nil || err.Error() != tc.want {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// spec: Modules/pkg
func TestParseDpkgBadOutput(t *testing.T) {
	for _, tc := range []struct{ name, out, want string }{
		{"empty", "", "no packages in the output"},
		{"junk line", "bash\tamd64\tii \t5.2\ndpkg-query: warning: something\n", `unexpected line "dpkg-query: warning: something"`},
		{"no version", "bash\tamd64\tii \t5.2\nnginx\tamd64\tii \n", `unexpected line "nginx\tamd64\tii "`},
		{"short status", "bash\tamd64\ti\t5.2\n", `unexpected line "bash\tamd64\ti\t5.2"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDpkg(tc.out, "amd64"); err == nil || err.Error() != tc.want {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// spec: Modules/service and unit
func TestInstallKeys(t *testing.T) {
	type keys = map[string][]string
	for _, tc := range []struct {
		name  string
		units []string
		want  keys
	}{
		{"no section", []string{"[Service]\nExecStart=/bin/true\n"}, keys{}},
		{"WantedBy", []string{"[Install]\nWantedBy=multi-user.target\n"}, keys{"WantedBy": {"multi-user.target"}}},
		{"Alias with spaces", []string{"[Install]\n  Alias = app2.service\n"}, keys{"Alias": {"app2.service"}}},
		{"Also adds its words", []string{"[Install]\nAlso=a.service b.socket\nAlso=c.service\n"}, keys{"Also": {"a.service", "b.socket", "c.service"}}},
		{"key in another section", []string{"[Unit]\nWantedBy=multi-user.target\n[Install]\n"}, keys{}},
		{"comment", []string{"[Install]\n#WantedBy=multi-user.target\n;RequiredBy=a.target\n"}, keys{}},
		{"empty value clears", []string{"[Install]\nUpheldBy=a.target\nUpheldBy=\n"}, keys{}},
		{"a drop-in adds a key", []string{"[Service]\n", "[Install]\nWantedBy=a.target\n"}, keys{"WantedBy": {"a.target"}}},
		{"a drop-in keeps a key", []string{"[Install]\nWantedBy=a.target\n", "[Service]\nNice=5\n"}, keys{"WantedBy": {"a.target"}}},
		{"a drop-in clears a key", []string{"[Install]\nWantedBy=a.target\n", "[Install]\nWantedBy=\n"}, keys{}},
		{"value after an empty one", []string{"[Install]\nRequiredBy=\nRequiredBy=a.target\n"}, keys{"RequiredBy": {"a.target"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			for i, u := range tc.units {
				p := filepath.Join(t.TempDir(), fmt.Sprint(i, ".conf"))
				if err := os.WriteFile(p, []byte(u), 0o644); err != nil {
					t.Fatal(err)
				}
				paths = append(paths, p)
			}
			got, err := installKeys(paths)
			if err != nil || !maps.EqualFunc(got, tc.want, slices.Equal[[]string]) {
				t.Errorf("installKeys = %v, %v, want %v", got, err, tc.want)
			}
		})
	}
}

// spec: Modules/service and unit
func TestFailedConditions(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		want      []string
	}{
		{"one", "a.service: ConditionPathExists=/ succeeded.\na.service: ConditionPathExists=/x failed.\nConditions failed.\n", []string{"ConditionPathExists=/x"}},
		{"negated", "a.service: ConditionPathExists=!/ failed.\nConditions failed.\n", []string{"ConditionPathExists=!/"}},
		{"a failed trigger before a failed plain condition", "a.service: ConditionPathExists=|/x failed.\na.service: ConditionPathExists=/y failed.\nConditions failed.\n", []string{"ConditionPathExists=/y"}},
		{"all triggers failed", "a.service: ConditionPathExists=|!/ failed.\na.service: ConditionPathExists=|/x failed.\nConditions failed.\n", []string{"ConditionPathExists=|!/", "ConditionPathExists=|/x"}},
		{"an assert", "a.service: AssertPathExists=/x failed.\nAsserts failed.\n", nil},
		{"another unit", "b.service: ConditionPathExists=/x failed.\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := failedConditions("a.service", tc.out); !slices.Equal(got, tc.want) {
				t.Errorf("failedConditions = %q, want %q", got, tc.want)
			}
		})
	}
}

// spec: Modules/file, dir, link
func TestTreeCheck(t *testing.T) {
	tests := []struct {
		name    string
		tree    tree
		replace bool
		want    string
		wantErr string
	}{
		{"file", tree{}, true, "remove file /srv/k", ""},
		{"empty directory", tree{dir: true}, true, "remove directory /srv/k: 0 files, 0 directories", ""},
		{"one of each", tree{dir: true, files: 1, dirs: 1}, true, "remove directory /srv/k: 1 file, 1 directory", ""},
		{"many", tree{dir: true, files: 40000, dirs: 12}, true, "remove directory /srv/k: 40000 files, 12 directories", ""},
		{"file without replace", tree{}, false, "", "/srv/k is a file; add replace: true to remove it"},
		{"empty directory without replace", tree{dir: true}, false, "", "/srv/k is an empty directory; add replace: true to remove it"},
		{"files without replace", tree{dir: true, files: 3}, false, "", "/srv/k is a directory with 3 files; add replace: true to remove it"},
		{"directories without replace", tree{dir: true, dirs: 1}, false, "", "/srv/k is a directory with 1 directory; add replace: true to remove it"},
		{"both without replace", tree{dir: true, files: 1, dirs: 2}, false, "", "/srv/k is a directory with 1 file and 2 directories; add replace: true to remove it"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tree.check("/srv/k", tt.replace)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if got != tt.want || gotErr != tt.wantErr {
				t.Errorf("got %q, %q; want %q, %q", got, gotErr, tt.want, tt.wantErr)
			}
		})
	}
}
