package module

import "testing"

// spec: Modules/line
func TestLineValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"line", "path: /etc/redis/redis.conf\nline: maxmemory 256mb\nmatch: ^maxmemory \n", ""},
		{"absent", "path: /etc/pam.d/sshd\nmatch: pam_motd\nabsent: true\n", ""},
		{"no path", "line: a\nmatch: ^a\n", `t.yaml:1:1: a line step needs path`},
		{"no match", "path: /etc/a\nline: a\n", `t.yaml:1:1: a line step needs match`},
		{"relative path", "path: etc/a\nline: a\nmatch: ^a\n", `t.yaml:1:7: path: must be an absolute path`},
		{"no line", "path: /etc/a\nmatch: ^a\n", `t.yaml:1:1: a line step needs line, or absent: true`},
		{"line and absent", "path: /etc/a\nline: a\nmatch: ^a\nabsent: true\n", `t.yaml:2:7: line: not with absent: true`},
		{"empty match", "path: /etc/a\nline: a\nmatch: \"\"\n", `t.yaml:3:8: match: is empty`},
		{"bad match", "path: /etc/a\nline: a\nmatch: \"a(\"\n", "t.yaml:3:8: match: not a regular expression: missing closing ): a("},
		{"Perl syntax", "path: /etc/a\nline: a\nmatch: \"^(?!#)PermitRootLogin\"\n", "t.yaml:3:8: match: (?! is not supported; match has the RE2 syntax, without lookahead, lookbehind, or backreferences"},
		{"two lines", "path: /etc/a\nline: \"a\\nb\"\nmatch: ^a\n", `t.yaml:2:7: line: must be one line`},
		{"carriage return", "path: /etc/a\nline: \"a\\r\"\nmatch: ^a\n", `t.yaml:2:7: line: must be one line`},
		{"line that match does not find", "path: /etc/a\nline: port 1\nmatch: ^Port \n", `t.yaml:2:7: line: match does not find it, so each run would add it again`},
		{"tab", "path: /etc/a\nline: \"a\\tb\"\nmatch: ^a\n", ""},
		{"match that finds an empty line", "path: /etc/a\nmatch: \".*\"\nabsent: true\n", `t.yaml:2:8: match: matches an empty line`},
		{"match of an empty line", "path: /etc/a\nmatch: ^$\nabsent: true\n", `t.yaml:2:8: match: matches an empty line`},
		{"validate", "path: /etc/ssh/sshd_config\nline: PermitRootLogin no\nmatch: ^PermitRootLogin \nvalidate: sshd -t\n", ""},
		{"validate with absent", "path: /etc/ssh/sshd_config\nmatch: ^PermitRootLogin \nabsent: true\nvalidate: sshd -t\n", ""},
		{"empty validate", "path: /etc/a\nline: a\nmatch: ^a\nvalidate: \"\"\n", `t.yaml:4:11: validate: is empty`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Line{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/line; CLI/Messages
func TestLineSeveralMatches(t *testing.T) {
	l := &Line{Path: "/etc/a", Line: "port 3", Match: "^port "}
	_, _, err := l.edit([]byte("port 1\nx\nport 2\n"))
	want := `/etc/a has 2 lines that match "^port ": lines 1, 3; make match find one line`
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}
