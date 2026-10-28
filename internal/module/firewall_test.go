package module

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/yamlx"
)

func decodeFirewall(t *testing.T, y string) (*Firewall, error) {
	t.Helper()
	n, err := yamlx.Parse("t.yaml", []byte(y))
	if err != nil {
		t.Fatal(err)
	}
	f := new(Firewall)
	return f, yamlx.Decode(n, f)
}

// spec: Modules/firewall (allow, rules, absent)
func TestFirewallValidate(t *testing.T) {
	tests := []struct {
		name, yaml, wantErr string
	}{
		{"rules", "allow:\n  - tcp: [22, 80, 443]\n  - udp: 51820\n  - tcp: 5432\n    from: [10.0.0.0/8, 2001:db8::/32]\n", ""},
		{"one address", "allow:\n  - tcp: 22\n    from: 192.0.2.7\n", ""},
		{"no rules", "allow: []\n", ""},
		{"absent", "absent: true\n", ""},
		{"nothing", "{}\n", "a firewall step needs allow, or absent: true"},
		{"absent with rules", "absent: true\nallow:\n  - tcp: 22\n", "absent: true takes no allow"},
		{"tcp and udp", "allow:\n  - tcp: 53\n    udp: 53\n", "a rule has one of tcp and udp, not both"},
		{"no protocol", "allow:\n  - from: 10.0.0.0/8\n", "a rule needs tcp or udp"},
		{"no ports", "allow:\n  - tcp: []\n", "tcp: needs a port"},
		{"port 0", "allow:\n  - tcp: 0\n", "tcp: port 0 is not between 1 and 65535"},
		{"port too high", "allow:\n  - udp: [53, 65536]\n", "udp: port 65536 is not between 1 and 65535"},
		{"repeated port", "allow:\n  - tcp: [22, 80, 22]\n", "tcp: port 22 is in the list twice"},
		{"no address", "allow:\n  - tcp: 22\n    from: []\n", "from: needs an address or a network"},
		{"bad address", "allow:\n  - tcp: 22\n    from: 10.0.0.300\n", `from: "10.0.0.300" is not an IPv4 or IPv6 address or network`},
		{"name", "allow:\n  - tcp: 22\n    from: office.example.com\n", `from: "office.example.com" is not an IPv4 or IPv6 address or network`},
		{"zone", "allow:\n  - tcp: 22\n    from: fe80::1%eth0\n", `from: "fe80::1%eth0" is not an IPv4 or IPv6 address or network`},
		{"host bits", "allow:\n  - tcp: 22\n    from: 10.1.2.3/8\n", "from: 10.1.2.3/8 has bits set after the prefix; write 10.0.0.0/8"},
		{"IPv4 in IPv6 form", "allow:\n  - tcp: 22\n    from: ::ffff:10.0.0.5\n", "from: ::ffff:10.0.0.5 is an IPv4 address in IPv6 form; write 10.0.0.5"},
		{"repeated address", "allow:\n  - tcp: 22\n    from: [10.0.0.0/8, 10.0.0.0/8]\n", "from: 10.0.0.0/8 is in the list twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeFirewall(t, tt.yaml)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("error %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// spec: Modules/firewall (the table, its built-in rules, and its file)
func TestFirewallContent(t *testing.T) {
	f, err := decodeFirewall(t, "allow:\n  - tcp: [22, 80, 443]\n  - udp: 51820\n  - tcp: 5432\n    from: [10.0.0.0/8, 2001:DB8::/32, 192.0.2.7]\n")
	if err != nil {
		t.Fatal(err)
	}
	got := string(f.render(f.id()))
	want := `# winch writes this file from the firewall step.
# allow tcp 22, 80, 443
# allow udp 51820
# allow tcp 5432 from 10.0.0.0/8, 2001:db8::/32, 192.0.2.7
table inet winch
delete table inet winch
table inet winch {
	comment "ID"
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		icmp type echo-request accept
		icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, packet-too-big } accept
		udp sport 67 udp dport 68 accept
		udp sport 547 udp dport 546 accept
		tcp dport { 22, 80, 443 } accept
		udp dport 51820 accept
		ip saddr { 10.0.0.0/8, 192.0.2.7 } tcp dport 5432 accept
		ip6 saddr 2001:db8::/32 tcp dport 5432 accept
	}
}
`
	comment := regexp.MustCompile(`\tcomment "([0-9a-f]{16})"\n`)
	m := comment.FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("no comment with the ID of the rules:\n%s", got)
	}
	if strings.Replace(got, m[1], "ID", 1) != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if f.id() != m[1] {
		t.Errorf("id() = %s, want %s", f.id(), m[1])
	}
	other, err := decodeFirewall(t, "allow:\n  - tcp: 22\n")
	if err != nil {
		t.Fatal(err)
	}
	if other.id() == f.id() {
		t.Error("two rule sets have the same ID")
	}
}

// spec: Modules/firewall (the plan fails when no rule accepts the port of the
// session's SSH server from the session's client address)
func TestFirewallSSH(t *testing.T) {
	const v4 = "10.0.2.2 54950 10.0.2.15 22"
	const v6 = "2001:db8::5 40000 2001:db8::1 2222"
	tests := []struct {
		name, allow, conn, wantErr string
	}{
		{"port", "- tcp: 22", v4, ""},
		{"port in a list", "- tcp: [80, 22]", v4, ""},
		{"second rule", "- tcp: 80\n- tcp: 22", v4, ""},
		{"from a network", "- tcp: 22\n  from: 10.0.0.0/8", v4, ""},
		{"from the address", "- tcp: 22\n  from: 10.0.2.2", v4, ""},
		{"other port", "- tcp: 80", v4, "the rules close the SSH port 22 that winch uses"},
		{"udp", "- udp: 22", v4, "the rules close the SSH port 22 that winch uses"},
		{"other network", "- tcp: 22\n  from: 192.168.0.0/16", v4, "the rules close the SSH port 22 that winch uses"},
		{"IPv6", "- tcp: 2222\n  from: 2001:db8::/32", v6, ""},
		{"IPv6 from an IPv4 network", "- tcp: 2222\n  from: 10.0.0.0/8", v6, "the rules close the SSH port 2222 that winch uses"},
		{"no rules", "[]", v4, "the rules close the SSH port 22 that winch uses"},
		{"no SSH session", "[]", "", ""},
		{"IPv4 in IPv6 form", "- tcp: 22\n  from: 10.0.0.0/8", "::ffff:10.0.2.2 54950 ::ffff:10.0.2.15 22", ""},
		{"loopback", "- tcp: 80", "127.0.0.1 54950 127.0.0.1 22", ""},
		{"IPv6 loopback", "- tcp: 80", "::1 54950 ::1 22", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := decodeFirewall(t, "allow:\n"+indent(tt.allow))
			if err != nil {
				t.Fatal(err)
			}
			err = f.checkSSH(tt.conn)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr) {
				t.Errorf("checkSSH(%q) = %v, want %q", tt.conn, err, tt.wantErr)
			}
		})
	}
}

func indent(s string) string {
	if s == "[]" {
		return "  []\n"
	}
	return "  " + strings.ReplaceAll(s, "\n", "\n  ") + "\n"
}

// spec: Modules/firewall (the plan shows each rule that the step adds or
// removes)
func TestFirewallRuleChanges(t *testing.T) {
	oldRules, err := decodeFirewall(t, "allow:\n  - tcp: [22, 80]\n  - udp: 51820\n")
	if err != nil {
		t.Fatal(err)
	}
	old := oldRules.render(oldRules.id())
	tests := []struct {
		name  string
		allow string
		old   []byte
		want  []string
	}{
		{"new file", "- tcp: 22", nil, []string{"add tcp 22"}},
		{"same rules", "- tcp: [22, 80]\n- udp: 51820", old, nil},
		{"add and remove", "- tcp: [22, 80]\n- tcp: 5432\n  from: 10.0.0.0/8", old, []string{"add tcp 5432 from 10.0.0.0/8", "remove udp 51820"}},
		{"a port more", "- tcp: [22, 80, 443]\n- udp: 51820", old, []string{"add tcp 22, 80, 443", "remove tcp 22, 80"}},
		{"a file of another writer", "- tcp: 22", []byte("table inet winch {\n}\n"), []string{"add tcp 22"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := decodeFirewall(t, "allow:\n"+indent(tt.allow))
			if err != nil {
				t.Fatal(err)
			}
			if got := f.ruleChanges(tt.old); !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
