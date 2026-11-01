package module

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Firewall struct {
	Allow  []Rule `yaml:"allow" json:"allow,omitempty" line:"accepted traffic; the host drops the rest" doc:"Accepted traffic; the host drops the rest. It always accepts established and related traffic, loopback, ICMP echo requests, the ICMPv6 types that IPv6 needs, and DHCP replies. It drops invalid packets."`
	Absent bool   `yaml:"absent" json:"absent,omitempty" line:"remove the table, its file, and its unit" doc:"Remove the table, its file, and its unit."`
	// What the check found to do.
	data                                      []byte
	writeFile, writeUnit, writeDropIn, enable bool
	load, stop, reload, deleteTable           bool
}

func (*Firewall) Noun() string { return "a firewall step" }

// Rule accepts traffic to its ports from the sources in From, or from every
// source.
type Rule struct {
	TCP  yamlx.Ints    `yaml:"tcp" json:"tcp,omitempty" line:"ports" doc:"Ports. A rule has tcp or udp."`
	UDP  yamlx.Ints    `yaml:"udp" json:"udp,omitempty" line:"ports" doc:"Ports. A rule has tcp or udp."`
	From yamlx.Strings `yaml:"from" json:"from,omitempty" line:"source addresses or networks" doc:"Source addresses or networks. IPv4 and IPv6 are allowed. Without from, the rule accepts every source."`
}

const (
	firewallFile   = "/etc/winch/firewall.nft"
	FirewallUnit   = "winch-firewall.service"
	firewallUnitP  = unitDir + "/" + FirewallUnit
	firewallWants  = unitDir + "/sysinit.target.wants/" + FirewallUnit
	firewallDropIn = unitDir + "/nftables.service.d/winch.conf"
	// firewallList is the listing that nft made of the table after the last
	// load, so the check finds a rule that someone changed by hand.
	firewallList = "/var/lib/winch/firewall.list"
)

var firewallPaths = []string{firewallFile, firewallUnitP, firewallWants, firewallDropIn}

// firewallUnitText loads the rules at boot, also when nftables.service is
// disabled.
const firewallUnitText = `[Unit]
Description=winch firewall
Wants=network-pre.target
Before=network-pre.target shutdown.target
After=nftables.service
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ` + firewallFile + `

[Install]
WantedBy=sysinit.target
`

// firewallDropInText loads the rules inside every start, restart, and reload
// of nftables.service, which flush the whole rule set.
const firewallDropInText = `[Service]
ExecStartPost=/usr/sbin/nft -f ` + firewallFile + `
ExecReload=/usr/sbin/nft -f ` + firewallFile + `
`

func (f *Firewall) Main() string { return "" }

func (f *Firewall) Validate() error {
	if f.Absent {
		return absentTakesNone(arg{"allow", f.Allow != nil})
	}
	if f.Allow == nil {
		return &yamlx.FieldError{Msg: "a firewall step needs allow, or absent: true"}
	}
	return nil
}

func (r *Rule) Validate() error {
	switch {
	case r.TCP != nil && r.UDP != nil:
		return &yamlx.FieldError{At: "udp", Msg: "a rule has at most one of tcp and udp"}
	case r.TCP == nil && r.UDP == nil:
		return errors.New("a rule needs tcp or udp")
	}
	proto, ports := r.ports()
	if len(ports) == 0 {
		return &yamlx.FieldError{Field: proto, Msg: "needs a port"}
	}
	for i, p := range ports {
		if p < 1 || p > 65535 {
			return &yamlx.FieldError{Field: proto, Msg: fmt.Sprintf("port %d is not between 1 and 65535", p)}
		}
		if slices.Contains(ports[:i], p) {
			return &yamlx.FieldError{Field: proto, Msg: fmt.Sprintf("port %d is in the list twice", p)}
		}
	}
	if r.From != nil && len(r.From) == 0 {
		return &yamlx.FieldError{Field: "from", Msg: "needs an address or a network"}
	}
	var seen []netip.Prefix
	for _, s := range r.From {
		p, err := parseSource(s)
		if err != nil {
			return &yamlx.FieldError{Field: "from", Msg: err.Error()}
		}
		if slices.Contains(seen, p) {
			return &yamlx.FieldError{Field: "from", Msg: sourceText(p) + " is in the list twice"}
		}
		seen = append(seen, p)
	}
	return nil
}

func (r *Rule) ports() (string, []int) {
	if r.TCP != nil {
		return "tcp", r.TCP
	}
	return "udp", r.UDP
}

// parseSource returns an address of From as a prefix of its full length.
func parseSource(s string) (netip.Prefix, error) {
	bad := fmt.Errorf("%q is not an IPv4 or IPv6 address or network", s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, bad
		}
		if p != p.Masked() {
			return netip.Prefix{}, fmt.Errorf("%s has bits set after the prefix; write %s", s, p.Masked())
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, bad
	}
	// nft matches such an address only in IPv6 packets.
	if a.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%s is an IPv4 address in IPv6 form; write %s", s, a.Unmap())
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func sourceText(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// sources returns From, which Validate checked.
func (r *Rule) sources() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range r.From {
		p, _ := parseSource(s)
		out = append(out, p)
	}
	return out
}

// text is the rule as the plan shows it: tcp 5432 from 10.0.0.0/8.
func (r *Rule) text() string {
	proto, ports := r.ports()
	s := proto + " " + strings.Join(portTexts(ports), ", ")
	if r.From == nil {
		return s
	}
	var from []string
	for _, p := range r.sources() {
		from = append(from, sourceText(p))
	}
	return s + " from " + strings.Join(from, ", ")
}

func portTexts(ports []int) []string {
	var out []string
	for _, p := range ports {
		out = append(out, strconv.Itoa(p))
	}
	return out
}

// set is one value, or an anonymous set of nft.
func set(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "{ " + strings.Join(values, ", ") + " }"
}

// render returns the file of the table. The comment holds id. The file
// replaces the table in one transaction: it creates the table when it is
// missing, deletes it, and creates it again.
func (f *Firewall) render(id string) []byte {
	var b strings.Builder
	b.WriteString("# winch writes this file from the firewall step.\n")
	for _, r := range f.Allow {
		b.WriteString(allowPrefix + r.text() + "\n")
	}
	b.WriteString("table inet winch\ndelete table inet winch\ntable inet winch {\n")
	if id != "" {
		fmt.Fprintf(&b, "\tcomment %q\n", id)
	}
	b.WriteString(`	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		icmp type echo-request accept
		icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, packet-too-big } accept
		udp sport 67 udp dport 68 accept
		udp sport 547 udp dport 546 accept
`)
	for _, r := range f.Allow {
		proto, ports := r.ports()
		match := proto + " dport " + set(portTexts(ports)) + " accept\n"
		if r.From == nil {
			b.WriteString("\t\t" + match)
			continue
		}
		var v4, v6 []string
		for _, p := range r.sources() {
			if p.Addr().Is4() {
				v4 = append(v4, sourceText(p))
			} else {
				v6 = append(v6, sourceText(p))
			}
		}
		if v4 != nil {
			b.WriteString("\t\tip saddr " + set(v4) + " " + match)
		}
		if v6 != nil {
			b.WriteString("\t\tip6 saddr " + set(v6) + " " + match)
		}
	}
	b.WriteString("\t}\n}\n")
	return []byte(b.String())
}

const allowPrefix = "# allow "

// id identifies the rules in the comment of the loaded table: the hash of
// the file without the comment.
func (f *Firewall) id() string { return sha(f.render(""))[:16] }

// checkSSH fails when no rule accepts the session's SSH port from the
// session's client address. conn is the SSH_CONNECTION of the session.
func (f *Firewall) checkSSH(conn string) error {
	if conn == "" {
		return nil
	}
	fields := strings.Fields(conn)
	if len(fields) != 4 {
		return fmt.Errorf("SSH_CONNECTION %q is not a client address and port and a local address and port", conn)
	}
	client, err := netip.ParseAddr(fields[0])
	if err != nil {
		return fmt.Errorf("SSH_CONNECTION %q: %w", conn, err)
	}
	client = client.Unmap()
	port, err := strconv.Atoi(fields[3])
	if err != nil {
		return fmt.Errorf("SSH_CONNECTION %q: %w", conn, err)
	}
	// The table accepts loopback, such as a session through a tunnel.
	if client.IsLoopback() {
		return nil
	}
	fix := fmt.Sprintf("add a rule with tcp: %d", port)
	for _, r := range f.Allow {
		if !slices.Contains(r.TCP, port) {
			continue
		}
		if r.From == nil || slices.ContainsFunc(r.sources(), func(p netip.Prefix) bool { return p.Contains(client) }) {
			return nil
		}
		fix = fmt.Sprintf("add %s to from in the rule with tcp: %d", client, port)
	}
	return fmt.Errorf("no rule accepts TCP port %d from %s, the address that winch connects from; %s", port, client, fix)
}

// ruleChanges lists the rules that the step adds to the file old, and the
// rules of old that it removes.
func (f *Firewall) ruleChanges(old []byte) []string {
	var had []string
	for line := range strings.Lines(string(old)) {
		if !strings.HasPrefix(line, "#") {
			break
		}
		if r, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), allowPrefix); ok {
			had = append(had, r)
		}
	}
	var lines, have []string
	for _, r := range f.Allow {
		t := r.text()
		have = append(have, t)
		if !slices.Contains(had, t) {
			lines = append(lines, "add "+t)
		}
	}
	for _, t := range had {
		if !slices.Contains(have, t) {
			lines = append(lines, "remove "+t)
		}
	}
	return lines
}

// loadedTable reports whether nft has the table inet winch, and its comment.
// Without nft, there is no table.
func loadedTable(ctx context.Context) (exists bool, comment string, err error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return false, "", nil
	}
	out, err := run(ctx, nil, "nft", "-j", "list", "tables", "inet")
	if err != nil {
		return false, "", err
	}
	var list struct {
		Nftables []struct {
			Table *struct {
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return false, "", fmt.Errorf("read the output of nft list tables: %w", err)
	}
	for _, e := range list.Nftables {
		if e.Table != nil && e.Table.Name == "winch" {
			return true, e.Table.Comment, nil
		}
	}
	return false, "", nil
}

func (f *Firewall) Check(ctx context.Context, st *State, say Say) (Result, error) {
	if f.Absent {
		return f.checkAbsent(ctx)
	}
	if err := f.checkSSH(st.SSHConnection); err != nil {
		return Result{}, err
	}
	if err := sayDroppingTables(ctx, say); err != nil {
		return Result{}, err
	}
	id := f.id()
	f.data = f.render(id)
	file, lines, err := checkRepoFile(firewallFile, f.data)
	if err != nil {
		return Result{}, err
	}
	var changes []string
	if file.fi == nil || !bytes.Equal(file.old, f.data) {
		changes = f.ruleChanges(file.old)
		if file.fi != nil && changes == nil {
			changes = []string{"rewrite " + firewallFile}
		}
	}
	changes = append(changes, lines...)
	f.writeFile = changes != nil
	unit, lines, err := checkRepoFile(firewallUnitP, []byte(firewallUnitText))
	if err != nil {
		return Result{}, err
	}
	if unit.fi != nil && string(unit.old) != firewallUnitText {
		lines = append([]string{"rewrite " + firewallUnitP}, lines...)
	}
	f.writeUnit = lines != nil
	changes = append(changes, lines...)
	dropIn, lines, err := checkRepoFile(firewallDropIn, []byte(firewallDropInText))
	if err != nil {
		return Result{}, err
	}
	if dropIn.fi != nil && string(dropIn.old) != firewallDropInText {
		lines = append([]string{"rewrite " + firewallDropIn}, lines...)
	}
	f.writeDropIn = lines != nil
	changes = append(changes, lines...)
	if f.writeUnit || f.writeDropIn {
		changes = append(changes, "daemon-reload")
	}
	if _, err := os.Lstat(firewallWants); errors.Is(err, fs.ErrNotExist) {
		f.enable = true
		changes = append(changes, "enable "+FirewallUnit)
	} else if err != nil {
		return Result{}, err
	}
	if f.load, err = tableStale(ctx, id); err != nil {
		return Result{}, err
	}
	if f.load {
		changes = append(changes, "load the rules")
	}
	if changes == nil {
		return Result{Status: OK}, nil
	}
	action := Modify
	if file.fi == nil {
		action = Create
	}
	res := Result{Status: Change, Action: action, Changes: changes, Guard: true}
	if _, err := exec.LookPath("nft"); err != nil {
		res.MissingTools = []Tool{{Name: "nft", Package: "nftables"}}
	}
	return res, nil
}

func sayDroppingTables(ctx context.Context, say Say) error {
	tables, err := droppingTables(ctx)
	if err != nil {
		return err
	}
	for _, t := range tables {
		say.Note("the table " + t + " also filters input, and its rules can drop what this step allows")
	}
	return nil
}

// droppingTables returns the tables other than inet winch with an input base
// chain whose policy or rules drop packets, once for each drop. nftables passes a packet only when
// every input chain accepts it. Without nft, there are no tables.
func droppingTables(ctx context.Context) ([]string, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, nil
	}
	out, err := run(ctx, nil, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	var list struct {
		Nftables []struct {
			Chain *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Hook   string `json:"hook"`
				Policy string `json:"policy"`
			} `json:"chain"`
			Rule *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Chain  string `json:"chain"`
				Expr   any    `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("read the output of nft list ruleset: %w", err)
	}
	input := map[[3]string]bool{}
	var tables []string
	for _, e := range list.Nftables {
		c := e.Chain
		if c == nil || c.Hook != "input" || c.Family == "inet" && c.Table == "winch" {
			continue
		}
		switch c.Family {
		case "ip", "ip6", "inet":
		default:
			continue
		}
		input[[3]string{c.Family, c.Table, c.Name}] = true
		if c.Policy == "drop" {
			tables = append(tables, c.Family+" "+c.Table)
		}
	}
	for _, e := range list.Nftables {
		if r := e.Rule; r != nil && input[[3]string{r.Family, r.Table, r.Chain}] && hasDrop(r.Expr) {
			tables = append(tables, r.Family+" "+r.Table)
		}
	}
	return tables, nil
}

// hasDrop reports whether the JSON expression v of a rule holds the verdict
// drop, also inside a verdict map.
func hasDrop(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if k == "drop" || hasDrop(x) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, hasDrop)
	}
	return false
}

// tableStale reports whether the table on the host is missing, holds the
// rules of another file, or differs from the listing of its last load.
func tableStale(ctx context.Context, id string) (bool, error) {
	_, comment, err := loadedTable(ctx)
	if err != nil || comment != id {
		return true, err
	}
	saved, err := os.ReadFile(firewallList)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	live, err := listTable(ctx)
	if err != nil {
		return false, err
	}
	return live != string(saved), nil
}

// listTable returns the listing that nft makes of the table inet winch.
func listTable(ctx context.Context) (string, error) {
	return run(ctx, nil, "nft", "list", "table", "inet", "winch")
}

func (f *Firewall) checkAbsent(ctx context.Context) (Result, error) {
	var changes []string
	u, err := showUnit(ctx, FirewallUnit)
	if err != nil {
		return Result{}, err
	}
	if f.stop = u.up(); f.stop {
		changes = append(changes, "stop "+FirewallUnit)
	}
	for _, p := range []struct{ path, change string }{
		{firewallWants, "disable " + FirewallUnit},
		{firewallUnitP, "remove " + firewallUnitP},
		{firewallDropIn, "remove " + firewallDropIn},
		{firewallFile, "remove " + firewallFile},
	} {
		_, err := os.Lstat(p.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Result{}, err
		}
		changes = append(changes, p.change)
		if p.path != firewallFile {
			f.reload = true
		}
	}
	if f.reload {
		changes = append(changes, "daemon-reload")
	}
	if f.deleteTable, _, err = loadedTable(ctx); err != nil {
		return Result{}, err
	}
	if f.deleteTable {
		changes = append(changes, "remove the table inet winch")
	}
	if changes == nil {
		return Result{Status: OK}, nil
	}
	return Result{Status: Change, Action: Remove, Changes: changes, Guard: true}, nil
}

func (f *Firewall) Apply(ctx context.Context, _ Say) error {
	if f.Absent {
		return f.applyAbsent(ctx)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nft is missing; install the package nftables in an earlier pkg step")
	}
	if f.writeFile {
		if err := writeRoot(firewallFile, f.data, 0, 0, 0o644); err != nil {
			return err
		}
	}
	if f.writeUnit {
		if err := writeRoot(firewallUnitP, []byte(firewallUnitText), 0, 0, 0o644); err != nil {
			return err
		}
	}
	if f.writeDropIn {
		if err := writeRoot(firewallDropIn, []byte(firewallDropInText), 0, 0, 0o644); err != nil {
			return err
		}
	}
	// systemctl enable reloads the units itself.
	if (f.writeUnit || f.writeDropIn) && !f.enable {
		if _, err := run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if f.enable {
		if _, err := run(ctx, nil, "systemctl", "enable", "--", FirewallUnit); err != nil {
			return err
		}
	}
	if f.load {
		return loadFirewall(ctx)
	}
	return nil
}

func (f *Firewall) applyAbsent(ctx context.Context) error {
	if f.stop {
		if _, err := run(ctx, nil, "systemctl", "stop", "--", FirewallUnit); err != nil {
			return err
		}
	}
	for _, p := range []string{firewallWants, firewallUnitP, firewallDropIn, firewallFile} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if f.reload {
		if _, err := run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if f.deleteTable {
		return loadFirewall(ctx)
	}
	return nil
}

// loadFirewall loads the rules of the firewall file and keeps their listing,
// or removes the table and the listing when there is no file. Without nft,
// there is no table.
func loadFirewall(ctx context.Context) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil
	}
	_, err := os.Stat(firewallFile)
	if errors.Is(err, fs.ErrNotExist) {
		if _, err := runInput(ctx, nil, "table inet winch\ndelete table inet winch\n", "nft", "-f", "-"); err != nil {
			return err
		}
		if err := os.Remove(firewallList); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := run(ctx, nil, "nft", "-f", firewallFile); err != nil {
		return err
	}
	out, err := listTable(ctx)
	if err != nil {
		return err
	}
	return writeRoot(firewallList, []byte(out), 0, 0, 0o644)
}

// loadsFirewall reports whether a restore of saved puts back the firewall
// file, so the rules must load again.
func loadsFirewall(saved []Saved) bool {
	return slices.ContainsFunc(saved, func(s Saved) bool {
		return s.Path == firewallFile || strings.HasPrefix(firewallFile, s.Path+"/") && s.Dir == nil
	})
}

func (f *Firewall) Writes() []string {
	if f.Absent {
		return nil
	}
	return firewallPaths
}
