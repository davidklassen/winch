package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/firewall
func TestFirewallModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "firewall2")
	dir := vmtest.WriteProject(t, map[string]string{})
	project := func(steps string) {
		t.Helper()
		data := "name: fw\nhosts:\n  firewall2: {}\nsteps:\n  - pkg:\n      name: nftables\n" + steps
		if err := os.WriteFile(filepath.Join(dir, "winch.yaml"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	firewall := "  - firewall:\n      allow:\n"
	table := "nft list table inet winch"

	// Create.
	project(firewall + "        - tcp: 22\n")
	r := lab.Winch(t, dir, "plan")
	if r.Code != 0 || !strings.Contains(r.Stdout, "+ firewall\n        add tcp 22\n        create directory /etc/winch") || !strings.Contains(r.Stdout, "enable winch-firewall.service\n        load the rules\n") {
		t.Fatalf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if r := lab.Winch(t, dir, "apply", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if out := vm.MustRun(t, table); !strings.Contains(out, "policy drop;") || !strings.Contains(out, "tcp dport 22 accept") {
		t.Fatalf("the table after apply:\n%s", out)
	}
	if out := vm.MustRun(t, "systemctl is-enabled winch-firewall.service"); out != "enabled\n" {
		t.Errorf("winch-firewall.service: %q", out)
	}
	if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	// The tables of other programs, such as fail2ban and Docker, stay.
	others := "nft add table inet f2b-table && nft add chain inet f2b-table f2b-chain '{ type filter hook input priority -1; }' && " +
		"nft add table ip filter && nft add chain ip filter DOCKER-FORWARD '{ type filter hook forward priority 0; policy accept; }'"
	vm.MustRun(t, others)

	// Change.
	project(firewall + "        - tcp: [22, 80]\n        - udp: 51820\n          from: [10.0.0.0/8, 2001:db8::/32]\n")
	r = lab.Winch(t, dir, "apply", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ firewall\n        add tcp 22, 80\n        add udp 51820 from 10.0.0.0/8, 2001:db8::/32\n        remove tcp 22\n        load the rules\n") {
		t.Fatalf("apply of a change: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	out := vm.MustRun(t, table)
	if !strings.Contains(out, "tcp dport { 22, 80 } accept") || !strings.Contains(out, "ip saddr 10.0.0.0/8 udp dport 51820 accept") || !strings.Contains(out, "ip6 saddr 2001:db8::/32 udp dport 51820 accept") {
		t.Errorf("the table after the change:\n%s", out)
	}
	if out := vm.MustRun(t, "nft list tables"); !strings.Contains(out, "table inet f2b-table\n") || !strings.Contains(out, "table ip filter\n") {
		t.Errorf("the tables of fail2ban and Docker are gone:\n%s", out)
	}
	if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after the change: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	// A table that is gone, and a file that changed by hand, come back.
	vm.MustRun(t, "nft delete table inet winch && sed -i 's/accept/drop/' /etc/winch/firewall.nft")
	r = lab.Winch(t, dir, "apply", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ firewall\n        rewrite /etc/winch/firewall.nft\n        load the rules\n") {
		t.Fatalf("apply after the changes by hand: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if out := vm.MustRun(t, table); !strings.Contains(out, "tcp dport { 22, 80 } accept") {
		t.Errorf("the table after the repair:\n%s", out)
	}
	if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after the repair: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	// The rules close the session's SSH port.
	project(firewall + "        - tcp: 80\n")
	r = lab.Winch(t, dir, "plan")
	if r.Code != 1 || !strings.Contains(r.Stderr, "firewall: the rules close the SSH port 22 that winch uses") {
		t.Errorf("plan that closes SSH: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	// A rule set whose access check fails rolls back. A second table drops
	// new SSH connections for 50 seconds, as rules that close the path of the
	// access check do.
	project("  - cmd:\n      command: |\n        nft add table inet block\n        nft add chain inet block input '{ type filter hook input priority -10; }'\n        nft add rule inet block input tcp dport 22 ct state new drop\n        systemd-run --on-active=50 nft delete table inet block\n" +
		firewall + "        - tcp: [22, 443]\n")
	r = lab.Winch(t, dir, "apply", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stderr, "failed: firewall: no new SSH connection works: ") || !strings.HasSuffix(r.Stderr, "; the old files are back\n") || strings.Contains(r.Stderr, "the rollback failed") {
		t.Fatalf("apply with a failed access check: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for {
		out, err := vm.Run(ctx, table+" && cat /etc/winch/firewall.nft")
		if err == nil {
			if !strings.Contains(out, "tcp dport { 22, 80 } accept") || strings.Contains(out, "443") {
				t.Errorf("the old rules are not back:\n%s", out)
			}
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("the VM does not answer after the rollback: %v", err)
		}
		time.Sleep(2 * time.Second)
	}

	// The table survives a reboot, also after nftables.service, which
	// flushes the rule set.
	project(firewall + "        - tcp: [22, 80]\n        - udp: 51820\n          from: [10.0.0.0/8, 2001:db8::/32]\n" +
		"  - service:\n      name: nftables\n      enabled: true\n  - reboot:\n      if_required: false\n")
	if r := lab.Winch(t, dir, "apply", "--yes"); r.Code != 0 {
		t.Fatalf("apply with a reboot: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if out := vm.MustRun(t, "nft list tables"); !strings.Contains(out, "table inet filter\n") || !strings.Contains(out, "table inet winch\n") {
		t.Errorf("the tables after the reboot:\n%s", out)
	}
	if out := vm.MustRun(t, table); !strings.Contains(out, "tcp dport { 22, 80 } accept") {
		t.Errorf("the table after the reboot:\n%s", out)
	}
	project(firewall + "        - tcp: [22, 80]\n        - udp: 51820\n          from: [10.0.0.0/8, 2001:db8::/32]\n" +
		"  - service:\n      name: nftables\n      enabled: true\n")
	if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after the reboot: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	// Remove.
	project("  - firewall:\n      absent: true\n")
	vm.MustRun(t, others)
	r = lab.Winch(t, dir, "apply", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "- firewall\n") {
		t.Fatalf("apply of absent: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if out := vm.MustRun(t, "nft list tables; ls /etc/winch /etc/systemd/system/winch-firewall.service /etc/systemd/system/sysinit.target.wants/winch-firewall.service 2>&1 || true"); strings.Contains(out, "inet winch") || !strings.Contains(out, "inet f2b-table") || !strings.Contains(out, "ip filter") || strings.Contains(out, "firewall.nft") || strings.Count(out, "No such file") != 2 {
		t.Errorf("after absent:\n%s", out)
	}
	if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after absent: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}
