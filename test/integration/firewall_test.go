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

	// Without nft and a pkg step for nftables, the plan notes the package.
	vm.MustRun(t, "[ ! -e /usr/sbin/nft ] || mv /usr/sbin/nft /usr/sbin/nft.off")
	if err := os.WriteFile(filepath.Join(dir, "winch.yaml"), []byte("name: fw\nhosts:\n  firewall2: {}\nsteps:\n"+firewall+"        - tcp: 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !strings.Contains(r.Stderr, "firewall2: nft is missing and no pkg step installs nftables\n") {
		t.Fatalf("plan without nftables: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "[ ! -e /usr/sbin/nft.off ] || mv /usr/sbin/nft.off /usr/sbin/nft")

	// Create.
	project(firewall + "        - tcp: 22\n")
	r := lab.Winch(t, dir, "plan")
	if r.Code != 0 || strings.Contains(r.Stderr, "nft is missing") || !strings.Contains(r.Stdout, "+ firewall\n        add tcp 22\n        create directory /etc/winch") || !strings.Contains(r.Stdout, "create file /etc/systemd/system/nftables.service.d/winch.conf") || !strings.Contains(r.Stdout, "enable winch-firewall.service\n        load the rules\n\n") {
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

	// The built-in rules accept DHCP replies.
	if out := vm.MustRun(t, table); !strings.Contains(out, "udp sport 67 udp dport 68 accept") || !strings.Contains(out, "udp sport 547 udp dport 546 accept") {
		t.Errorf("no DHCP rules in the table:\n%s", out)
	}

	// A rule added by hand, and a chain flushed by hand, show as a change.
	for _, edit := range []string{"nft add rule inet winch input tcp dport 6379 accept", "nft flush chain inet winch input && nft add rule inet winch input tcp dport 22 accept"} {
		vm.MustRun(t, edit)
		r = lab.Winch(t, dir, "apply", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "~ firewall\n        load the rules\n") {
			t.Fatalf("apply after %s: exit %d, stdout %q, stderr %q", edit, r.Code, r.Stdout, r.Stderr)
		}
		if out := vm.MustRun(t, table); strings.Contains(out, "6379") || !strings.Contains(out, "tcp dport { 22, 80 } accept") {
			t.Errorf("the table after %s and apply:\n%s", edit, out)
		}
		if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("plan after %s and apply: exit %d, stdout %q, stderr %q", edit, r.Code, r.Stdout, r.Stderr)
		}
	}

	// A start, restart, or reload of nftables.service, which flushes the rule
	// set, keeps the table. The restart comes first: it starts
	// nftables.service, and a reload needs an active unit.
	for _, cmd := range []string{"systemctl restart nftables", "systemctl reload nftables", "systemctl stop nftables && systemctl start nftables"} {
		vm.MustRun(t, cmd)
		if out := vm.MustRun(t, "nft list tables"); !strings.Contains(out, "table inet winch\n") {
			t.Errorf("the tables after %s:\n%s", cmd, out)
		}
		if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("plan after %s: exit %d, stdout %q, stderr %q", cmd, r.Code, r.Stdout, r.Stderr)
		}
	}

	// A drop-in that changed by hand comes back.
	vm.MustRun(t, "sed -i /ExecStartPost/d /etc/systemd/system/nftables.service.d/winch.conf")
	r = lab.Winch(t, dir, "apply", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "~ firewall\n        rewrite /etc/systemd/system/nftables.service.d/winch.conf\n") || !strings.Contains(r.Stdout, "daemon-reload\n") {
		t.Errorf("apply after a change of the drop-in: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "systemctl stop nftables && systemctl start nftables")
	if out := vm.MustRun(t, "nft list tables"); !strings.Contains(out, "table inet winch\n") {
		t.Errorf("the tables after the repair of the drop-in and a start of nftables:\n%s", out)
	}

	// Another step on the firewall file fails the plan.
	project(firewall + "        - tcp: [22, 80]\n        - udp: 51820\n          from: [10.0.0.0/8, 2001:db8::/32]\n" +
		"  - file:\n      path: /etc/winch/firewall.nft\n      content: \"\"\n")
	r = lab.Winch(t, dir, "plan")
	if r.Code != 1 || !strings.Contains(r.Stderr, "file /etc/winch/firewall.nft: the path /etc/winch/firewall.nft is also in ") {
		t.Errorf("plan with a file step on the firewall file: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	// A service step on the unit of the firewall fails the plan.
	project(firewall + "        - tcp: [22, 80]\n        - udp: 51820\n          from: [10.0.0.0/8, 2001:db8::/32]\n" +
		"  - service:\n      name: winch-firewall\n      running: false\n")
	r = lab.Winch(t, dir, "plan")
	if r.Code != 1 || !strings.Contains(r.Stderr, "service winch-firewall: the unit winch-firewall.service is also in ") {
		t.Errorf("plan with a service step on the firewall unit: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	// The rules close the session's SSH port.
	project(firewall + "        - tcp: 80\n")
	r = lab.Winch(t, dir, "plan")
	if r.Code != 1 || !strings.Contains(r.Stderr, "firewall: the rules close the SSH port 22 that winch uses") {
		t.Errorf("plan that closes SSH: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}

	// A rule set whose access check fails rolls back. A second table drops
	// new SSH connections for 60 seconds, as rules that close the path of the
	// access check do. The timeout of the set element ends the drop on time;
	// a systemd timer can elapse a minute late.
	project("  - cmd:\n      command: |\n        nft add table inet block\n        nft add set inet block ssh '{ type inet_service; timeout 60s; elements = { 22 }; }'\n        nft add chain inet block input '{ type filter hook input priority -10; }'\n        nft add rule inet block input tcp dport @ssh ct state new drop\n" +
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
	if r.Code != 0 || !strings.Contains(r.Stdout, "- firewall\n        stop winch-firewall.service\n") {
		t.Fatalf("apply of absent: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	if out := vm.MustRun(t, "nft list tables; ls /etc/winch /etc/systemd/system/winch-firewall.service /etc/systemd/system/sysinit.target.wants/winch-firewall.service /etc/systemd/system/nftables.service.d/winch.conf 2>&1 || true"); strings.Contains(out, "inet winch") || !strings.Contains(out, "inet f2b-table") || !strings.Contains(out, "ip filter") || strings.Contains(out, "firewall.nft") || strings.Count(out, "No such file") != 3 {
		t.Errorf("after absent:\n%s", out)
	}
	if out := vm.MustRun(t, "systemctl is-active winch-firewall.service || true"); out != "inactive\n" {
		t.Errorf("winch-firewall.service after absent: %q", out)
	}
	if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after absent: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	// Without the drop-in, nftables.service does not load the removed file.
	vm.MustRun(t, "systemctl restart nftables")
}
