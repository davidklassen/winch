package integration

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// spec: roadmap: Testing/VMs
func TestLab(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "lab")

	t.Run("the clock is the time of the Mac", func(t *testing.T) {
		out := vm.MustRun(t, "date +%s.%N")
		sec, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(time.Unix(0, int64(sec*1e9))).Abs(); d > 2*time.Second {
			t.Errorf("the VM's clock is %s away from the Mac's", d)
		}
	})

	t.Run("the apt timers are disabled, and no apt run is active", func(t *testing.T) {
		out := vm.MustRun(t, "systemctl list-unit-files --no-legend 'apt-*.timer' | awk '{print $2}' | sort -u; systemctl list-units --no-legend --state=active,activating 'apt-*'; true")
		if out != "disabled\n" {
			t.Errorf("the states of the apt timers, and the active apt units: %q, want %q", out, "disabled\n")
		}
	})

	t.Run("the VM resolves its own host name at once", func(t *testing.T) {
		out := vm.MustRun(t, `python3 -c 'import socket, time; t = time.monotonic(); socket.getfqdn(); print(time.monotonic() - t)'`)
		sec, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
		if err != nil {
			t.Fatal(err)
		}
		if sec > 5 {
			t.Errorf("the lookup of the host name takes %.1fs", sec)
		}
	})

	if lab.Online() {
		t.Run("online, apt reads the image's sources and the test packages", func(t *testing.T) {
			out := vm.MustRun(t, "apt-get update")
			if !strings.Contains(out, "10.0.2.100/test") {
				t.Errorf("apt-get update does not read the test packages:\n%s", out)
			}
			image := false
			for line := range strings.SplitSeq(out, "\n") {
				if (strings.HasPrefix(line, "Hit:") || strings.HasPrefix(line, "Get:")) && !strings.Contains(line, "10.0.2.100") {
					image = true
				}
			}
			if !image {
				t.Errorf("apt-get update does not read the image's sources:\n%s", out)
			}
			if strings.Contains(out, "10.0.2.100/debian") {
				t.Errorf("apt-get update reads the local Debian packages:\n%s", out)
			}
		})
		return
	}

	t.Run("offline, the VM has no internet", func(t *testing.T) {
		// curl exits 6 when it cannot resolve the name, 7 when it cannot
		// connect, and 28 on the timeout.
		for _, url := range []string{"http://deb.debian.org/debian/", "http://151.101.2.132/"} {
			out := vm.MustRun(t, "curl -s -m 5 -o /dev/null "+url+"; echo $?")
			if out != "6\n" && out != "7\n" && out != "28\n" {
				t.Errorf("curl %s: %q, want exit 6, 7, or 28", url, out)
			}
		}
	})
	t.Run("offline, the local repository is the only apt source", func(t *testing.T) {
		out := vm.MustRun(t, "apt-get update")
		for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
			if strings.HasPrefix(line, "Get:") || strings.HasPrefix(line, "Hit:") || strings.HasPrefix(line, "Ign:") || strings.HasPrefix(line, "Err:") {
				if !strings.Contains(line, "http://10.0.2.100/") {
					t.Errorf("apt-get update reads another source: %s", line)
				}
			}
		}
		vm.MustRun(t, "apt-cache show nginx winch-conflict >/dev/null")
	})
	t.Run("offline, a package that the list does not name fails and names the list", func(t *testing.T) {
		_, err := vm.Run(t.Context(), "apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q cowsay")
		if err == nil || !strings.Contains(err.Error(), "test/repo/debian.list") {
			t.Errorf("error = %v, want the list test/repo/debian.list in it", err)
		}
	})
}

// spec: roadmap: Testing/VMs
func TestLabReboot(t *testing.T) {
	t.Parallel()
	if lab.Online() {
		t.Skip("online, DHCP gives the VM a gateway and DNS")
	}
	vm := lab.StartVM(t, "labreboot")
	// In CI, the router adverts of QEMU give the VM no gateway and no DNS.
	// The file sorts before netplan's, so networkd uses it.
	vm.MustRun(t, `printf '[Match]\nName=e*\n[Network]\nDHCP=ipv4\nIPv6AcceptRA=no\n' > /etc/systemd/network/00-no-ra.network`)
	before := vm.MustRun(t, "cat /proc/sys/kernel/random/boot_id")
	vm.MustRun(t, "systemd-run --on-active=1 systemctl reboot")
	start := time.Now()
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		out, err := vm.Run(ctx, "cat /proc/sys/kernel/random/boot_id")
		cancel()
		if err == nil && out != before {
			break
		}
		if d := time.Since(start); d > 5*time.Minute {
			t.Fatalf("the VM is not back %s after the reboot", d.Round(time.Second))
		}
		time.Sleep(time.Second)
	}
	if out := vm.MustRun(t, "networkctl status -n0 | grep -E 'Gateway:|DNS:' || true"); out != "" {
		t.Errorf("the VM has a gateway or DNS after the reboot:\n%s", out)
	}
	// A boot of Ubuntu 24.04 takes most of a minute on a loaded Mac, so the
	// test measures the wait itself, not the reboot.
	var result string
	var exit, enter int64
	out := vm.MustRun(t, "systemctl show -p Result -p InactiveExitTimestampMonotonic -p ActiveEnterTimestampMonotonic systemd-networkd-wait-online")
	for line := range strings.Lines(out) {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "Result":
			result = v
		case "InactiveExitTimestampMonotonic":
			exit, _ = strconv.ParseInt(v, 10, 64)
		case "ActiveEnterTimestampMonotonic":
			enter, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if result != "success" {
		t.Fatalf("systemd-networkd-wait-online: result %s, want success", result)
	}
	if d := time.Duration(enter-exit) * time.Microsecond; exit == 0 || d <= 0 || d > 30*time.Second {
		t.Errorf("systemd-networkd-wait-online took %s, want at most 30s", d)
	}
}
