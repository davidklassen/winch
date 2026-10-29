package integration

import (
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
