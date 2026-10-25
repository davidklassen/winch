package integration

import (
	"strings"
	"testing"
)

func TestDemo(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "demo")
	vm.MustRun(t, quietApt)
	dir := "../../examples/demo"

	r := lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	for path, want := range map[string]string{
		"/":           `<li><a href="/contact">Contact</a></li>`,
		"/about":      "<h1>About</h1>",
		"/contact":    "webmaster@example.com",
		"/robots.txt": "Disallow: /",
	} {
		// Without Debian's default site, a request without a Host header
		// reaches the site.
		if out := vm.MustRun(t, "curl -s http://localhost"+path); !strings.Contains(out, want) {
			t.Errorf("page %s = %q, want %q in it", path, out, want)
		}
	}

	if out := vm.MustRun(t, "stat -c '%a %G' /var/www/example.com"); out != "750 www-data\n" {
		t.Errorf("site directory: %q, want mode 750 and group www-data", out)
	}
	if out := vm.MustRun(t, "cat /etc/motd"); out != "demo is managed by winch.\n" {
		t.Errorf("/etc/motd = %q", out)
	}

	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || r.Stdout != "1 host: 0 to change, 1 unchanged, 0 unknown\n" {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
