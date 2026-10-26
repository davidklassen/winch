package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

// demoPassword is the password of the demo's /private page, and demoKeyLine
// a line of the demo's DKIM key. No output of winch may hold them.
const (
	demoPassword = "demo-basic-auth-pw"
	demoKeyLine  = "NgIwR5awfpE4iT1Unnu1//QmYhkacu6TnHyKGfvka4F2JwTfnhnweU3GQIKDcKAj"
)

func noSecrets(t *testing.T, what, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("%s shows the secret %q", what, s)
		}
	}
}

func TestDemo(t *testing.T) {
	t.Parallel()
	vms := []*vmtest.VM{lab.StartVM(t, "demo"), lab.StartVM(t, "demo2")}
	for _, vm := range vms {
		vm.MustRun(t, quietApt)
	}
	dir := "../../examples/demo"
	env := []string{"WINCH_AGE_KEY=age.key", "HOME=" + t.TempDir()}

	r := lab.WinchEnv(t, dir, env, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	noSecrets(t, "apply", r.Stdout+r.Stderr, demoPassword, demoKeyLine)
	if !strings.Contains(r.Stdout, "file /etc/nginx/htpasswd-example.com") {
		t.Errorf("apply does not show the password file:\n%s", r.Stdout)
	}
	// parallelism: 1 runs the web stage on demo, then its gate, then on demo2.
	gate := strings.Index(r.Stdout, "demo: web: * health: ")
	if gate < 0 || strings.Index(r.Stdout, "demo2: nginx: ") < gate {
		t.Errorf("demo2 started the web stage before the health gate of demo:\n%s", r.Stdout)
	}
	for i, vm := range vms {
		checkDemo(t, vm, vms[1-i].Name)
	}

	r = lab.WinchEnv(t, dir, env, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 2) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}

	// A new password: the plan masks the old and the new value.
	copyDir := t.TempDir()
	if err := os.CopyFS(copyDir, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	rotatePassword(t, copyDir, "n3w-demo-pass")
	r = lab.WinchEnv(t, copyDir, env, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "-demo:{PLAIN}(secret)\n") || !strings.Contains(r.Stdout, "+demo:{PLAIN}(secret) (secret value changed)\n") {
		t.Errorf("plan after a new password: exit %d, stdout %q", r.Code, r.Stdout)
	}
	noSecrets(t, "plan", r.Stdout+r.Stderr, demoPassword, "n3w-demo-pass")
}

// checkDemo checks the site and the services of the demo on vm. peer is the
// other web host.
func checkDemo(t *testing.T, vm *vmtest.VM, peer string) {
	t.Helper()
	// systemctl reload returns before nginx reads the new config.
	vm.MustRun(t, "for i in $(seq 50); do curl -s -o /dev/null http://localhost/ && exit 0; sleep 0.2; done; exit 1")
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
	if out := vm.MustRun(t, "curl -s -o /dev/null -w '%{http_code}' http://localhost/private"); out != "401" {
		t.Errorf("/private without the password: %q, want 401", out)
	}
	if out := vm.MustRun(t, "curl -s -u demo:"+demoPassword+" http://localhost/private"); !strings.Contains(out, "<h1>Private</h1>") {
		t.Errorf("/private with the password = %q", out)
	}
	if out := vm.MustRun(t, "systemctl is-active dkimpy-milter"); out != "active\n" {
		t.Errorf("dkimpy-milter: %q", out)
	}
	if out := vm.MustRun(t, "grep -c "+demoKeyLine+" /etc/dkimpy-milter/dkim.key; stat -c '%a %U' /etc/dkimpy-milter/dkim.key"); out != "1\n600 root\n" {
		t.Errorf("the DKIM key: %q", out)
	}

	if out := vm.MustRun(t, "stat -c '%a %G' /var/www/example.com"); out != "750 www-data\n" {
		t.Errorf("site directory: %q, want mode 750 and group www-data", out)
	}
	if out := vm.MustRun(t, "cat /etc/motd"); out != vm.Name+" is managed by winch.\n" {
		t.Errorf("/etc/motd = %q", out)
	}
	if out := vm.MustRun(t, "curl -s http://localhost/"); !strings.Contains(out, "<p>Also served by: "+peer+"</p>") {
		t.Errorf("the index page does not name the other web host %s: %q", peer, out)
	}
}

// rotatePassword gives the website a new password in the inventory of the
// project in dir.
func rotatePassword(t *testing.T, dir, password string) {
	t.Helper()
	cfg, err := os.ReadFile(filepath.Join(dir, "winch.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(cfg), "\n  - age1")
	if !ok {
		t.Fatal("winch.yaml has no recipients")
	}
	recipient, _, _ := strings.Cut("age1"+after, "\n")
	rec, err := secret.ParseRecipients([]string{recipient})
	if err != nil {
		t.Fatal(err)
	}
	text, err := secret.Encrypt(password, rec)
	if err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(dir, "inventories/demo.yaml")
	data, err := os.ReadFile(inv)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if k, _, ok := strings.Cut(line, "website_password: !secret "); ok {
			line = k + "website_password: !secret " + text
		}
		lines = append(lines, line)
	}
	if err := os.WriteFile(inv, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
}
