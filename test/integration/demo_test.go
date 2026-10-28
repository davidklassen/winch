package integration

import (
	"os"
	"os/exec"
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

	// Drift: stock restores nginx.conf, and purge removes an unknown page.
	vms[0].MustRun(t, "echo edited >> /etc/nginx/nginx.conf && chmod 600 /etc/nginx/nginx.conf && touch /var/www/example.com/old.html")
	r = lab.WinchEnv(t, dir, env, "plan", "site", "--hosts", "demo")
	for _, want := range []string{"file /etc/nginx/nginx.conf\n          content of nginx-common ", "          mode 0600 → 0644\n", "dir /var/www/example.com\n          remove file /var/www/example.com/old.html\n"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("plan after drift: no %q in %q", want, r.Stdout)
		}
	}
	if r := lab.WinchEnv(t, dir, env, "apply", "site", "--hosts", "demo", "--yes"); r.Code != 0 {
		t.Fatalf("apply after drift: exit %d, stderr %q", r.Code, r.Stderr)
	}
	r = lab.WinchEnv(t, dir, env, "plan", "site", "--hosts", "demo")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("plan after the repair: exit %d, stdout %q", r.Code, r.Stdout)
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
	if out := vm.MustRun(t, "hostname; nft list table inet winch | grep -c 'tcp dport { 22, 80 } accept'; ls /etc/ssh/sshd_config.d"); out != vm.Name+"\n1\nlocal.conf\n" {
		t.Errorf("hostname, firewall rule, sshd drop-ins: %q", out)
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
	cmd := exec.CommandContext(t.Context(), "ssh", "-l", "deploy", vm.Name, "id")
	cmd.Env = lab.Env()
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "uid=2000(deploy) gid=2000(deploy) groups=2000(deploy)\n" {
		t.Errorf("ssh as deploy: %v: %q", err, out)
	}
	if out := vm.MustRun(t, "stat -c '%a %U' /etc/sudoers.d/admin; getent passwd admin | cut -d: -f7"); out != "440 root\n/bin/bash\n" {
		t.Errorf("the admin recipe: %q", out)
	}
	if out := vm.MustRun(t, "systemctl is-active rspamd valkey-server; stat -c '%a %U' /var/lib/rspamd/dkim/example.com.dkim.key"); out != "active\nactive\n600 _rspamd\n" {
		t.Errorf("the rspamd recipe: %q", out)
	}
	if out := vm.MustRun(t, "apt-cache policy rspamd | grep -c 10.0.2.100/signed"); out == "0\n" {
		t.Errorf("rspamd does not come from the signed source")
	}
	if out := vm.MustRun(t, "systemctl is-active heartbeat heartbeat-report.timer; systemctl is-enabled heartbeat heartbeat-report.timer"); out != "active\nactive\nenabled\nenabled\n" {
		t.Errorf("the heartbeat recipe: %q", out)
	}
	if out := vm.MustRun(t, "echo 'GET unattended-upgrades/enable_auto_updates' | debconf-communicate 2>/dev/null"); out != "0 true\n" {
		t.Errorf("the answer of unattended-upgrades: %q", out)
	}
	if out := vm.MustRun(t, "grep -o 'Unattended-Upgrade \"[01]\"' /etc/apt/apt.conf.d/20auto-upgrades"); out != "Unattended-Upgrade \"1\"\n" {
		t.Errorf("the unattended upgrades: %q", out)
	}
	if out := vm.MustRun(t, "systemctl is-active postfix; postconf -h inet_interfaces myorigin; postalias -q root /etc/aliases"); out != "active\nloopback-only\n/etc/mailname\nwebmaster@example.com\n" {
		t.Errorf("the postfix recipe: %q", out)
	}
	if out := vm.MustRun(t, "ss -Hltn 'sport = :25' | awk '{print $4}'"); out != "127.0.0.1:25\n" {
		t.Errorf("postfix listens on %q, want only 127.0.0.1:25", out)
	}
	if out := vm.MustRun(t, "cmp /etc/postfix/master.cf /usr/share/postfix/master.cf.dist && echo stock"); out != "stock\n" {
		t.Errorf("postfix master.cf: %q", out)
	}
	// The stock and purge steps.
	if out := vm.MustRun(t, "dpkg-deb --fsys-tarfile /var/cache/apt/archives/nginx-common_*.deb | tar -xO ./etc/nginx/nginx.conf | cmp - /etc/nginx/nginx.conf && echo stock"); out != "stock\n" {
		t.Errorf("nginx.conf: %q", out)
	}
	for dir, want := range map[string]string{
		"/etc/nginx/sites-enabled": "example.com",
		"/var/www/example.com":     "about.html contact.html index.html private.html robots.txt",
		"/etc/sudoers.d":           "README admin",
		"/etc/fail2ban/jail.d":     "defaults-debian.conf mail.conf",
		"/etc/monit/conf.d":        "inside outside settings",
		"/etc/dovecot/conf.d":      "10-auth.conf 10-mail.conf 10-master.conf 10-ssl.conf 15-mailboxes.conf 20-imap.conf 20-lmtp.conf 90-sieve-extprograms.conf 90-sieve.conf 99-local.conf",
		"/etc/letsencrypt/renewal": vm.Name + ".conf example.com.conf mta-sts.example.com.conf",
	} {
		if out := vm.MustRun(t, "ls "+dir+" | tr '\\n' ' '"); out != want+" " {
			t.Errorf("%s holds %q, want %q", dir, out, want)
		}
	}
	if out := vm.MustRun(t, "stat -c '%a' /etc/sudoers.d; systemctl is-active dovecot fail2ban monit"); out != "750\nactive\nactive\nactive\n" {
		t.Errorf("leftovers, dovecot, fail2ban, monit: %q", out)
	}
	if out := vm.MustRun(t, "fail2ban-client status | grep 'Jail list'"); !strings.Contains(out, "dovecot, postfix-sasl, sshd") {
		t.Errorf("fail2ban jails: %q", out)
	}
	// The certificates come from Pebble, which signs with a root of its own.
	if out := vm.MustRun(t, "curl -sk https://localhost:15000/roots/0 > /root/pebble-root.pem && curl -s --cacert /root/pebble-root.pem --resolve example.com:443:127.0.0.1 https://example.com/about"); !strings.Contains(out, "<h1>About</h1>") {
		t.Errorf("https://example.com/about = %q", out)
	}
	if out := vm.MustRun(t, "echo | openssl s_client -connect localhost:993 -CAfile /root/pebble-root.pem -verify_return_error 2>/dev/null | openssl x509 -noout -ext subjectAltName | tail -1"); out != "    DNS:"+vm.Name+"\n" {
		t.Errorf("the TLS of dovecot: %q", out)
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
