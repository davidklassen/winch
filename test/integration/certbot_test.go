package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// pebbleSetup installs certbot with its plugins and the web servers, and
// starts Pebble, the ACME test server. Its DNS server answers 127.0.0.1 for
// every name, so Pebble checks the challenges on this VM. With
// PEBBLE_AUTHZREUSE=0, Pebble still reuses a valid authorization of the
// account in 1% of the orders. A test whose challenge must fail removes the
// account first, and certbot registers a new one.
const pebbleSetup = `set -e
apt-get update -q >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -q certbot python3-certbot-nginx python3-certbot-apache nginx apache2 pebble curl >/dev/null
systemctl stop apache2
systemctl start nginx
mkdir -p /etc/pebble
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj /CN=localhost \
	-addext subjectAltName=DNS:localhost -keyout /etc/pebble/key.pem -out /usr/local/share/ca-certificates/pebble.crt 2>/dev/null
update-ca-certificates >/dev/null 2>&1
cat > /etc/pebble/config.json <<'EOF'
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
 "certificate": "/usr/local/share/ca-certificates/pebble.crt", "privateKey": "/etc/pebble/key.pem",
 "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false}}
EOF
# The Pebble of Ubuntu 24.04 has no DNS over HTTPS.
doh=
if pebble-challtestsrv -h 2>&1 | grep -q '^  -doh '; then doh=-doh=; fi
systemd-run --unit pebble-dns pebble-challtestsrv -defaultIPv6 "" -dns01 127.0.0.1:8053 -http01 "" -https01 "" -tlsalpn01 "" $doh -management 127.0.0.1:8055
systemd-run --unit pebble -E PEBBLE_VA_NOSLEEP=1 -E PEBBLE_WFE_NONCEREJECT=0 -E PEBBLE_AUTHZREUSE=0 pebble -config /etc/pebble/config.json -dnsserver 127.0.0.1:8053
echo 'server = https://localhost:14000/dir' >> /etc/letsencrypt/cli.ini
for i in $(seq 100); do curl -sf -o /dev/null https://localhost:14000/dir && exit 0; sleep 0.1; done
exit 1
`

// startPebble runs pebbleSetup on vm. A failed test logs Pebble's log.
func startPebble(t *testing.T, vm *vmtest.VM) {
	t.Helper()
	vm.MustRun(t, pebbleSetup)
	vm.LogOnFailure(t, "journalctl -u pebble -n 200 --no-pager")
}

// issue runs certbot with the nginx authenticator, as a person would, with
// args after the common ones.
func issue(args string) string {
	return "certbot certonly --non-interactive --agree-tos --no-eff-email --email admin@example.com --authenticator nginx " + args + " >/root/issue.log 2>&1 || { cat /root/issue.log; exit 1; }\n"
}

const keySum = "sha256sum /etc/letsencrypt/live/a.example.com/privkey.pem"

// spec: Modules/certbot; Modules (commands)
func TestCertbotModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "certbot")
	startPebble(t, vm)
	reset := `rm -rf /etc/letsencrypt/accounts /etc/letsencrypt/live/* /etc/letsencrypt/archive/* /etc/letsencrypt/renewal/* /root/deployed /root/key.sum /root/hook-ok
systemctl stop apache2
systemctl start nginx
md5sum /etc/nginx/nginx.conf /etc/nginx/sites-enabled/* /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* > /root/web.md5`
	sans := func(names string) string {
		return "openssl x509 -in /etc/letsencrypt/live/a.example.com/cert.pem -noout -ext subjectAltName | grep -qx '    " + names + "'"
	}
	webUnchanged := "md5sum -c --quiet /root/web.md5"
	ab := []string{"a.example.com", "b.example.com"}
	deployed := "echo deployed >> /root/deployed"
	vmtest.RunCases(t, vm, "certbot", reset, []vmtest.Case{
		{
			Name:      "first issue",
			Args:      &module.Certbot{Name: "a.example.com", Domains: ab, Email: "admin@example.com", DeployHook: &deployed},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"domains a.example.com, b.example.com", "authenticator nginx", "deploy_hook echo deployed >> /root/deployed"}},
			Unchanged: "test ! -e /etc/letsencrypt/renewal/a.example.com.conf",
			After:     sans("DNS:a.example.com, DNS:b.example.com") + ` && [ "$(cat /root/deployed)" = deployed ] && ` + webUnchanged,
		},
		{
			Name:  "the same certificate, with the domains in another order",
			Setup: issue(`--cert-name a.example.com -d a.example.com,b.example.com --deploy-hook "echo deployed >> /root/deployed"`),
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"b.example.com", "a.example.com"}, Email: "admin@example.com", DeployHook: &deployed},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:  "a new domain",
			Setup: issue("--cert-name a.example.com -d a.example.com"),
			Args:  &module.Certbot{Name: "a.example.com", Domains: ab, Email: "admin@example.com"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"domains a.example.com → a.example.com, b.example.com", "issue the certificate again, with a new key"}},
			After: sans("DNS:a.example.com, DNS:b.example.com"),
		},
		{
			Name:  "a changed deploy_hook runs certbot and the new hook",
			Setup: issue(`--cert-name a.example.com -d a.example.com --deploy-hook "echo old >> /root/deployed"`) + "rm /root/deployed",
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", DeployHook: &deployed},
			Want: module.Result{Status: module.Change, Action: module.Modify, Changes: []string{
				"deploy_hook echo old >> /root/deployed → echo deployed >> /root/deployed",
				"issue the certificate again, with a new key; run deploy_hook",
			}},
			After: `[ "$(cat /root/deployed)" = deployed ] && python3 -c ` + vmtest.Quote(`from configobj import ConfigObj; assert ConfigObj("/etc/letsencrypt/renewal/a.example.com.conf")["renewalparams"]["renew_hook"] == "sh -ec 'echo deployed >> /root/deployed'"`),
		},
		{
			Name:  "reuse_key keeps the key",
			Setup: issue("--cert-name a.example.com -d a.example.com --reuse-key") + keySum + " > /root/key.sum",
			Args:  &module.Certbot{Name: "a.example.com", Domains: ab, Email: "admin@example.com", ReuseKey: true},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"domains a.example.com → a.example.com, b.example.com", "issue the certificate again, with the same key"}},
			After: sans("DNS:a.example.com, DNS:b.example.com") + " && " + keySum + " | cmp -s - /root/key.sum",
		},
		{
			Name:  "without reuse_key, the key changes",
			Setup: issue("--cert-name a.example.com -d a.example.com --reuse-key") + keySum + " > /root/key.sum",
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"reuse_key true → false", "issue the certificate again, with a new key"}},
			After: "! " + keySum + " | cmp -s - /root/key.sum",
		},
		{
			Name:  "a removed hook goes away",
			Setup: issue("--cert-name a.example.com -d a.example.com --pre-hook true"),
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"pre_hook true → (none)", "issue the certificate again, with a new key"}},
			After: "! grep -q pre_hook /etc/letsencrypt/renewal/a.example.com.conf",
		},
		{
			Name:  "a hook of several lines, with white space at the end of its first line",
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", DeployHook: new("echo one >> /root/deployed \necho two >> /root/deployed\n")},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"domains a.example.com", "authenticator nginx", "deploy_hook\necho one >> /root/deployed \necho two >> /root/deployed"}},
			After: `[ "$(cat /root/deployed)" = "$(printf 'one\ntwo')" ]`,
		},
		{
			Name:  "a hook of several lines with quotes",
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", DeployHook: new("test \"$X\" = '' && echo 'one' >> /root/deployed\necho '\"\"\"' >> /root/deployed\necho \"'''\" >> /root/deployed")},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"domains a.example.com", "authenticator nginx", "deploy_hook\ntest \"$X\" = '' && echo 'one' >> /root/deployed\necho '\"\"\"' >> /root/deployed\necho \"'''\" >> /root/deployed"}},
			After: `[ "$(cat /root/deployed)" = "$(printf "one\n\"\"\"\n'''")" ] && { certbot renew --dry-run --no-random-sleep-on-renew --cert-name a.example.com >/root/renew.log 2>&1 || { cat /root/renew.log; exit 1; }; }`,
		},
		{
			Name:    "a renewal file without its certificate",
			Setup:   issue("--cert-name a.example.com -d a.example.com") + "rm -r /etc/letsencrypt/live/a.example.com",
			Args:    &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com"},
			WantErr: "certbot delete --cert-name a.example.com",
		},
		{
			Name:         "a failing deploy_hook fails the step",
			Args:         &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", DeployHook: new("test -e /root/hook-ok || { echo oops >&2; exit 3; }")},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"domains a.example.com", "authenticator nginx", "deploy_hook test -e /root/hook-ok || { echo oops >&2; exit 3; }"}},
			WantApplyErr: "a hook failed:\nHook 'deploy-hook' reported error code 3\nHook 'deploy-hook' ran with error output:\n oops",
			After:        "test -e /etc/letsencrypt/renewal/a.example.com.conf",
			Fix:          "touch /root/hook-ok",
		},
		{
			Name:         "a failing pre_hook fails the step",
			Args:         &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", PreHook: new("false")},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"domains a.example.com", "authenticator nginx", "pre_hook false"}},
			WantApplyErr: "Hook 'pre-hook' reported error code 1",
			// certbot issues the certificate after a failed pre_hook.
			ErrAfterChange: true,
		},
		{
			Name:  "apache",
			Setup: "systemctl stop nginx && systemctl start apache2",
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", Authenticator: "apache"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"domains a.example.com", "authenticator apache"}},
			After: sans("DNS:a.example.com") + " && systemctl is-active -q apache2 && " + webUnchanged,
		},
		{
			Name: "standalone with hooks frees port 80",
			Args: &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", Authenticator: "standalone", PreHook: new("systemctl stop nginx"), PostHook: new("systemctl start nginx")},
			Want: module.Result{Status: module.Change, Action: module.Create, Changes: []string{
				"domains a.example.com", "authenticator standalone", "pre_hook systemctl stop nginx", "post_hook systemctl start nginx",
			}},
			After: sans("DNS:a.example.com") + " && systemctl is-active -q nginx",
		},
		{
			Name:         "standalone without hooks while nginx holds port 80",
			Args:         &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", Authenticator: "standalone"},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"domains a.example.com", "authenticator standalone"}},
			WantApplyErr: "Could not bind TCP port 80",
			After:        "test ! -e /etc/letsencrypt/renewal/a.example.com.conf",
			Fix:          "systemctl stop nginx",
		},
		{
			Name:  "webroot",
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", Authenticator: "webroot", WebrootPath: "/var/www/html"},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"domains a.example.com", "authenticator webroot", "webroot_path /var/www/html"}},
			After: sans("DNS:a.example.com") + " && " + webUnchanged,
		},
		{
			Name:  "a changed authenticator",
			Setup: issue("--cert-name a.example.com -d a.example.com"),
			Args:  &module.Certbot{Name: "a.example.com", Domains: []string{"a.example.com"}, Email: "admin@example.com", Authenticator: "webroot", WebrootPath: "/var/www/html"},
			Want: module.Result{Status: module.Change, Action: module.Modify, Changes: []string{
				"authenticator nginx → webroot", "webroot_path (none) → /var/www/html", "issue the certificate again, with a new key",
			}},
			After: "grep -qx 'authenticator = webroot' /etc/letsencrypt/renewal/a.example.com.conf",
		},
	})
}

// spec: Modules/certbot
func TestCertbotPendingHooks(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "pending-hooks")
	startPebble(t, vm)
	for _, hook := range []string{"deploy_hook", "post_hook"} {
		t.Run(hook, func(t *testing.T) {
			dir := vmtest.WriteProject(t, map[string]string{
				"winch.yaml":            "name: hooks\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  pending-hooks: {}\n",
				"pipelines/site.yaml": fmt.Sprintf(`stages:
  - name: test
    hosts: all
    steps:
      - certbot:
          name: %s
          domains: [a.example.com]
          email: admin@example.com
          %s: |
            if [ ! -e /root/%s-failed ]; then
              touch /root/%s-failed
              echo "Hook 'post-hook' reported error code 9" >&2
              exit 3
            fi
            printf '%%s\n' "$RENEWED_LINEAGE $RENEWED_DOMAINS" >> /root/%s-runs
`, hook, hook, hook, hook, hook),
			})
			r := lab.Winch(t, dir, "apply", "site", "--yes")
			if r.Code != 1 || !strings.Contains(r.Stderr, "reported error code 3") {
				t.Fatalf("first apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
			}
			vm.MustRun(t, "test -e /etc/letsencrypt/renewal/"+hook+".conf && sha256sum /etc/letsencrypt/live/"+hook+"/cert.pem > /root/cert.sum")
			r = lab.Winch(t, dir, "plan", "site", "--exit-code")
			if r.Code != 2 || !strings.Contains(r.Stdout, "pending "+hook) {
				t.Fatalf("plan after failure: exit %d, want pending %s\n%s%s", r.Code, hook, r.Stdout, r.Stderr)
			}
			if hook == "deploy_hook" && strings.Contains(r.Stdout, "pending post_hook") {
				t.Errorf("hook stderr became a pending post_hook:\n%s", r.Stdout)
			}
			r = lab.Winch(t, dir, "apply", "site", "--yes")
			if r.Code != 0 {
				t.Fatalf("retry apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
			}
			vm.MustRun(t, "sha256sum -c /root/cert.sum")
			want := " \n"
			if hook == "deploy_hook" {
				want = "/etc/letsencrypt/live/" + hook + " a.example.com\n"
			}
			if got := vm.MustRun(t, "cat /root/"+hook+"-runs"); got != want {
				t.Errorf("retried hook output = %q, want %q", got, want)
			}
			r = lab.Winch(t, dir, "plan", "site", "--exit-code")
			if r.Code != 0 || !unchanged(r.Stdout, 1) {
				t.Errorf("third plan: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
			}
		})
	}

	t.Run("partial recovery", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: hooks\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  pending-hooks: {}\n",
			"pipelines/site.yaml": `stages:
  - name: test
    hosts: all
    steps:
      - certbot:
          name: both
          domains: [a.example.com]
          email: admin@example.com
          deploy_hook: |
            test -e /root/both-ready
            echo deploy >> /root/both-deploy
          post_hook: |
            if [ ! -e /root/both-post-failed ]; then
              touch /root/both-post-failed
              exit 3
            fi
            echo post >> /root/both-post
`,
		})
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 1 || !strings.Contains(r.Stderr, "Hook 'deploy-hook' reported") || !strings.Contains(r.Stderr, "Hook 'post-hook' reported") {
			t.Fatalf("first apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, "sha256sum /etc/letsencrypt/live/both/cert.pem > /root/both.sum")
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 1 || !strings.Contains(r.Stderr, "deploy_hook") {
			t.Fatalf("failed retry: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		r = lab.Winch(t, dir, "plan", "site", "--exit-code")
		if r.Code != 2 || !strings.Contains(r.Stdout, "pending deploy_hook") || strings.Contains(r.Stdout, "pending post_hook") {
			t.Errorf("partial recovery plan: exit %d, want only deploy pending\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if got := vm.MustRun(t, "cat /root/both-post 2>/dev/null; true"); got != "post\n" {
			t.Errorf("post after failed deploy retry = %q, want one successful post", got)
		}
		vm.MustRun(t, "touch /root/both-ready")
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("final retry: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, "sha256sum -c /root/both.sum")
		if got := vm.MustRun(t, "cat /root/both-post /root/both-deploy"); got != "post\ndeploy\n" {
			t.Errorf("successful hooks = %q, want one run of each", got)
		}
		r = lab.Winch(t, dir, "plan", "site", "--exit-code")
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("final plan: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
	})

	t.Run("a failed challenge leaves no pending hook", func(t *testing.T) {
		step := func(webroot string) map[string]string {
			return map[string]string{
				"winch.yaml":            "name: hooks\ninventory: test\n",
				"inventories/test.yaml": "hosts:\n  pending-hooks: {}\n",
				"pipelines/site.yaml": `stages:
  - name: test
    hosts: all
    steps:
      - certbot:
          name: challenge
          domains: [a.example.com]
          email: admin@example.com
          authenticator: webroot
          webroot_path: ` + webroot + `
          deploy_hook: echo deploy >> /root/challenge-hooks
          post_hook: echo post >> /root/challenge-hooks
`,
			}
		}
		good := vmtest.WriteProject(t, step("/var/www/html"))
		if r := lab.Winch(t, good, "apply", "site", "--yes"); r.Code != 0 {
			t.Fatalf("first apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		// nginx does not serve this directory, so Pebble's challenge fails.
		vm.MustRun(t, "mkdir -p /root/unserved && rm -r /root/challenge-hooks /etc/letsencrypt/accounts")
		r := lab.Winch(t, vmtest.WriteProject(t, step("/root/unserved")), "apply", "site", "--yes")
		if r.Code != 1 || !strings.Contains(r.Stderr, "Some challenges have failed") || strings.Contains(r.Stderr, "reported error code") {
			t.Fatalf("apply with a failing challenge: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if got := vm.MustRun(t, "cat /root/challenge-hooks"); got != "post\n" {
			t.Errorf("hooks after the failed challenge = %q, want a successful post_hook", got)
		}
		r = lab.Winch(t, good, "plan", "site", "--exit-code")
		if r.Code != 0 || !unchanged(r.Stdout, 1) {
			t.Errorf("plan of the old step after a failed challenge: exit %d, want no pending hook\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
	})

	t.Run("certbot killed during deploy_hook", func(t *testing.T) {
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: hooks\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  pending-hooks: {}\n",
			"pipelines/site.yaml": `stages:
  - name: test
    hosts: all
    steps:
      - certbot:
          name: killed
          domains: [a.example.com]
          email: admin@example.com
          deploy_hook: |
            exec >/dev/null 2>&1
            if [ ! -e /root/killed ]; then
              touch /root/killed
              pkill -9 -x certbot
              exit 1
            fi
            echo deploy >> /root/killed-runs
`,
		})
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 1 || strings.Contains(r.Stderr, "reported error code") {
			t.Fatalf("apply with a killed certbot: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		r = lab.Winch(t, dir, "plan", "site", "--exit-code")
		if r.Code != 2 || !strings.Contains(r.Stdout, "pending deploy_hook") {
			t.Fatalf("plan after the kill: exit %d, want pending deploy_hook\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if r = lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
			t.Fatalf("retry apply: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if got := vm.MustRun(t, "cat /root/killed-runs"); got != "deploy\n" {
			t.Errorf("deploy_hook runs = %q, want one", got)
		}
	})

	t.Run("record failure prevents issue", func(t *testing.T) {
		vm.MustRun(t, "mkdir -p /var/lib/winch/certbot-hooks && mount -t tmpfs none /var/lib/winch/certbot-hooks && mount -o remount,ro /var/lib/winch/certbot-hooks")
		dir := vmtest.WriteProject(t, map[string]string{
			"winch.yaml":            "name: hooks\ninventory: test\n",
			"inventories/test.yaml": "hosts:\n  pending-hooks: {}\n",
			"pipelines/site.yaml": `stages:
  - name: test
    hosts: all
    steps:
      - certbot:
          name: record-failure
          domains: [a.example.com]
          email: admin@example.com
          deploy_hook: |
            test -e /root/record-ready
            echo deployed > /root/record-deployed
`,
		})
		r := lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 1 || !strings.Contains(r.Stderr, "read-only file system") {
			t.Fatalf("apply without record storage: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if got := vm.MustRun(t, "test ! -e /etc/letsencrypt/renewal/record-failure.conf && echo absent; true"); got != "absent\n" {
			t.Errorf("certificate was issued before recovery could be recorded")
		}
		vm.MustRun(t, "mount -o remount,rw /var/lib/winch/certbot-hooks && touch /root/record-ready")
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply with record storage: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
		if got := vm.MustRun(t, "cat /root/record-deployed 2>/dev/null; true"); got != "deployed\n" {
			t.Errorf("deploy after storage recovery = %q", got)
		}
		vm.MustRun(t, "umount /var/lib/winch/certbot-hooks")
	})
}
