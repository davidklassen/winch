package integration

import (
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

const nginxSite = `stages:
  - name: web
    hosts: all
    steps:
      - file:
          path: /etc/nginx/nginx.conf
          content: |
            events {}
            http {
                include /etc/nginx/sites-enabled/*;
            }
      - dir:
          path: /var/www/demo
      - file:
          path: /var/www/demo/index.html
          content: "Hello from winch.\n"
      - file:
          path: /etc/nginx/sites-available/demo
          content: |
            server {
                listen 8080;
                root /var/www/demo;
            }
      - link:
          path: /etc/nginx/sites-enabled/demo
          target: /etc/nginx/sites-available/demo
      - pkg:
          name: [nginx, curl]
      - service:
          name: nginx
          running: true
          enabled: true
`

// spec: Modules/pkg; Modules/file, dir, link; Modules/service and unit; Running a pipeline/Plan
func TestNginx(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "nginx")
	vm.MustRun(t, quietApt+` && echo 'APT::Update::Pre-Invoke {"echo x >> /root/updates";};' > /etc/apt/apt.conf.d/99count && touch /root/updates`)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  nginx: {}\n",
		"pipelines/site.yaml":   nginxSite,
	})

	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || strings.Count(r.Stdout, "refresh the package index") != 1 {
		t.Fatalf("plan: exit %d, want one index refresh", r.Code)
	}
	for _, want := range []string{"+ file /etc/nginx/nginx.conf", "+ dir /var/www/demo", "+ link /etc/nginx/sites-enabled/demo", "+ pkg nginx, curl", "~ service nginx"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("plan has no %q", want)
		}
	}

	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "curl -s http://localhost:8080/"); out != "Hello from winch.\n" {
		t.Errorf("page = %q", out)
	}
	// dpkg keeps a config file that a step wrote before the install.
	if out := vm.MustRun(t, "head -1 /etc/nginx/nginx.conf"); out != "events {}\n" {
		t.Errorf("nginx.conf starts with %q", out)
	}
	if out := vm.MustRun(t, "wc -l < /root/updates"); strings.TrimSpace(out) != "1" {
		t.Errorf("index refreshes = %s, want 1", out)
	}

	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || r.Stdout != "1 host: 0 to change, 1 unchanged, 0 unknown\n" {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}

// spec: Running a pipeline/Apply
func TestApplyChecksStagesWithoutChange(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "stages")
	vm.MustRun(t, quietApt)
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  stages: {}\n",
		"pipelines/site.yaml": `stages:
  - name: install
    hosts: all
    steps:
      - pkg:
          name: nginx
  - name: configure
    hosts: all
    steps:
      - link:
          path: /etc/nginx/sites-enabled/default
          absent: true
`,
	})

	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "+ pkg nginx") || strings.Contains(r.Stdout, "link") {
		t.Fatalf("plan: exit %d, want only the pkg step:\n%s", r.Code, r.Stdout)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 || !strings.Contains(r.Stdout, "stages: configure: - link /etc/nginx/sites-enabled/default") {
		t.Fatalf("apply: exit %d, stdout %q", r.Code, r.Stdout)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || r.Stdout != "1 host: 0 to change, 1 unchanged, 0 unknown\n" {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
