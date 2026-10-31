package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// exampleHost makes the lab's SSH config name vm web1.example.com, the host
// of the examples. Their user is admin, the lab's user.
func exampleHost(t *testing.T, vm *vmtest.VM) {
	t.Helper()
	conf, err := os.ReadFile(filepath.Join(lab.Dir, "hosts", vm.Name+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	alias, err := lab.WriteHost("web1.example.com", strings.Replace(string(conf), "Host "+vm.Name, "Host web1.example.com", 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(alias) })
}

// spec: Project layout; Variables
func TestOneFileExamples(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "examples")
	exampleHost(t, vm)
	for _, name := range []string{"nginx", "caddy"} {
		r := lab.Winch(t, "../../examples/"+name, "plan")
		if r.Code != 0 || !strings.Contains(r.Stdout, "\n1 host: 1 to change, 0 unchanged, 0 unknown\nplan ") {
			t.Errorf("%s: plan: exit %d, stdout %q, stderr %q", name, r.Code, r.Stdout, r.Stderr)
		}
	}

	// Pebble answers the certificate request of the nginx example. The
	// example installs certbot and nginx itself.
	vm.MustRun(t, "set -e\napt-get update -q >/dev/null\nDEBIAN_FRONTEND=noninteractive apt-get install -y -q pebble curl >/dev/null\n"+pebbleStart)
	vm.LogOnFailure(t, "journalctl -u pebble -n 200 --no-pager")
	vm.MustRun(t, "! command -v certbot && ! command -v nginx")
	applyExample(t, vm, "nginx", "curl -sk --resolve example.com:443:127.0.0.1 https://example.com/", "<p>Hello from web1.example.com.</p>")

	// Caddy and nginx both listen on ports 80 and 443. Caddy cannot reach
	// Let's Encrypt from the lab, so it has no certificate, and only its
	// redirect to HTTPS shows that it serves the site.
	vm = lab.StartVM(t, "examples-caddy")
	exampleHost(t, vm)
	applyExample(t, vm, "caddy", "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --resolve example.com:80:127.0.0.1 http://example.com/", "308 https://example.com/")
}

// applyExample applies the example name, checks that the output of the
// command check on vm holds want, and plans again.
func applyExample(t *testing.T, vm *vmtest.VM, name, check, want string) {
	t.Helper()
	dir := "../../examples/" + name
	if r := lab.Winch(t, dir, "apply", "--yes"); r.Code != 0 {
		t.Fatalf("%s: apply: exit %d, stdout %q, stderr %q", name, r.Code, r.Stdout, r.Stderr)
	}
	if got := vm.MustRun(t, check+" || true"); !strings.Contains(got, want) {
		t.Errorf("%s: %s: %q, want %q", name, check, got, want)
	}
	if r := lab.Winch(t, dir, "plan"); r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("%s: second plan: exit %d, stdout %q, stderr %q", name, r.Code, r.Stdout, r.Stderr)
	}
}
