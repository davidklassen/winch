package run_test

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/run"
)

// progress records the calls of a run.
type progress struct {
	mu    sync.Mutex
	calls map[string][]string
}

func (p *progress) Busy(host, text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[host] = append(p.calls[host], text)
}

func (p *progress) Idle(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[host] = append(p.calls[host], "idle")
}

var progressFiles = map[string]string{
	"winch.yaml":            "name: acme\ninventory: test\n",
	"inventories/test.yaml": "hosts:\n  web1: {}\n",
	"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    health:
      command: curl -sf http://localhost/
    steps:
      - recipe: nginx
`,
	"recipes/nginx/recipe.yaml": `steps:
  - name: Configure
    file:
      path: /etc/nginx/nginx.conf
      content: "a\n"
    then: nginx -t
    notify: reload
handlers:
  reload:
    - cmd:
        command: systemctl reload nginx
`,
}

// spec: CLI/Output (progress)
func TestProgress(t *testing.T) {
	for _, serial := range []bool{false, true} {
		h := fakehost.New()
		p := &progress{calls: map[string][]string{}}
		opts := run.Options{Serial: serial, Progress: p}
		plan := run.MakePlan(context.Background(), loadFiles(t, progressFiles), h.Connector(), opts)
		var out, errOut bytes.Buffer
		if o := run.Apply(context.Background(), plan, h.Connector(), run.Text(plain(&out), plain(&errOut))); !o.OK() {
			t.Fatalf("apply failed: %s", errOut.String())
		}
		step := "nginx: Configure: file /etc/nginx/nginx.conf"
		want := []string{"connecting", step, "idle",
			"connecting", step, step + ": then", "nginx: handler nginx.reload: cmd systemctl reload nginx", "web: health", "access check", "idle"}
		if !slices.Equal(p.calls["web1"], want) {
			t.Errorf("serial %v: progress %q, want %q", serial, p.calls["web1"], want)
		}
	}
}

// spec: CLI/Output (progress)
func TestProgressUnreachable(t *testing.T) {
	for _, serial := range []bool{false, true} {
		p := &progress{calls: map[string][]string{}}
		run.MakePlan(context.Background(), load(t, "unreachable"), fakehost.New().Connector(), run.Options{Serial: serial, Progress: p})
		if want := []string{"connecting", "idle"}; !slices.Equal(p.calls["web3"], want) {
			t.Errorf("serial %v: progress %q, want %q", serial, p.calls["web3"], want)
		}
	}
}
