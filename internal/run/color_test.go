package run_test

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/davidklassen/winch/internal/color"
	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/golden"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

var codes = regexp.MustCompile("\x1b\\[[0-9;]*m")

// colored runs write twice, with color on and off. It checks that the
// output with color, without the codes, is the output without color, and
// returns the output with color.
func colored(t *testing.T, filter *secret.Filter, format func(out, errOut *bytes.Buffer) []byte, write func(out, errOut *color.Writer)) []byte {
	t.Helper()
	var out, errOut, plainOut, plainErr bytes.Buffer
	write(color.NewWriter(&out, filter.Parts, true), color.NewWriter(&errOut, filter.Parts, true))
	write(color.NewWriter(&plainOut, filter.Parts, false), color.NewWriter(&plainErr, filter.Parts, false))
	got := format(&out, &errOut)
	if plain := format(&plainOut, &plainErr); string(codes.ReplaceAll(got, nil)) != string(plain) {
		t.Errorf("without the codes, the output differs from the output without color:\n%s\n--- without color\n%s", codes.ReplaceAll(got, nil), plain)
	}
	if !codes.Match(got) {
		t.Error("the output has no color")
	}
	return got
}

func colorProject(t *testing.T) *project.Project {
	t.Helper()
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  web1: {}\n  web2: {}\n  web3: {}\n",
		"pipelines/site.yaml": `stages:
  - name: web
    hosts: all
    health:
      command: curl -sf http://localhost/
    steps:
      - recipe: nginx
      - file:
          path: /etc/issue
          absent: true
`,
		"recipes/nginx/recipe.yaml": `steps:
  - name: Configure nginx
    file:
      path: /etc/nginx/nginx.conf
      content: "user www-data;\nlisten 8080;\n"
    notify: reload
    then: nginx -t
handlers:
  reload:
    - service:
        name: nginx
        reloaded: true
`,
	})
	p, err := project.Load(t.Context(), dir, "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// colorHosts returns hosts for colorProject: web1 and web2 have changes,
// web3 fails the check, and web2 fails in apply.
func colorHosts() *fakehost.Hosts {
	h := fakehost.New()
	for _, host := range []string{"web1", "web2"} {
		h.SetFile(host, "/etc/nginx/nginx.conf", "user www-data;\nlisten 80;\n")
		h.SetFile(host, "/etc/issue", "Debian\n")
	}
	h.FailCheck("web3")
	h.FailApply("web2 /etc/issue")
	return h
}

// spec: CLI/Output
func TestColor(t *testing.T) {
	filter := secret.NewFilter()
	plan := run.MakePlan(context.Background(), colorProject(t), colorHosts().Connector(), run.Options{})
	golden.Assert(t, filepath.Join("testdata", "color", "plan.golden"), colored(t, filter, output, func(out, errOut *color.Writer) {
		plan.Write(out, errOut)
	}))
	golden.Assert(t, filepath.Join("testdata", "color", "apply.golden"), colored(t, filter, applyOutput, func(out, errOut *color.Writer) {
		run.Apply(context.Background(), plan, colorHosts().Connector(), run.Text(out, errOut))
	}))
}

// secretHosts returns a host for secretProject with a changed file and a
// pending then. With fail, a step fails in apply.
func secretHosts(fail bool) *fakehost.Hosts {
	h := fakehost.New()
	h.SetFile("web1", "/etc/monit/conf.d/settings", "set httpd port 2812\n  allow admin:old-pass\n# Old-Pass\n")
	h.SetThen("web1", protocol.Then{Recipe: "monit", Step: 2, Module: "file", Main: "/etc/monit/hunter2.key"})
	if fail {
		h.FailApply("web1 /etc/monit/hunter2.key")
	}
	return h
}

// spec: CLI/Output; Variables/Secrets in output
func TestColorSecrets(t *testing.T) {
	p, filter := secretProject(t)
	plan := run.MakePlan(context.Background(), p, secretHosts(true).Connector(), run.Options{})
	golden.Assert(t, filepath.Join("testdata", "color", "secrets-plan.golden"), colored(t, filter, output, func(out, errOut *color.Writer) {
		plan.Write(out, errOut)
	}))
	golden.Assert(t, filepath.Join("testdata", "color", "secrets-apply.golden"), colored(t, filter, applyOutput, func(out, errOut *color.Writer) {
		run.Apply(context.Background(), plan, secretHosts(true).Connector(), run.Text(out, errOut))
	}))
	golden.Assert(t, filepath.Join("testdata", "color", "secrets-apply-ok.golden"), colored(t, filter, applyOutput, func(out, errOut *color.Writer) {
		run.Apply(context.Background(), plan, secretHosts(false).Connector(), run.Text(out, errOut))
	}))
}
