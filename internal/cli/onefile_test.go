package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/vmtest"
)

const oneFile = `name: demo
inventory: staging
inventories:
  staging:
    hosts:
      app.staging.internal: {}
  prod:
    hosts:
      app1.prod.internal: {}
      app2.prod.internal: {}
pipelines:
  site:
    stages:
      - name: site
        hosts: all
        steps:
          - recipe: app
recipes:
  app:
    vars:
      app_port: 8080
    steps:
      - unit:
          name: app.service
          content: !tpl |
            [Service]
            ExecStart=/usr/local/bin/app --port {{ .vars.app_port }}
        notify: restart
    handlers:
      restart:
        - service:
            name: app
            restarted: true
`

var manyFiles = map[string]string{
	"winch.yaml":               "name: demo\ninventory: staging\n",
	"inventories/staging.yaml": "hosts:\n  app.staging.internal: {}\n",
	"inventories/prod.yaml":    "hosts:\n  app1.prod.internal: {}\n  app2.prod.internal: {}\n",
	"pipelines/site.yaml":      "stages:\n  - name: site\n    hosts: all\n    steps:\n      - recipe: app\n",
	"recipes/app/recipe.yaml": `vars:
  app_port: 8080
steps:
  - unit:
      name: app.service
      source: app.service
    notify: restart
handlers:
  restart:
    - service:
        name: app
        restarted: true
`,
	"recipes/app/files/app.service": "[Service]\nExecStart=/usr/local/bin/app --port 8080\n",
}

// spec: Project layout; CLI
func TestOneFile(t *testing.T) {
	one := vmtest.WriteProject(t, map[string]string{"winch.yaml": oneFile})
	many := vmtest.WriteProject(t, manyFiles)
	for _, args := range [][]string{{"plan", "site"}, {"plan", "site", "--inventory", "prod"}} {
		got := winch(t, one, fakehost.New(), false, "", args...)
		want := winch(t, many, fakehost.New(), false, "", args...)
		// The hash covers the text of the project files, so it differs.
		got.out, want.out = hashLineRe.ReplaceAllString(got.out, "\n"), hashLineRe.ReplaceAllString(want.out, "\n")
		if got.code != exitOK || got.out != want.out || got.err != want.err {
			t.Errorf("%v: one file: exit %d\n%s%s\nmany files: exit %d\n%s%s", args, got.code, got.out, got.err, want.code, want.out, want.err)
		}
	}
	if r := winch(t, one, fakehost.New(), false, "", "plan", "site", "--inventory", "prod"); !strings.Contains(r.out, "app2.prod.internal") {
		t.Errorf("--inventory prod: %s", r.out)
	}
	if r := winch(t, one, fakehost.New(), false, "", "validate"); r.code != exitOK {
		t.Errorf("validate: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Project layout; CLI (winch validate); CLI/Errors
func TestOneFileValidate(t *testing.T) {
	cfg := strings.Replace(oneFile, "inventory: staging\n", "", 1)
	cfg = strings.Replace(cfg, "pipelines:\n", "pipelines:\n  other:\n    stages:\n      - name: o\n        hosts: app1.prod.internal\n        steps:\n          - pkg: {nam: x}\n", 1)
	r := winch(t, vmtest.WriteProject(t, map[string]string{"winch.yaml": cfg}), fakehost.New(), false, "", "validate")
	if want := "winch.yaml:16:19: unknown key \"nam\"; did you mean \"name\"?\nwinch.yaml:16:18: missing key \"name\"\n"; r.code != exitInvalid || r.err != want {
		t.Errorf("validate: exit %d, stderr %q", r.code, r.err)
	}
	// Every inventory of winch.yaml is checked: the host is only in prod.
	cfg = strings.Replace(cfg, "pkg: {nam: x}", "pkg: {name: htop}", 1)
	r = winch(t, vmtest.WriteProject(t, map[string]string{"winch.yaml": cfg}), fakehost.New(), false, "", "validate")
	if want := `winch.yaml:14:16: unknown host or group "app1.prod.internal" in inventories.staging of winch.yaml`; r.code != exitInvalid || !strings.Contains(r.err, want) {
		t.Errorf("validate: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Variables/Secrets (winch secret generate); Project layout
func TestOneFileSecretGenerate(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(oneFile, "name: demo\n", "name: demo\nrecipients:\n  - "+id.Recipient().String()+"\n", 1)
	cfg = strings.Replace(cfg, "--port {{ .vars.app_port }}", "--port {{ .vars.app_port }} --password {{ .vars.pw }}", 1)
	r := winch(t, vmtest.WriteProject(t, map[string]string{"winch.yaml": cfg}), fakehost.New(), false, "", "secret", "generate", "vars.pw", "--inventory", "prod")
	if r.code != exitOK || r.out != "wrote vars.pw into the vars of the group all in inventories.prod of winch.yaml\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
}

// spec: Project layout; CLI
func TestTopLevel(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": `name: simple
hosts:
  web1.example.com: {}
groups:
  all:
    vars:
      domain: example.com
steps:
  - file:
      path: /etc/motd
      content: !tpl "{{ .vars.domain }}\n"
    notify: reload
handlers:
  reload:
    - service:
        name: nginx
        reloaded: true
`})
	r := winch(t, dir, fakehost.New(), false, "", "plan")
	if r.code != exitOK || !strings.Contains(r.out, "web1.example.com") || !strings.Contains(r.out, "/etc/motd") {
		t.Errorf("plan: exit %d\n%s%s", r.code, r.out, r.err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "apply")
	if r.code != exitConfirm || !strings.HasSuffix(r.out, "To apply, run: winch apply --check "+planHash(t, r.out)+"\n") {
		t.Errorf("apply: exit %d\n%s%s", r.code, r.out, r.err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "apply", "site")
	if want := `pipeline "site": the steps at the top of winch.yaml are the only pipeline; leave out the pipeline name`; r.code != exitInvalid || !strings.Contains(r.err, want) {
		t.Errorf("apply site: exit %d, stderr %q", r.code, r.err)
	}
	if r := winch(t, dir, fakehost.New(), false, "", "validate"); r.code != exitOK {
		t.Errorf("validate: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: Variables/Secrets (winch secret generate); Project layout
func TestTopLevelSecretGenerate(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := "name: simple\nrecipients:\n  - " + id.Recipient().String() + "\nhosts:\n  web1:\nsteps:\n  - file:\n      path: /etc/pw\n      content: !tpl \"{{ .vars.pw }}\\n\"\n"
	dir := vmtest.WriteProject(t, map[string]string{"winch.yaml": cfg})
	r := winch(t, dir, fakehost.New(), false, "", "secret", "generate", "vars.pw")
	if r.code != exitOK || r.out != "wrote vars.pw into the vars of the group all in winch.yaml\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	r = winch(t, dir, fakehost.New(), false, "", "secret", "generate", "vars.pw", "--host", "web1")
	if r.code != exitOK || r.out != "wrote vars.pw into the vars of host web1 in winch.yaml\n" {
		t.Errorf("--host: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	if got := readFile(t, filepath.Join(dir, "winch.yaml")); !strings.Contains(got, "\nhosts:\n  web1:\n    vars:\n      pw: !secret ") || !strings.Contains(got, "\ngroups:\n  all:\n    vars:\n      pw: !secret ") {
		t.Errorf("winch.yaml:\n%s", got)
	}
}
