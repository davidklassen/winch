package run_test

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
	"github.com/davidklassen/winch/internal/run"
	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

var hashFiles = map[string]string{
	"winch.yaml": "name: acme\ninventory: inventories/test.yaml\nvars:\n  greeting:\n",
	"inventories/test.yaml": `hosts:
  web1:
    vars:
      greeting: hello
  web2:
    vars:
      greeting: hi
`,
	"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - file:
          path: /etc/motd
          content: !tpl "{{ .vars.greeting }}\n"
          validate: "true"
        then: echo done
      - dir:
          path: /srv/old
          absent: true
      - cmd:
          command: make
          creates: /srv/built
      - dir:
          path: /srv/www
          replace: true
      - recipe: app
  - name: extra
    hosts: all
    parallelism: 2
    health:
      command: check
      stable: 1
      timeout: 10
    steps:
      - file:
          path: /etc/issue
          content: "x\n"
`,
	"recipes/app/recipe.yaml": `steps:
  - file:
      path: /etc/app.conf
      content: "a\n"
    notify: reload
handlers:
  reload:
    - service:
        name: app
        reloaded: true
`,
}

// removeOld is the check result of the dir absent step of hashFiles.
func removeOld(files int) module.Result {
	return module.Result{Status: module.Change, Action: module.Remove,
		Changes: []string{"remove its content: " + map[int]string{2: "2 files", 3: "3 files"}[files] + ", 1 directory"}}
}

// replaceWWW is the check result of the dir replace step of hashFiles.
func replaceWWW(files int) module.Result {
	return module.Result{Status: module.Change, Action: module.Create,
		Changes: []string{"remove the directory: " + map[int]string{2: "2 files", 3: "3 files"}[files], "owner root, group root, mode 0755"}}
}

// planHash plans the project of files on hosts that setup prepares.
func planHash(t *testing.T, files map[string]string, setup func(h *fakehost.Hosts)) *run.Plan {
	t.Helper()
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{})
	if err != nil {
		t.Fatal(err)
	}
	h := fakehost.New()
	for _, host := range []string{"web1", "web2"} {
		h.SetResult(host, "/srv/old", removeOld(2))
		h.SetResult(host, "/srv/www", replaceWWW(2))
	}
	if setup != nil {
		setup(h)
	}
	return run.MakePlan(context.Background(), p, h.Connector(), run.Options{})
}

// edit returns hashFiles with old replaced by new in file.
func edit(t *testing.T, file, old, new string) map[string]string {
	t.Helper()
	files := maps.Clone(hashFiles)
	if !strings.Contains(files[file], old) {
		t.Fatalf("%s has no %q", file, old)
	}
	files[file] = strings.Replace(files[file], old, new, 1)
	return files
}

// spec: Running a pipeline/Plan
func TestHashStable(t *testing.T) {
	a := planHash(t, hashFiles, nil)
	b := planHash(t, hashFiles, nil)
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(a.Hash()) {
		t.Errorf("hash %q is not 16 hex characters", a.Hash())
	}
	if a.Hash() != b.Hash() {
		t.Errorf("two plans of the same state: %s and %s", a.Hash(), b.Hash())
	}
	if len(a.HashInput()) == 0 {
		t.Error("the hash input is empty")
	}
}

// spec: Running a pipeline/Plan; Modules/file, dir, link
func TestHashChanges(t *testing.T) {
	base := planHash(t, hashFiles, nil).Hash()
	tests := []struct {
		name  string
		files func(t *testing.T) map[string]string
		setup func(h *fakehost.Hosts)
	}{
		{name: "content on the host", setup: func(h *fakehost.Hosts) { h.SetFile("web1", "/etc/motd", "old\n") }},
		{name: "a step argument", files: func(t *testing.T) map[string]string {
			return edit(t, "pipelines/site.yaml", `content: "x\n"`, `content: "y\n"`)
		}},
		{name: "a validate command", files: func(t *testing.T) map[string]string {
			return edit(t, "pipelines/site.yaml", `validate: "true"`, `validate: "/bin/true"`)
		}},
		{name: "a then command", files: func(t *testing.T) map[string]string {
			return edit(t, "pipelines/site.yaml", "then: echo done", "then: echo ok")
		}},
		{name: "a handler step", files: func(t *testing.T) map[string]string {
			return edit(t, "recipes/app/recipe.yaml", "reloaded: true", "restarted: true")
		}},
		{name: "a cmd whose creates exists", setup: func(h *fakehost.Hosts) { h.SetFile("web1", "/srv/built", "") }},
		{name: "a pending handler", setup: func(h *fakehost.Hosts) { h.SetPending("web1", "app.reload") }},
		{name: "a pending then", setup: func(h *fakehost.Hosts) {
			h.SetThen("web2", protocol.Then{Pipeline: "site", Stage: "extra", Step: 1})
		}},
		{name: "the stage order", files: func(t *testing.T) map[string]string {
			files := maps.Clone(hashFiles)
			pl := files["pipelines/site.yaml"]
			i := strings.Index(pl, "  - name: extra")
			files["pipelines/site.yaml"] = "stages:\n" + pl[i:] + pl[len("stages:\n"):i]
			return files
		}},
		{name: "the values of two hosts swapped", files: func(t *testing.T) map[string]string {
			files := maps.Clone(hashFiles)
			files["inventories/test.yaml"] = "hosts:\n  web1:\n    vars:\n      greeting: hi\n  web2:\n    vars:\n      greeting: hello\n"
			return files
		}},
		{name: "the counts of dir absent", setup: func(h *fakehost.Hosts) { h.SetResult("web2", "/srv/old", removeOld(3)) }},
		{name: "the counts of replace", setup: func(h *fakehost.Hosts) { h.SetResult("web2", "/srv/www", replaceWWW(3)) }},
		{name: "a failed host", setup: func(h *fakehost.Hosts) { h.FailCheck("web2 /etc/issue") }},
		{name: "parallelism", files: func(t *testing.T) map[string]string {
			return edit(t, "pipelines/site.yaml", "parallelism: 2", "parallelism: 1")
		}},
		{name: "the health command", files: func(t *testing.T) map[string]string {
			return edit(t, "pipelines/site.yaml", "command: check", "command: check2")
		}},
		{name: "the health stable time", files: func(t *testing.T) map[string]string {
			return edit(t, "pipelines/site.yaml", "stable: 1", "stable: 2")
		}},
		{name: "the health timeout", files: func(t *testing.T) map[string]string {
			return edit(t, "pipelines/site.yaml", "timeout: 10", "timeout: 11")
		}},
		{name: "another address", files: func(t *testing.T) map[string]string {
			return edit(t, "inventories/test.yaml", "web1:\n", "web1:\n    address: 192.0.2.10\n")
		}},
		{name: "another user", files: func(t *testing.T) map[string]string {
			return edit(t, "inventories/test.yaml", "web1:\n", "web1:\n    user: deploy\n")
		}},
		{name: "another project name", files: func(t *testing.T) map[string]string {
			return edit(t, "winch.yaml", "name: acme", "name: acme2")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := hashFiles
			if tt.files != nil {
				files = tt.files(t)
			}
			if got := planHash(t, files, tt.setup).Hash(); got == base {
				t.Errorf("hash %s did not change", got)
			}
		})
	}
}

// hashSecretProject loads a project whose pipeline reads the secret pw.
func hashSecretProject(t *testing.T, value, pipeline string, recipe string) *project.Project {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(identity, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := secret.ParseRecipients([]string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	text, err := secret.Encrypt(value, rec)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"winch.yaml":            "name: acme\ninventory: inventories/test.yaml\nrecipients: [" + id.Recipient().String() + "]\nvars:\n  pw:\n",
		"inventories/test.yaml": "hosts:\n  web1:\n    vars:\n      pw: !secret " + text + "\n",
		"pipelines/site.yaml":   pipeline,
	}
	if recipe != "" {
		files["recipes/app/recipe.yaml"] = recipe
	}
	p, err := project.Load(t.Context(), vmtest.WriteProject(t, files), "", "site", nil, project.Keys{Identity: secret.Identity{Path: identity}, Filter: secret.NewFilter()})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const stage = "stages:\n  - name: base\n    hosts: all\n    steps:\n"

// spec: Running a pipeline/Plan; Variables/Secrets in output
func TestHashSecret(t *testing.T) {
	tests := []struct{ name, pipeline, recipe string }{
		{name: "every argument", pipeline: stage + `      - file:
          path: !tpl "/etc/{{ .vars.pw }}.key"
          content: !tpl "password {{ .vars.pw }}\n"
          owner: !tpl "u{{ .vars.pw }}"
        then: !tpl "passwd {{ .vars.pw }}"
`},
		{name: "then only", pipeline: stage + `      - file:
          path: /etc/pw
          content: "x\n"
        then: !tpl "passwd {{ .vars.pw }}"
`},
		{name: "owner only", pipeline: stage + `      - file:
          path: /etc/pw
          content: "x\n"
          owner: !tpl "u{{ .vars.pw }}"
`},
		{name: "content only", pipeline: stage + `      - file:
          path: /etc/pw
          content: !tpl "password {{ .vars.pw }}\n"
`},
		{name: "a loop item", pipeline: stage + `      - file:
          path: !tpl "/etc/{{ .item }}"
          content: "x\n"
        loop: !expr '[vars.pw]'
`},
		{name: "a handler step", pipeline: stage + "      - recipe: app\n", recipe: `steps:
  - file:
      path: /etc/app.conf
      content: "a\n"
    notify: reload
handlers:
  reload:
    - service:
        name: !tpl "app-{{ .vars.pw }}"
        reloaded: true
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := func(value string) *run.Plan {
				h := fakehost.New()
				// The old content holds the value too.
				h.SetFile("web1", "/etc/pw", "password "+value+" old\n")
				h.SetFile("web1", "/etc/"+value+".key", "password "+value+" old\n")
				return run.MakePlan(context.Background(), hashSecretProject(t, value, tt.pipeline, tt.recipe), h.Connector(), run.Options{})
			}
			for _, short := range []bool{false, true} {
				old, new := "hunter2", "hunter3"
				if short {
					old, new = "h2", "h3"
				}
				a, b := plan(old), plan(new)
				if a.Hash() == b.Hash() {
					t.Errorf("a new secret value %q did not change the hash", new)
				}
				for _, p := range []*run.Plan{a, b} {
					if len(p.Failed) > 0 {
						t.Fatalf("the plan failed: %v", p.Failed)
					}
					in := string(p.HashInput())
					for _, v := range []string{old, new, secret.Placeholder(1), secret.Placeholder(2)} {
						if strings.Contains(in, v) {
							t.Errorf("the hash input holds %q:\n%s", v, in)
						}
					}
				}
			}
		})
	}
}

// spec: Running a pipeline/Plan
func TestHashOldContent(t *testing.T) {
	plan := func(old string) string {
		return planHash(t, hashFiles, func(h *fakehost.Hosts) { h.SetFile("web1", "/etc/motd", old) }).Hash()
	}
	if plan("old1\n") == plan("old2\n") {
		t.Error("the old content of a changed file did not change the hash")
	}
}

// handlerFilesWith returns the files of a recipe whose file step is ok on
// both hosts. Its notify and its handler steps never run in the plan.
func handlerFilesWith(t *testing.T, notify, action string) map[string]string {
	t.Helper()
	files := maps.Clone(hashFiles)
	files["recipes/app/recipe.yaml"] = `steps:
  - file:
      path: /etc/app.conf
      content: "a\n"
    notify: ` + notify + `
handlers:
  reload:
    - service:
        name: app
        ` + action + `: true
  restart:
    - service:
        name: app
        restarted: true
`
	return files
}

// spec: Running a pipeline/Plan ("the hash covers the evaluated steps")
func TestHashSteps(t *testing.T) {
	present := func(h *fakehost.Hosts) {
		h.SetFile("web1", "/etc/app.conf", "a\n")
		h.SetFile("web2", "/etc/app.conf", "a\n")
	}
	base := planHash(t, handlerFilesWith(t, "reload", "reloaded"), present).Hash()
	if got := planHash(t, handlerFilesWith(t, "restart", "reloaded"), present).Hash(); got == base {
		t.Error("a new notify of a step without a change did not change the hash")
	}
	if got := planHash(t, handlerFilesWith(t, "reload", "restarted"), present).Hash(); got == base {
		t.Error("a new step of a handler that does not run did not change the hash")
	}
}

// spec: Running a pipeline/Plan ("the order of the stages")
func TestHashStageOrderDisjointHosts(t *testing.T) {
	migrate := "  - name: migrate\n    hosts: web1\n    steps:\n      - file:\n          path: /etc/migrate\n          content: \"m\\n\"\n"
	deploy := "  - name: deploy\n    hosts: web2\n    steps:\n      - file:\n          path: /etc/deploy\n          content: \"d\\n\"\n"
	plan := func(pipeline string) string {
		files := maps.Clone(hashFiles)
		files["pipelines/site.yaml"] = pipeline
		return planHash(t, files, nil).Hash()
	}
	if a, b := plan("stages:\n"+migrate+deploy), plan("stages:\n"+deploy+migrate); a == b {
		t.Errorf("two swapped stages on disjoint hosts give one hash %s", a)
	}
}
