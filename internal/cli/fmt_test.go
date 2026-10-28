package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
	"github.com/davidklassen/winch/internal/vmtest"
)

// planOf returns the plan hash of the pipeline site of the project in dir.
func planOf(t *testing.T, dir string) string {
	t.Helper()
	r := winch(t, dir, fakehost.New(), false, "", "plan", "site")
	if r.code != exitOK {
		t.Fatalf("plan: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	return planHash(t, r.out)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// spec: CLI (winch fmt); Steps (winch fmt)
func TestFmt(t *testing.T) {
	files := map[string]string{
		"winch.yaml": "name: acme\ninventory: hosts\nvars:\n    domain: example.com\n" + `recipes:
    other:
        steps:
        -   notify: done
            pkg:
                name: htop
        handlers:
            done:
            -   cmd:
                    command: "true"
                name: Done
pipelines:
    extra:
        stages:
        -   name: x
            hosts: all
            steps:
            -   notify: [other.done, x]
                pkg:
                    name: curl
            handlers:
                x:
                -   cmd:
                        command: "true"
                    name: X
    quick:
        steps:
        -   notify: y
            pkg:
                name: jq
        handlers:
            y:
            -   cmd:
                    command: "true"
                name: Y
`,
		"inventories/hosts.yaml": "hosts:\n    web1: {}\n    web2:\n        vars:\n            motd_text: hi\n",
		"pipelines/short.yaml": `steps:
-   notify: z
    pkg:
        name: tree
handlers:
    z:
    -   cmd:
            command: "true"
        name: Z
`,
		"pipelines/site.yaml": `stages:
-   name: base
    hosts: all
    steps:
    -   recipe: motd
        name: The motd
    -   notify: reload
        file:
            path: /etc/issue
            content: hi
    handlers:
        reload:
        -   cmd:
                command: "true"
            name: Reload
`,
		"recipes/motd/recipe.yaml": `vars:
    motd_text: hello
steps:
-   notify: done
    file:
        path: /etc/motd
        content: !tpl "{{ .vars.motd_text }}\n"
handlers:
    done:
    -   cmd:
            command: "true"
        name: Done
`,
		"recipes/motd/files/data.yaml": "a:\n    b: 1\n",
		"pipelines/old.yml":            "a:\n    b: 1\n",
	}
	dir := vmtest.WriteProject(t, files)
	before := planOf(t, dir)

	r := winch(t, dir, fakehost.New(), false, "", "fmt")
	want := "inventories/hosts.yaml\npipelines/short.yaml\npipelines/site.yaml\nrecipes/motd/recipe.yaml\nwinch.yaml\n"
	if r.code != exitOK || r.out != want || r.err != "" {
		t.Fatalf("fmt: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	formatted := map[string]string{
		"winch.yaml": "name: acme\ninventory: hosts\nvars:\n  domain: example.com\n" + `recipes:
  other:
    steps:
      - pkg:
          name: htop
        notify: done
    handlers:
      done:
        - name: Done
          cmd:
            command: "true"
pipelines:
  extra:
    stages:
      - name: x
        hosts: all
        steps:
          - pkg:
              name: curl
            notify: [other.done, x]
        handlers:
          x:
            - name: X
              cmd:
                command: "true"
  quick:
    steps:
      - pkg:
          name: jq
        notify: y
    handlers:
      y:
        - name: Y
          cmd:
            command: "true"
`,
		"inventories/hosts.yaml": "hosts:\n  web1: {}\n  web2:\n    vars:\n      motd_text: hi\n",
		"pipelines/short.yaml": `steps:
  - pkg:
      name: tree
    notify: z
handlers:
  z:
    - name: Z
      cmd:
        command: "true"
`,
		"pipelines/site.yaml": `stages:
  - name: base
    hosts: all
    steps:
      - name: The motd
        recipe: motd
      - file:
          path: /etc/issue
          content: hi
        notify: reload
    handlers:
      reload:
        - name: Reload
          cmd:
            command: "true"
`,
		"recipes/motd/recipe.yaml": `vars:
  motd_text: hello
steps:
  - file:
      path: /etc/motd
      content: !tpl "{{ .vars.motd_text }}\n"
    notify: done
handlers:
  done:
    - name: Done
      cmd:
        command: "true"
`,
		"recipes/motd/files/data.yaml": files["recipes/motd/files/data.yaml"],
		"pipelines/old.yml":            files["pipelines/old.yml"],
	}
	for name, want := range formatted {
		if got := readFile(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s:\n%s\nwant\n%s", name, got, want)
		}
	}
	if after := planOf(t, dir); after != before {
		t.Errorf("plan hash %s after fmt, %s before", after, before)
	}

	r = winch(t, dir, fakehost.New(), false, "", "fmt")
	if r.code != exitOK || r.out != "" {
		t.Errorf("second fmt: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
}

// spec: CLI (winch fmt); CLI/Errors
func TestFmtError(t *testing.T) {
	files := map[string]string{
		"winch.yaml":               "name: acme\nvars:\n    domain: example.com\n",
		"pipelines/site.yaml":      "stages: [\n",
		"recipes/motd/recipe.yaml": "steps:\n    - pkg:\n          name: a\n      pkg:\n          name: b\n",
	}
	dir := vmtest.WriteProject(t, files)
	r := winch(t, dir, fakehost.New(), false, "", "fmt")
	want := "pipelines/site.yaml:1:1: did not find expected node content\nrecipes/motd/recipe.yaml:4:7: duplicate key \"pkg\" (first at line 2)\n"
	if r.code != exitInvalid || r.out != "" || r.err != want {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	for name, want := range files {
		if got := readFile(t, filepath.Join(dir, name)); got != want {
			t.Errorf("fmt changed %s", name)
		}
	}
	r = winch(t, dir, fakehost.New(), false, "", "fmt", "site")
	if r.code != exitInvalid || r.err != "winch: fmt takes no arguments\n" {
		t.Errorf("with an argument: exit %d, stderr %q", r.code, r.err)
	}
}

// spec: CLI (winch fmt)
func TestFmtFiles(t *testing.T) {
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":             "name: acme\nnope:\n    a: 1\n",
		"pipelines/a.yaml":       "stages:\n-   name: a\n",
		"inventories/hosts.yaml": "hosts:\n    web1: {}\n",
	})
	if err := os.Symlink("a.yaml", filepath.Join(dir, "pipelines/b.yaml")); err != nil {
		t.Fatal(err)
	}
	r := winch(t, dir, fakehost.New(), false, "", "fmt")
	want := "inventories/hosts.yaml\npipelines/a.yaml\nwinch.yaml\n"
	if r.code != exitOK || r.out != want {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
	}
	if got := readFile(t, filepath.Join(dir, "pipelines/b.yaml")); got != "stages:\n  - name: a\n" {
		t.Errorf("pipelines/b.yaml = %q", got)
	}
	if info, err := os.Lstat(filepath.Join(dir, "pipelines/b.yaml")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("pipelines/b.yaml is no longer a link: %v", err)
	}
}

func TestExamplesFormatted(t *testing.T) {
	entries, err := os.ReadDir("../../examples")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.CopyFS(dir, os.DirFS(filepath.Join("../../examples", e.Name()))); err != nil {
				t.Fatal(err)
			}
			r := winch(t, dir, fakehost.New(), false, "", "fmt")
			if r.code != exitOK || r.out != "" {
				t.Errorf("fmt changes the example: exit %d, stdout %q, stderr %q", r.code, r.out, r.err)
			}
		})
	}
}
