package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Recipes; Running a pipeline/Plan; Remote execution/Facts; Modules/file, dir, link; CLI/Output
func TestRecipes(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "recipes")
	vm.MustRun(t, quietApt)
	// A second inventory host on the same VM, for a recipe whose requirement fails.
	conf, err := os.ReadFile(filepath.Join(lab.Dir, "hosts", vm.Name+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(lab.Dir, "hosts", "recipes-other.conf")
	if err := os.WriteFile(other, []byte(strings.Replace(string(conf), "Host "+vm.Name, "Host recipes-other", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(other) })

	blob := make([]byte, 256<<10)
	rand.Read(blob)
	for i := range 256 {
		blob[i] = byte(i)
	}
	sum := sha256.Sum256(blob)
	web := `  - name: web
    hosts: recipes
    steps:
      - recipe: nginx
`
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  recipes: {}\n  recipes-other: {}\n",
		"pipelines/web.yaml":    "stages:\n" + web,
		"pipelines/site.yaml": "stages:\n" + web + `  - name: other
    hosts: recipes-other
    steps:
      - recipe: ubuntu_only
`,
		"recipes/nginx/recipe.yaml": `require:
  - !expr 'facts.os.id == "debian" and facts.os.version == "13" and facts.os.codename == "trixie"'
steps:
  - name: Site
    file:
      path: /etc/nginx/sites-available/demo
      source: demo.conf
  - file:
      path: /var/www/demo/index.html
      template: index.html.tmpl
  - file:
      path: /var/www/demo/blob.bin
      source: blob/blob.bin
  - link:
      path: /etc/nginx/sites-enabled/demo
      target: /etc/nginx/sites-available/demo
  - pkg:
      name: [nginx, curl]
  - service:
      name: nginx
      running: true
      enabled: true
`,
		"recipes/nginx/files/demo.conf":           "server {\n    listen 8080;\n    root /var/www/demo;\n}\n",
		"recipes/nginx/files/blob/blob.bin":       string(blob),
		"recipes/nginx/templates/index.html.tmpl": "Hello from {{ .host.name }} ({{ .host.short }}).\n",
		"recipes/ubuntu_only/recipe.yaml": `require:
  - !expr 'facts.os.id == "ubuntu"'
steps:
  - file:
      path: /etc/ubuntu
      content: "x\n"
`,
	})

	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 1 || !strings.Contains(r.Stdout, "recipes\n  web\n    nginx\n      + Site: file /etc/nginx/sites-available/demo\n") {
		t.Fatalf("plan: exit %d, want 1 and the steps under the stage and the recipe", r.Code)
	}
	if !strings.Contains(r.Stderr, `recipes-other: recipes/ubuntu_only/recipe.yaml:2:5: recipe ubuntu_only requires facts.os.id == "ubuntu"; the host has os.id "debian"`) {
		t.Errorf("plan: no requirement failure for host recipes-other")
	}

	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 1 || !strings.Contains(r.Stdout, "recipes: + Site: file /etc/nginx/sites-available/demo") {
		t.Fatalf("apply: exit %d, want 1 with the steps of host recipes", r.Code)
	}
	if out, err := vm.Run(t.Context(), "test -e /etc/ubuntu"); err == nil {
		t.Errorf("the host that failed its requirement changed: %s", out)
	}
	if out := vm.MustRun(t, "curl -s http://localhost:8080/"); out != "Hello from recipes (recipes).\n" {
		t.Errorf("page = %q", out)
	}
	if out := vm.MustRun(t, "sha256sum /var/www/demo/blob.bin"); strings.Fields(out)[0] != hex.EncodeToString(sum[:]) {
		t.Errorf("blob.bin on the host: %s, want %x", out, sum)
	}

	r = lab.Winch(t, dir, "plan", "web")
	if r.Code != 0 || r.Stdout != "1 host: 0 to change, 1 unchanged, 0 unknown\n" {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
