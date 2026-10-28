package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spec: Project layout; Variables
func TestOneFileExamples(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "examples")
	// The examples name the host web1.example.com and the user admin, the
	// lab's user.
	conf, err := os.ReadFile(filepath.Join(lab.Dir, "hosts", vm.Name+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	alias, err := lab.WriteHost("web1.example.com", strings.Replace(string(conf), "Host "+vm.Name, "Host web1.example.com", 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(alias) })

	for _, name := range []string{"nginx", "caddy"} {
		r := lab.Winch(t, "../../examples/"+name, "plan")
		if r.Code != 0 || !strings.Contains(r.Stdout, "\n1 host: 1 to change, 0 unchanged, 0 unknown\nplan ") {
			t.Errorf("%s: plan: exit %d, stdout %q, stderr %q", name, r.Code, r.Stdout, r.Stderr)
		}
	}
}
