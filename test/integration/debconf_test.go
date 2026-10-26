package integration

import (
	"regexp"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Modules/debconf
func TestDebconfModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "debconf")
	// winch-ask has a question of each type.
	vm.MustRun(t, "apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q winch-ask >/dev/null")
	get := func(q, want string) string {
		return "[ \"$(echo 'GET " + q + "' | debconf-communicate)\" = '0 " + want + "' ]"
	}
	reset := "rm -f /root/locked /root/released; echo PURGE | debconf-communicate winch-later >/dev/null; " +
		"printf 'RESET winch-ask/name\\nRESET winch-ask/enabled\\nRESET winch-ask/mode\\nRESET winch-ask/level\\nRESET winch-ask/features\\nRESET winch-ask/secret\\n' | debconf-communicate winch-ask >/dev/null"
	set := func(line string) string { return "echo '" + line + "' | debconf-set-selections" }
	vmtest.RunCases(t, vm, "debconf", reset, []vmtest.Case{
		{
			Name:      "a question that does not exist yet",
			Args:      &module.Debconf{Package: "winch-later", Question: "winch-later/greeting", Type: "string", Value: "hello there"},
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{`answer (none) → "hello there"`}},
			Unchanged: "echo 'GET winch-later/greeting' | debconf-communicate | grep -q '^10 '",
			After:     get("winch-later/greeting", "hello there"),
		},
		{
			Name:      "change an answer",
			Args:      &module.Debconf{Package: "winch-ask", Question: "winch-ask/name", Type: "string", Value: "y"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{`answer "x" → "y"`}},
			Unchanged: get("winch-ask/name", "x"),
			After:     get("winch-ask/name", "y"),
		},
		{
			Name: "the same answer",
			Args: &module.Debconf{Package: "winch-ask", Question: "winch-ask/name", Type: "string", Value: "x"},
			Want: module.Result{Status: module.OK},
		},
		{
			Name:  "a boolean",
			Args:  &module.Debconf{Package: "winch-ask", Question: "winch-ask/enabled", Type: "boolean", Value: "true"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{`answer "false" → "true"`}},
			After: get("winch-ask/enabled", "true"),
		},
		{
			Name:  "a select choice",
			Args:  &module.Debconf{Package: "winch-ask", Question: "winch-ask/mode", Type: "select", Value: "two"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{`answer "one" → "two"`}},
			After: get("winch-ask/mode", "two"),
		},
		{
			Name:    "a select value outside the choices",
			Args:    &module.Debconf{Package: "winch-ask", Question: "winch-ask/mode", Type: "select", Value: "four"},
			WantErr: `"four" is not a choice of winch-ask/mode; the choices are one, two, three`,
		},
		{
			Name:  "a select with choices for the C locale",
			Args:  &module.Debconf{Package: "winch-ask", Question: "winch-ask/level", Type: "select", Value: "high"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{`answer "low" → "high"`}},
			After: get("winch-ask/level", "high"),
		},
		{
			Name:    "a select value that is a shown choice",
			Args:    &module.Debconf{Package: "winch-ask", Question: "winch-ask/level", Type: "select", Value: "High level"},
			WantErr: `"High level" is not a choice of winch-ask/level; the choices are low, high`,
		},
		{
			Name:  "a multiselect in another order",
			Setup: set("winch-ask winch-ask/features multiselect a, b"),
			Args:  &module.Debconf{Package: "winch-ask", Question: "winch-ask/features", Type: "multiselect", Value: "b, a"},
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "a multiselect value outside the choices",
			Args:    &module.Debconf{Package: "winch-ask", Question: "winch-ask/features", Type: "multiselect", Value: "a, d"},
			WantErr: `"d" is not a choice of winch-ask/features; the choices are a, b, c`,
		},
		{
			Name:      "a password",
			Setup:     set("winch-ask winch-ask/secret password old-pass"),
			Args:      &module.Debconf{Package: "winch-ask", Question: "winch-ask/secret", Type: "password", Value: "new-pass"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"answer (password, not shown)"}},
			Unchanged: get("winch-ask/secret", "old-pass"),
			After:     get("winch-ask/secret", "new-pass"),
		},
		{
			Name:  "a value that ends in a backslash",
			Args:  &module.Debconf{Package: "winch-later", Question: "winch-later/path", Type: "string", Value: `C:\dir\`},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{`answer (none) → "C:\\dir\\"`}},
			After: get("winch-later/path", `C:\dir\`),
		},
		{
			Name:  "a value with spaces at the ends",
			Args:  &module.Debconf{Package: "winch-later", Question: "winch-later/pad", Type: "string", Value: " a b "},
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{`answer (none) → " a b "`}},
			After: get("winch-later/pad", " a b "),
		},
		{
			Name: "choices with a variable",
			Setup: "printf 'Template: winch-later/pick\\nType: select\\nChoices: none, ${extra}\\nDescription: x\\n' > /root/t && " +
				"echo 'X_LOADTEMPLATEFILE /root/t' | debconf-communicate winch-later >/dev/null",
			Args: &module.Debconf{Package: "winch-later", Question: "winch-later/pick", Type: "select", Value: "other"},
			Want: module.Result{Status: module.Change, Action: module.Modify, Changes: []string{`answer "" → "other"`}},
		},
		{
			Name:  "a type that an earlier answer gave",
			Setup: set("winch-later winch-later/flag string yes"),
			Args:  &module.Debconf{Package: "winch-later", Question: "winch-later/flag", Type: "boolean", Value: "true"},
			Want:  module.Result{Status: module.Change, Action: module.Modify, Changes: []string{`answer "yes" → "true"`}},
		},
		{
			Name: "a check waits for apt",
			// The fcntl lock of apt, which a background process holds for 2 s.
			Setup: `(python3 -c 'from fcntl import lockf, LOCK_EX; import time; f = open("/var/lib/dpkg/lock-frontend", "w"); lockf(f, LOCK_EX); open("/root/locked", "w"); time.sleep(2); open("/root/released", "w")' >/dev/null 2>&1 &) && ` +
				"timeout 10 sh -c 'until [ -e /root/locked ]; do sleep 0.1; done'",
			Args:      &module.Debconf{Package: "winch-ask", Question: "winch-ask/name", Type: "string", Value: "z"},
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{`answer "x" → "z"`}},
			Unchanged: "[ -e /root/released ]",
		},
		{
			Name:    "a type that differs from the template",
			Args:    &module.Debconf{Package: "winch-ask", Question: "winch-ask/name", Type: "boolean", Value: "true"},
			WantErr: "winch-ask/name is a string question, not boolean",
		},
	})
}

// spec: Modules/repo; Modules/debconf; Modules/pkg
func TestPackageSources(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "sources")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":                              "name: acme\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml":                   "hosts:\n  " + vm.Name + ": {}\n",
		"pipelines/site.yaml":                     "stages:\n  - name: packages\n    hosts: all\n    steps:\n      - recipe: packages\n",
		"recipes/packages/files/winch-signed.asc": string(vmtest.RepoKey),
		"recipes/packages/recipe.yaml": `steps:
  - pkg:
      name: hello
  - repo:
      name: winch-signed
      url: ` + signedURL + `
      suite: !expr facts.os.codename
      components: [main]
      key: winch-signed.asc
  - debconf:
      package: winch-signed
      question: winch-signed/greeting
      type: string
      value: hi from winch
  - pkg:
      name: winch-signed
  - pkg:
      name: sl
`,
	})
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 {
		t.Fatalf("plan: exit %d", r.Code)
	}
	for _, want := range []string{"refresh the index of source winch-signed", `answer (none) → "hi from winch"`, "install winch-signed"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("the plan does not show %q", want)
		}
	}
	// The first install refreshes, and the first install after the repo
	// step refreshes again. The index on the host does not know
	// winch-signed before the refresh.
	want := regexp.MustCompile(`(?s)\+ pkg hello\n\s+refresh the package index\n.*\+ pkg winch-signed\n\s+refresh the package index\n\s+install winch-signed\n\s+other packages: known after the refresh\n\s+\+ pkg sl\n\s+install sl\n`)
	if n := strings.Count(r.Stdout, "refresh the package index"); n != 2 || !want.MatchString(r.Stdout) {
		t.Errorf("the plan does not refresh before hello and before winch-signed only")
	}
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	if out := vm.MustRun(t, "cat /etc/winch-signed.conf"); out != "hi from winch\n" {
		t.Errorf("/etc/winch-signed.conf = %q", out)
	}
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q", r.Code, r.Stdout)
	}
}
