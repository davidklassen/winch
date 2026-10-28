package integration

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/vmtest"
)

// spec: Templates and expressions/Template functions
func TestSQLQuote(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "sqlquote")
	values := []string{"it's", `a\b`, "a\nb", `\'`, `x\'; SELECT 1; --`, "''", "über"}
	var vars strings.Builder
	vars.WriteString("vars:\n  values:\n")
	for _, v := range values {
		vars.WriteString("    - " + strconv.Quote(v) + "\n")
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n" + vars.String(),
		"inventories/test.yaml": "hosts:\n  sqlquote: {}\n",
		"pipelines/site.yaml": `stages:
  - name: db
    hosts: all
    steps:
      - pkg:
          name: [mariadb-server, postgresql]
      - file:
          path: /root/q.mariadb
          content: !tpl "{{ range .vars.values }}SELECT HEX({{ sqlquote . }});\n{{ end }}"
      - file:
          path: /root/q.pg
          content: !expr 'join(map(vars.values, "SELECT encode(convert_to(E" + sqlquote(#) + ", ''UTF8''), ''hex'');\n"), "")'
`,
	})

	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d", r.Code)
	}
	var want strings.Builder
	for _, v := range values {
		want.WriteString(hex.EncodeToString([]byte(v)) + "\n")
	}
	if got := vm.MustRun(t, "mariadb -N -B < /root/q.mariadb"); got != strings.ToUpper(want.String()) {
		t.Errorf("MariaDB reads %q as hex\n%s\nwant\n%s", values, got, strings.ToUpper(want.String()))
	}
	if got := vm.MustRun(t, "runuser -u postgres -- psql -X -q -t -A < /root/q.pg"); got != want.String() {
		t.Errorf("PostgreSQL reads %q as hex\n%s\nwant\n%s", values, got, want.String())
	}
}
