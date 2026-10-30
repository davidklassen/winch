package integration

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/secret"
	"github.com/davidklassen/winch/internal/vmtest"
)

const manyPipeline = `stages:
  - name: base
    hosts: all
    steps:
      - recipe: app
  - name: web
    hosts: web
    parallelism: 1
    health:
      command: test -e /root/healthy
      stable: 1
      timeout: 5
    steps:
      - file:
          path: /root/web
          content: !tpl "{{ .vars.web_text }}\n"
        then: date +%s.%N >> /root/times && sleep 2 && date +%s.%N >> /root/times
      - recipe: peers
        vars:
          peers_list: !expr 'filter(match("all"), .name != host.name)'
          peers_token: !expr 'vars.token + "-x"'
  - name: conf
    hosts: all
    steps:
      - file:
          path: /etc/winch-app/extra.conf
          content: !tpl "{{ .vars.web_text }}\n"
        notify: app.reload
`

const hangPipeline = `stages:
  - name: hang
    hosts: many-a
    health:
      command: sleep 300
      timeout: 3
    steps:
      - file:
          path: /root/hang
          content: "x\n"
`

// manyTokens are the secret tokens of the two hosts. No output may hold
// them.
var manyTokens = [2]string{"many-token-aaaa", "many-token-bbbb"}

// spec: Running a pipeline/Order; Running a pipeline/Health gates; Running a pipeline/Failures; Handlers; Templates and expressions/Data; Variables/Sources; Variables/Secrets in output; CLI
func TestMany(t *testing.T) {
	t.Parallel()
	vms := []*vmtest.VM{lab.StartVM(t, "many-a"), lab.StartVM(t, "many-b")}
	for _, vm := range vms {
		vm.MustRun(t, "touch /root/healthy")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := secret.ParseRecipients([]string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	var sealed [2]string
	for i, tok := range manyTokens {
		if sealed[i], err = secret.Encrypt(tok, rec); err != nil {
			t.Fatal(err)
		}
	}
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml": "name: many\ninventory: test\nrecipients: [" + id.Recipient().String() + "]\n" +
			"vars:\n  web_text: one\n",
		"inventories/test.yaml": "hosts:\n  many-a:\n    vars:\n      token: !secret " + sealed[0] + "\n  many-b:\n    vars:\n      token: !secret " + sealed[1] + "\n" +
			"groups:\n  web:\n    hosts: [many-a, many-b]\n",
		"pipelines/site.yaml": manyPipeline,
		"pipelines/hang.yaml": hangPipeline,
		"recipes/app/recipe.yaml": `steps:
  - file:
      path: /etc/winch-app/app.conf
      content: "app\n"
handlers:
  reload:
    - service:
        name: ssh
        reloaded: true
`,
		"recipes/peers/recipe.yaml": `steps:
  - file:
      path: /etc/peers
      template: peers.tmpl
  - file:
      path: /etc/peers-token
      content: !tpl "{{ .vars.peers_token }}\n"
      mode: "0600"
`,
		"recipes/peers/templates/peers.tmpl": "{{ range .vars.peers_list }}{{ .name }} {{ .short }} {{ .vars.token }}\n{{ end }}",
	})
	keyFile := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"WINCH_AGE_KEY=" + keyFile}
	winch := func(args ...string) vmtest.Result {
		t.Helper()
		r := lab.WinchEnv(t, dir, env, args...)
		noSecrets(t, strings.Join(args, " "), r.Stdout+r.Stderr, manyTokens[0], manyTokens[1])
		return r
	}
	const records = "sed '/^version 1$/d' /var/lib/winch/handlers/many 2>/dev/null; true"

	t.Run("match() peers and step vars render, secrets show as (secret)", func(t *testing.T) {
		r := winch("plan", "site")
		for _, want := range []string{"+many-b many-b (secret)\n", "+many-a many-a (secret)\n", "+(secret)-x\n"} {
			if !strings.Contains(r.Stdout, want) {
				t.Errorf("plan: no %q in the output", want)
			}
		}
	})

	t.Run("parallelism 1 changes one host at a time", func(t *testing.T) {
		r := winch("apply", "site", "--yes")
		if r.Code != 0 || !strings.Contains(r.Stdout, "many-a: web: * health: test -e /root/healthy\n") {
			t.Fatalf("apply: exit %d", r.Code)
		}
		var times [2][2]float64
		for i, vm := range vms {
			lines := strings.Fields(vm.MustRun(t, "cat /root/times"))
			if len(lines) != 2 {
				t.Fatalf("%s: times %q", vm.Name, lines)
			}
			for j, l := range lines {
				if times[i][j], err = strconv.ParseFloat(l, 64); err != nil {
					t.Fatal(err)
				}
			}
		}
		if !(times[0][1] <= times[1][0] || times[1][1] <= times[0][0]) {
			t.Errorf("the hosts ran the web stage at the same time: %v", times)
		}
		if out := vms[0].MustRun(t, "cat /etc/peers"); out != "many-b many-b "+manyTokens[1]+"\n" {
			t.Errorf("many-a /etc/peers = %q", out)
		}
		if out := vms[1].MustRun(t, "cat /etc/peers-token"); out != manyTokens[1]+"-x\n" {
			t.Errorf("many-b /etc/peers-token = %q", out)
		}
		if r := winch("plan", "site"); r.Code != 0 || !unchanged(r.Stdout, 2) {
			t.Errorf("second plan: exit %d", r.Code)
		}
	})

	t.Run("--hosts and --stages select the steps", func(t *testing.T) {
		r := winch("plan", "site", "--set", "vars.web_text=two", "--hosts", "many-b")
		if r.Code != 0 || strings.Contains(r.Stdout, "many-a") || !strings.Contains(r.Stdout, "many-b\n  web\n    ~ file /root/web\n") {
			t.Errorf("plan --hosts many-b: exit %d", r.Code)
		}
		r = winch("plan", "site", "--set", "vars.web_text=two", "--stages", "web")
		if r.Code != 0 || strings.Contains(r.Stdout, "extra.conf") || !strings.Contains(r.Stdout, "many-a, many-b (2 hosts)\n  web\n    ~ file /root/web\n") {
			t.Errorf("plan --stages web: exit %d", r.Code)
		}
		r = winch("apply", "site", "--yes", "--set", "vars.web_text=two", "--hosts", "many-b", "--stages", "web")
		if r.Code != 0 || vms[0].MustRun(t, "cat /root/web") != "one\n" || vms[1].MustRun(t, "cat /root/web") != "two\n" {
			t.Errorf("apply --hosts many-b --stages web: exit %d", r.Code)
		}
	})

	t.Run("--stages without the recipe's stage keeps its handler pending", func(t *testing.T) {
		r := winch("apply", "site", "--yes", "--set", "vars.web_text=two", "--stages", "conf")
		if r.Code != 0 || strings.Contains(r.Stdout, "handler") {
			t.Fatalf("apply --stages conf: exit %d", r.Code)
		}
		for _, vm := range vms {
			if out := vm.MustRun(t, records); out != "app.reload\n" {
				t.Errorf("%s: pending handlers %q, want app.reload", vm.Name, out)
			}
		}
		r = winch("apply", "site", "--yes", "--set", "vars.web_text=two")
		if r.Code != 0 || strings.Count(r.Stdout, ": app: ~ handler app.reload: service ssh") != 2 {
			t.Errorf("full apply: exit %d, want the handler on both hosts", r.Code)
		}
		for _, vm := range vms {
			if out := vm.MustRun(t, records); out != "" {
				t.Errorf("%s: pending handlers %q after the full run", vm.Name, out)
			}
		}
	})

	t.Run("a failing health gate stops the next host", func(t *testing.T) {
		vms[0].MustRun(t, "rm /root/healthy")
		r := winch("apply", "site", "--yes", "--set", "vars.web_text=three")
		if r.Code != 1 || !strings.Contains(r.Stderr, "many-a: web: failed: health: test -e /root/healthy: did not pass within 5s") ||
			!strings.Contains(r.Stderr, "many-b: not started: many-a failed in stage web") {
			t.Errorf("apply: exit %d", r.Code)
		}
		if out := vms[1].MustRun(t, "cat /root/web"); out != "two\n" {
			t.Errorf("many-b changed after the failed gate: /root/web = %q", out)
		}
		r = winch("plan", "site", "--set", "vars.web_text=three")
		if !strings.Contains(r.Stdout, "many-a\n  web\n    ! health: test -e /root/healthy\n") {
			t.Errorf("the next plan does not show the pending gate on many-a:\n%s", r.Stdout)
		}
		r = winch("apply", "site", "--yes", "--set", "vars.web_text=three")
		if r.Code != 1 || !strings.Contains(r.Stderr, "many-a: web: failed: health: test -e /root/healthy: did not pass within 5s") ||
			!strings.Contains(r.Stderr, "many-b: not started: many-a failed in stage web") {
			t.Errorf("apply with the pending gate: exit %d, stderr %q", r.Code, r.Stderr)
		}
		vms[0].MustRun(t, "touch /root/healthy")
		if r := winch("apply", "site", "--yes", "--set", "vars.web_text=three"); r.Code != 0 {
			t.Errorf("apply after the fix: exit %d, stderr %q", r.Code, r.Stderr)
		}
		if out := vms[1].MustRun(t, "cat /root/web"); out != "three\n" {
			t.Errorf("many-b did not change after the gate passed: /root/web = %q", out)
		}
		if out := vms[0].MustRun(t, "sed '/^version 1$/d' /var/lib/winch/checks/many"); out != "" {
			t.Errorf("records after the gate passed: %q", out)
		}
	})

	t.Run("a health command that hangs fails at the timeout", func(t *testing.T) {
		start := time.Now()
		r := winch("apply", "hang", "--yes")
		if r.Code != 1 || !strings.Contains(r.Stderr, "many-a: hang: failed: health: sleep 300: did not pass within 3s") {
			t.Errorf("apply: exit %d", r.Code)
		}
		if took := time.Since(start); took > time.Minute {
			t.Errorf("the gate took %s", took)
		}
	})
}
