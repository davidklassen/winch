package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/davidklassen/winch/internal/secret"
)

// writeSecret writes hunter2 at path and returns the output line.
func writeSecret(dir, path string) (string, error) {
	edit, err := SecretAt(dir, path)
	if err != nil {
		return "", err
	}
	return edit.Write("hunter2")
}

// readFiles returns the content of each file in dir by its path.
func readFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		out[filepath.ToSlash(rel)] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// spec: Variables/Secrets (winch secret generate, paths)
func TestSecretAt(t *testing.T) {
	k := newKey(t)
	head := "name: acme\nrecipients:\n  - " + k.id.Recipient().String() + "\n"
	inv := func(content string) map[string]string {
		return map[string]string{"winch.yaml": "vars:\n  domain: x\n  motd: x\n", "inventories/test.yaml": content}
	}
	top := func(content string) map[string]string {
		return map[string]string{"winch.yaml": content, "inventories/test.yaml": ""}
	}
	tests := []struct {
		name string
		// files has the project files; winch.yaml follows head.
		files map[string]string
		path  string
		// file is the file that changes, and want its content with S for
		// the secret, after head for winch.yaml.
		file, want string
		line       string
	}{
		{"after the last value of all", inv("groups:\n  all:\n    vars:\n      domain: acme.com # main\n  web:\n    hosts: [web1]\nhosts:\n  web1:\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"groups:\n  all:\n    vars:\n      domain: acme.com # main\n      pw: !secret S\n  web:\n    hosts: [web1]\nhosts:\n  web1:\n",
			"added inventories.test.groups.all.vars.pw in inventories/test.yaml"},
		{"no groups", inv("# hosts\nhosts:\n  web1:\n    address: 192.0.2.1\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"# hosts\nhosts:\n  web1:\n    address: 192.0.2.1\ngroups:\n  all:\n    vars:\n      pw: !secret S\n", ""},
		{"no group all", inv("groups:\n  web:\n    hosts: [web1]\n\nhosts:\n  web1:\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"groups:\n  web:\n    hosts: [web1]\n  all:\n    vars:\n      pw: !secret S\n\nhosts:\n  web1:\n", ""},
		{"all without vars", inv("groups:\n  all:\n    user: admin\nhosts:\n  web1:\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"groups:\n  all:\n    user: admin\n    vars:\n      pw: !secret S\nhosts:\n  web1:\n", ""},
		{"empty vars", inv("groups:\n  all:\n    vars: # none yet\nhosts:\n  web1:\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"groups:\n  all:\n    vars: # none yet\n      pw: !secret S\nhosts:\n  web1:\n", ""},
		{"a block scalar last", inv("groups:\n  all:\n    vars:\n      motd: |\n        hi\n        # not a comment\n\n# hosts\nhosts:\n  web1:\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"groups:\n  all:\n    vars:\n      motd: |\n        hi\n        # not a comment\n      pw: !secret S\n\n# hosts\nhosts:\n  web1:\n", ""},
		{"no final newline", inv("hosts:\n  web1:"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"hosts:\n  web1:\ngroups:\n  all:\n    vars:\n      pw: !secret S\n", ""},
		{"an empty file", inv("\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"\ngroups:\n  all:\n    vars:\n      pw: !secret S\n", ""},
		{"a host", inv("hosts:\n    web1:\n        address: 192.0.2.1\n    web2:\ngroups:\n    all:\n        vars:\n            domain: acme.com\n"),
			"inventories.test.hosts.web1.vars.pw", "inventories/test.yaml",
			"hosts:\n    web1:\n        address: 192.0.2.1\n        vars:\n          pw: !secret S\n    web2:\ngroups:\n    all:\n        vars:\n            domain: acme.com\n",
			"added inventories.test.hosts.web1.vars.pw in inventories/test.yaml"},
		{"a host without a value", inv("hosts:\n  web1:\n  web2:\n"),
			"inventories.test.hosts.web1.vars.pw", "inventories/test.yaml",
			"hosts:\n  web1:\n    vars:\n      pw: !secret S\n  web2:\n", ""},
		{"a quoted host", inv("hosts:\n  \"1234\":\n    vars:\n      domain: acme.com\n"),
			"inventories.test.hosts.1234.vars.pw", "inventories/test.yaml",
			"hosts:\n  \"1234\":\n    vars:\n      domain: acme.com\n      pw: !secret S\n", ""},
		{"a host with dots", inv("hosts:\n  db1.acme.com:\n"),
			"inventories.test.hosts.db1.acme.com.vars.pw", "inventories/test.yaml",
			"hosts:\n  db1.acme.com:\n    vars:\n      pw: !secret S\n", ""},
		{"an empty host", inv("hosts:\n  web1: {}\n  web2: {} # b\n"),
			"inventories.test.hosts.web1.vars.pw", "inventories/test.yaml",
			"hosts:\n  web1:\n    vars:\n      pw: !secret S\n  web2: {} # b\n", ""},
		{"an empty host with a comment", inv("hosts:\n  web1: {}\n  web2: {} # b\n"),
			"inventories.test.hosts.web2.vars.pw", "inventories/test.yaml",
			"hosts:\n  web1: {}\n  web2: # b\n    vars:\n      pw: !secret S\n", ""},
		{"empty vars of all", inv("groups:\n  all:\n    vars: {}\nhosts:\n  web1: {}\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"groups:\n  all:\n    vars:\n      pw: !secret S\nhosts:\n  web1: {}\n", ""},
		{"a group", inv("groups:\n  web:\n    hosts: [web1]\nhosts:\n  web1:\n"),
			"inventories.test.groups.web.vars.pw", "inventories/test.yaml",
			"groups:\n  web:\n    hosts: [web1]\n    vars:\n      pw: !secret S\nhosts:\n  web1:\n", ""},
		{"an inventory name with a dot", map[string]string{"winch.yaml": "inventory: prod.eu\n", "inventories/prod.eu.yaml": "hosts:\n  web1:\n"},
			"inventories.prod.eu.hosts.web1.vars.pw", "inventories/prod.eu.yaml",
			"hosts:\n  web1:\n    vars:\n      pw: !secret S\n", ""},
		{"a value in a host", inv("hosts:\n  web1:\n    vars:\n      pw: x # old\n  web2:\n"),
			"inventories.test.hosts.web1.vars.pw", "inventories/test.yaml",
			"hosts:\n  web1:\n    vars:\n      pw: !secret S # old\n  web2:\n",
			"replaced inventories.test.hosts.web1.vars.pw in inventories/test.yaml"},
		{"an inventory in winch.yaml", top("inventories:\n  prod:\n    hosts:\n      web1:\n"),
			"inventories.prod.hosts.web1.vars.pw", "winch.yaml",
			"inventories:\n  prod:\n    hosts:\n      web1:\n        vars:\n          pw: !secret S\n",
			"added inventories.prod.hosts.web1.vars.pw in winch.yaml"},
		{"the group all at the top", top("hosts:\n  web1:\n"),
			"groups.all.vars.pw", "winch.yaml",
			"hosts:\n  web1:\ngroups:\n  all:\n    vars:\n      pw: !secret S\n",
			"added groups.all.vars.pw in winch.yaml"},
		{"a host with brackets", top("hosts:\n  web[1]:\n    address: 192.0.2.1\n"),
			"hosts.web[1].vars.pw", "winch.yaml",
			"hosts:\n  web[1]:\n    address: 192.0.2.1\n    vars:\n      pw: !secret S\n", ""},
		{"a host at the top", top("hosts:\n  db1.acme.com:\n"),
			"hosts.db1.acme.com.vars.pw", "winch.yaml",
			"hosts:\n  db1.acme.com:\n    vars:\n      pw: !secret S\n", ""},
		{"a default", top("vars:\n  domain: x # d\n\nhosts:\n  web1:\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  domain: x # d\n  pw: !secret S\n\nhosts:\n  web1:\n",
			"added vars.pw in winch.yaml"},
		{"no defaults", top("hosts:\n  web1:\n"),
			"vars.pw", "winch.yaml",
			"hosts:\n  web1:\nvars:\n  pw: !secret S\n", ""},
		{"a default with a comment", top("vars:\n  pw: old # db\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S # db\n  domain: x\n",
			"replaced vars.pw in winch.yaml"},
		{"a quoted default", top("vars:\n  pw: \"a # b\" # c\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S # c\n", ""},
		{"a single-quoted default", top("vars:\n  pw: 'it''s # x'\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S\n", ""},
		{"a block scalar default", top("vars:\n  pw: | # c\n    line1\n    line2\n\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S # c\n\n  domain: x\n", ""},
		{"a null default", top("vars:\n  pw: # later\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S # later\n  domain: x\n", ""},
		{"a map default", top("vars:\n  pw:\n    a: 1\n    b: 2\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S\n  domain: x\n", ""},
		{"a map default with a comment", top("vars:\n  pw: # m\n    a: 1\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S # m\n  domain: x\n", ""},
		{"a map default with a quoted key", top("vars:\n  \"pw\": # m: \"x\"\n    a: 1\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  \"pw\": !secret S # m: \"x\"\n", ""},
		{"a list default at the key's indent", top("vars:\n  pw:\n  - a\n  - b\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S\n  domain: x\n", ""},
		{"a flow default", top("vars:\n  pw: {a: 1,\n    b: 2}\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S\n  domain: x\n", ""},
		{"a secret default", top("vars:\n  pw: !secret OLD\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S\n  domain: x\n", ""},
		{"a key of a map variable", top("vars:\n  users:\n    bob: x\n"),
			"vars.users.alice", "winch.yaml",
			"vars:\n  users:\n    bob: x\n    alice: !secret S\n",
			"added vars.users.alice in winch.yaml"},
		{"a key with dots", top("vars:\n  users:\n    acme.com: old # k\n    bob: x\n"),
			`vars.users["acme.com"]`, "winch.yaml",
			"vars:\n  users:\n    acme.com: !secret S # k\n    bob: x\n",
			`replaced vars.users["acme.com"] in winch.yaml`},
		{"a missing key with dots", top("vars:\n  users:\n    bob: x\n"),
			`vars.users["acme.com"]`, "winch.yaml",
			"vars:\n  users:\n    bob: x\n    acme.com: !secret S\n",
			`added vars.users["acme.com"] in winch.yaml`},
		{"keys with dots in a row", top("hosts:\n  db1.acme.com:\n"),
			`hosts.db1.acme.com.vars.users["a.b"]["c.d"].e`, "winch.yaml",
			"hosts:\n  db1.acme.com:\n    vars:\n      users:\n        a.b:\n          c.d:\n            e: !secret S\n", ""},
		{"a key of a map variable without a value", top("vars:\n  users:\n"),
			"vars.users.alice", "winch.yaml",
			"vars:\n  users:\n    alice: !secret S\n", ""},
		{"a recipe file", map[string]string{"recipes/mail/recipe.yaml": "vars:\n  mail_pw: x\nsteps: []\n"},
			"recipes.mail.vars.mail_pw", "recipes/mail/recipe.yaml",
			"vars:\n  mail_pw: !secret S\nsteps: []\n",
			"replaced recipes.mail.vars.mail_pw in recipes/mail/recipe.yaml"},
		{"a recipe file without defaults", map[string]string{"recipes/mail/recipe.yaml": "steps: []\n"},
			"recipes.mail.vars.mail_pw", "recipes/mail/recipe.yaml",
			"steps: []\nvars:\n  mail_pw: !secret S\n", ""},
		{"a recipe in winch.yaml", map[string]string{"winch.yaml": "inventory: test\nrecipes:\n  mail:\n    steps: []\n"},
			"recipes.mail.vars.mail_pw", "winch.yaml",
			"inventory: test\nrecipes:\n  mail:\n    steps: []\n    vars:\n      mail_pw: !secret S\n",
			"added recipes.mail.vars.mail_pw in winch.yaml"},
		{"a broken secret in another place", inv("hosts:\n  web1:\n    vars:\n      token: !secret broken\n"),
			"inventories.test.groups.all.vars.pw", "inventories/test.yaml",
			"hosts:\n  web1:\n    vars:\n      token: !secret broken\ngroups:\n  all:\n    vars:\n      pw: !secret S\n", ""},
		{"a broken secret default", top("vars:\n  tok: !secret broken\nhosts:\n  web1:\n"),
			"groups.all.vars.pw", "winch.yaml",
			"vars:\n  tok: !secret broken\nhosts:\n  web1:\ngroups:\n  all:\n    vars:\n      pw: !secret S\n", ""},
		{"a new map variable", top("hosts:\n  web1:\n"),
			"vars.users.a.b", "winch.yaml",
			"hosts:\n  web1:\nvars:\n  users:\n    a:\n      b: !secret S\n", ""},
		{"a named inventory next to the default", map[string]string{"winch.yaml": "inventory: test\n", "inventories/prod.yaml": "hosts:\n  web2:\n"},
			"inventories.prod.hosts.web2.vars.pw", "inventories/prod.yaml",
			"hosts:\n  web2:\n    vars:\n      pw: !secret S\n", ""},
		{"a null value in a host", inv("hosts:\n  web1:\n    vars:\n      pw:\n"),
			"inventories.test.hosts.web1.vars.pw", "inventories/test.yaml",
			"hosts:\n  web1:\n    vars:\n      pw: !secret S\n", ""},
		{"a comment below a value", top("vars:\n  pw: old\n    # rotate yearly\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S\n    # rotate yearly\n  domain: x\n", ""},
		{"a comment inside a list", top("vars:\n  pw:\n  - a\n  # - b\n  - c\n# end\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S\n# end\n  domain: x\n", ""},
		{"a block scalar that ends with a hash", top("vars:\n  pw: |\n    a\n    # b\n  domain: x\n"),
			"vars.pw", "winch.yaml",
			"vars:\n  pw: !secret S\n  domain: x\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pipelines/site.yaml": readsPipeline("pw", "users", "mail_pw", "token")}
			for name, content := range tt.files {
				files[name] = content
			}
			files["winch.yaml"] = head + files["winch.yaml"]
			want := tt.want
			if tt.file == "winch.yaml" {
				want = head + want
			}
			dir := writeProject(t, files)
			before := readFiles(t, dir)
			line, err := writeSecret(dir, tt.path)
			if err != nil {
				t.Fatalf("write %s: %v", tt.path, err)
			}
			if tt.line != "" && line != tt.line {
				t.Errorf("line %q; want %q", line, tt.line)
			}
			after := readFiles(t, dir)
			for name, content := range before {
				if name != tt.file && after[name] != content {
					t.Errorf("%s changed:\n%s", name, after[name])
				}
			}
			got := after[tt.file]
			var texts []string
			for _, text := range secretTexts(got) {
				if text != "broken" {
					texts = append(texts, text)
				}
			}
			if len(texts) != 1 {
				t.Fatalf("%d secrets in:\n%s", len(texts), got)
			}
			if plain, err := secret.Decrypt(texts[0], []age.Identity{k.id}); err != nil || plain != "hunter2" {
				t.Errorf("secret = %q, %v; want hunter2", plain, err)
			}
			if got := strings.Replace(got, texts[0], "S", 1); got != want {
				t.Errorf("%s:\n%s\nwant:\n%s", tt.file, got, want)
			}
		})
	}
}

// spec: Variables/Secrets (winch secret generate, paths)
func TestSecretAtErrors(t *testing.T) {
	k := newKey(t)
	head := "name: acme\nrecipients:\n  - " + k.id.Recipient().String() + "\n"
	inv := "hosts:\n  web1:\n    vars:\n      pw: x\ngroups:\n  all:\n    vars:\n      token: x\n      users:\n        a.b: [x]\n  web:\n    hosts: [web1]\n"
	tests := []struct {
		name string
		// cfg follows head in winch.yaml.
		cfg, recipe, path, want string
	}{
		{"an unknown host", "", "", "inventories.test.hosts.web9.vars.pw", "host web9 is not in inventories/test.yaml"},
		{"an unknown group", "", "", "inventories.test.groups.db.vars.pw", "group db is not in inventories/test.yaml"},
		{"an unknown host at the top", "hosts:\n  web1:\n", "", "hosts.web9.vars.pw", "host web9 is not in winch.yaml"},
		{"an unknown inventory", "", "", "inventories.tset.groups.all.vars.pw", `unknown inventory "tset"; did you mean "test"?`},
		{"an unknown recipe", "", "steps: []\n", "recipes.mial.vars.mail_pw", `unknown recipe "mial"; did you mean "mail"?`},
		{"no inventory at the top", "", "", "groups.all.vars.pw", "winch.yaml has no hosts or groups at the top; start the path with inventories.<name>: test"},
		{"a list item", "vars:\n  users: [a]\n", "", "vars.users.0", "cannot write vars.users.0: vars.users is a list; a path cannot name a list item"},
		{"a list item below a map", "vars:\n  users:\n    a: [x]\n", "", "vars.users.a.b", "cannot write vars.users.a.b: vars.users.a is a list; a path cannot name a list item"},
		{"a value that is not a map", "vars:\n  domain: x\n", "", "vars.domain.x", "cannot write vars.domain.x: vars.domain is not a map"},
		{"a second default in winch.yaml", "", "vars:\n  mail_pw: x\nsteps: []\n", "vars.mail_pw", "vars.mail_pw has a default at recipes/mail/recipe.yaml:2:3; write the secret there: recipes.mail.vars.mail_pw"},
		{"a second default in a recipe", "vars:\n  mail_pw: x\n", "steps: []\n", "recipes.mail.vars.mail_pw", "vars.mail_pw has a default at winch.yaml:5:3; write the secret there: vars.mail_pw"},
		{"not read", "", "", "inventories.test.groups.all.vars.tokn", `nothing reads vars.tokn; did you mean "token"?`},
		{"not read as a default", "", "", "vars.tokn", `nothing reads vars.tokn; did you mean "token"?`},
		{"a flow map", "vars: {domain: x}\n", "", "vars.pw", "cannot write vars.pw into winch.yaml: winch writes only into block maps, not into flow maps such as {a: 1}; rewrite the map as a block map, or add the value of winch secret encrypt by hand"},
		{"a value in a flow map", "vars: {pw: x, domain: x}\n", "", "vars.pw", "cannot write vars.pw into winch.yaml: winch writes only into block maps"},
		{"a value that is not a map in an inventory", "", "", "inventories.test.hosts.web1.vars.pw.x", "cannot write inventories.test.hosts.web1.vars.pw.x: inventories.test.hosts.web1.vars.pw is not a map"},
		{"a recipe default without the prefix", "", "steps: []\n", "recipes.mail.vars.pw", "cannot write recipes.mail.vars.pw: a variable of recipe mail starts with mail_"},
		{"a second default through a map", "", "vars:\n  mail_pw:\n    a: x\nsteps: []\n", "vars.mail_pw.b", "vars.mail_pw has a default at recipes/mail/recipe.yaml:2:3; write the secret there: recipes.mail.vars.mail_pw.b"},
		{"an alias of the value", "vars:\n  pw: &p old\n  other: *p\n", "", "vars.pw", "cannot write vars.pw into winch.yaml: winch cannot keep the rest of the file the same; add the value of winch secret encrypt by hand"},
		{"a list item below a host and a key with dots", "hosts:\n  db1.acme.com:\n    vars:\n      users:\n        a.b: [x]\n", "", `hosts.db1.acme.com.vars.users["a.b"].c`, `cannot write hosts.db1.acme.com.vars.users["a.b"].c: hosts.db1.acme.com.vars.users["a.b"] is a list; a path cannot name a list item`},
		{"a list item in an inventory file below a key with dots", "", "", `inventories.test.groups.all.vars.users["a.b"].c`, `cannot write inventories.test.groups.all.vars.users["a.b"].c: inventories.test.groups.all.vars.users["a.b"] is a list`},
		{"a second default below a key with dots", "", "vars:\n  mail_pw:\n    a.b: x\nsteps: []\n", `vars.mail_pw["a.b"]`, `vars.mail_pw has a default at recipes/mail/recipe.yaml:2:3; write the secret there: 'recipes.mail.vars.mail_pw["a.b"]'`},
		{"a list item below a key with dots", "vars:\n  users:\n    a.b: [x]\n", "", `vars.users["a.b"].c`, `cannot write vars.users["a.b"].c: vars.users["a.b"] is a list; a path cannot name a list item`},
		{"no recipients", "", "", "vars.pw", "winch.yaml has no recipients; run winch secret init"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := head + tt.cfg
			if tt.name == "no recipients" {
				cfg = "name: acme\n"
			}
			files := map[string]string{
				"winch.yaml":            cfg,
				"inventories/test.yaml": inv,
				"pipelines/site.yaml":   readsPipeline("pw", "token", "users", "domain", "mail_pw"),
			}
			if strings.HasPrefix(tt.cfg, "hosts:") {
				files["inventories/test.yaml"] = ""
			}
			if tt.recipe != "" {
				files["recipes/mail/recipe.yaml"] = tt.recipe
			}
			dir := writeProject(t, files)
			before := readFiles(t, dir)
			_, err := writeSecret(dir, tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err %v; want %q", err, tt.want)
			}
			for name, content := range readFiles(t, dir) {
				if content != before[name] {
					t.Errorf("%s changed:\n%s", name, content)
				}
			}
		})
	}
}

// spec: Variables/Secrets (winch secret generate, paths)
func TestSecretAtFlowHost(t *testing.T) {
	k := newKey(t)
	dir := writeProject(t, map[string]string{
		"winch.yaml":            "name: acme\nrecipients:\n  - " + k.id.Recipient().String() + "\n",
		"inventories/test.yaml": "hosts: {web1: {}}\n",
		"pipelines/site.yaml":   readsPipeline("pw"),
	})
	_, err := writeSecret(dir, "inventories.test.hosts.web1.vars.pw")
	if want := "cannot write inventories.test.hosts.web1.vars.pw into inventories/test.yaml: winch writes only into block maps"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("err %v; want %q", err, want)
	}
}

// spec: Variables/Secrets (winch secret generate, paths)
func TestSecretAtBadPath(t *testing.T) {
	k := newKey(t)
	dir := writeProject(t, map[string]string{
		"winch.yaml":          "name: acme\ninventory: test\nrecipients:\n  - " + k.id.Recipient().String() + "\n",
		"pipelines/site.yaml": readsPipeline("pw"),
	})
	for _, path := range []string{"", "pw", "vars", "vars.", "vars..pw", "x.pw", "recipes.mail.pw", "recipes.vars.pw", "hosts.web1", "groups.all.pw", "inventories.test.vars.pw", "inventories.test.hosts.web1.pw",
		`hosts.web1.vars["pw"]`, `vars.pw.["a"]`, `vars["pw"]`,
		`hosts["web1"].vars.pw`, `recipes.mail.vars["mail_pw"]`} {
		_, err := SecretAt(dir, path)
		want := fmt.Sprintf(`%q is not a path to a variable value; use vars.<name>, recipes.<recipe>.vars.<name>, [inventories.<inventory>.]groups.<group>.vars.<name>, or [inventories.<inventory>.]hosts.<host>.vars.<name>`, path)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("path %q: err %v; want %q", path, err, want)
		}
	}
}

// spec: Variables/Secrets (winch secret generate, paths)
func TestSecretAtBadBracketPath(t *testing.T) {
	k := newKey(t)
	dir := writeProject(t, map[string]string{
		"winch.yaml":          "name: acme\ninventory: test\nrecipients:\n  - " + k.id.Recipient().String() + "\n",
		"pipelines/site.yaml": readsPipeline("pw"),
	})
	for _, path := range []string{"vars.pw[acme.com]", `vars.pw["a`, `vars.pw["a"`, `vars.pw["a"]b`, `vars.pw.x[a]`, `vars.pw['a']`, "vars.pw[`a`]", `vars.pw[""]`, `vars.pw["a"].`} {
		_, err := SecretAt(dir, path)
		want := fmt.Sprintf(`%q is not a path to a variable value; put a key with dots in brackets and double quotes, and the path in single quotes: 'vars.m["a.b"]'`, path)
		if err == nil || err.Error() != want {
			t.Errorf("path %q: err %v; want %q", path, err, want)
		}
	}
}

// spec: Variables/Secrets (winch secret generate, paths); Project layout
func TestSecretAtLayoutErrors(t *testing.T) {
	k := newKey(t)
	head := "name: acme\nrecipients:\n  - " + k.id.Recipient().String() + "\n"
	t.Run("no hosts", func(t *testing.T) {
		dir := writeProject(t, map[string]string{
			"winch.yaml":            head,
			"inventories/test.yaml": "",
			"pipelines/site.yaml":   readsPipeline("pw"),
		})
		_, err := writeSecret(dir, "groups.all.vars.pw")
		if want := "the project has no hosts; add hosts to winch.yaml or a file to inventories/"; err == nil || err.Error() != want {
			t.Errorf("err %v; want %q", err, want)
		}
	})
	t.Run("two inventory files", func(t *testing.T) {
		inv := "hosts:\n  web1:\n"
		dir := writeProject(t, map[string]string{
			"winch.yaml":            head,
			"inventories/test.yaml": inv,
			"inventories/test.yml":  inv,
			"pipelines/site.yaml":   readsPipeline("pw"),
		})
		_, err := writeSecret(dir, "inventories.test.groups.all.vars.pw")
		if want := `inventory "test" is both inventories/test.yaml and inventories/test.yml; keep one of the two`; err == nil || err.Error() != want {
			t.Errorf("err %v; want %q", err, want)
		}
	})
	t.Run("the top inventory by name", func(t *testing.T) {
		dir := writeProject(t, map[string]string{
			"winch.yaml":            head + "hosts:\n  web1:\n",
			"inventories/test.yaml": "",
			"pipelines/site.yaml":   readsPipeline("pw"),
		})
		_, err := writeSecret(dir, "inventories.acme.groups.all.vars.pw")
		if want := `inventory "acme": the hosts at the top of winch.yaml are the only inventory; leave out the inventory name`; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err %v; want %q", err, want)
		}
	})
}

// spec: Variables/Secrets (winch secret generate)
func TestSecretAtBrokenRecipe(t *testing.T) {
	k := newKey(t)
	dir := writeProject(t, map[string]string{
		"winch.yaml":                   "name: acme\ninventory: test\nrecipients:\n  - " + k.id.Recipient().String() + "\n",
		"inventories/test.yaml":        "hosts:\n  web1:\n",
		"pipelines/site.yaml":          readsPipeline("db_password"),
		"recipes/db/recipe.yaml":       "steps:\n  - file:\n      path: /etc/db.conf\n      template: db.conf\n",
		"recipes/db/templates/db.conf": "{{ .vars.db_password ",
	})
	if _, err := writeSecret(dir, "inventories.test.groups.all.vars.db_password"); err != nil {
		t.Errorf("write: %v", err)
	}
}

// spec: Variables/Secrets (winch secret generate)
func TestSecretAtReadInBrokenRecipe(t *testing.T) {
	k := newKey(t)
	dir := writeProject(t, map[string]string{
		"winch.yaml":             "name: acme\ninventory: test\nrecipients:\n  - " + k.id.Recipient().String() + "\n",
		"inventories/test.yaml":  "hosts:\n  web1:\n",
		"recipes/db/recipe.yaml": "steps:\n  - file:\n      path: /x\n      content: !expr vars.db_password\n  - file: {path: /y\n",
	})
	_, err := writeSecret(dir, "inventories.test.groups.all.vars.db_password")
	if err == nil || !strings.Contains(err.Error(), `nothing reads vars.db_password`) || !strings.Contains(err.Error(), "recipes/db/recipe.yaml:4:1: did not find expected") {
		t.Errorf("err %v; want the unknown variable and the parse error", err)
	}
}

// spec: Variables/Secrets (winch secret generate)
func TestSecretAtThroughLink(t *testing.T) {
	k := newKey(t)
	dir := writeProject(t, map[string]string{
		"winch.yaml":            "name: acme\ninventory: test\nrecipients:\n  - " + k.id.Recipient().String() + "\n",
		"inventories/test.yaml": "",
		"pipelines/site.yaml":   readsPipeline("pw"),
	})
	target := filepath.Join(t.TempDir(), "shared.yaml")
	if err := os.WriteFile(target, []byte("hosts:\n  web1:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "inventories", "test.yaml")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := writeSecret(dir, "inventories.test.groups.all.vars.pw"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the inventory is no longer a link: %v", err)
	}
	if data, _ := os.ReadFile(target); len(secretTexts(string(data))) != 1 {
		t.Errorf("target:\n%s", data)
	}
}

// spec: Variables/Secrets (winch secret generate, paths)
func TestSecretAtLinkedProjectFile(t *testing.T) {
	k := newKey(t)
	dir := writeProject(t, map[string]string{"pipelines/site.yaml": readsPipeline("pw")})
	target := filepath.Join(t.TempDir(), "winch.yaml")
	if err := os.WriteFile(target, []byte("name: acme\ninventory: test\nrecipients:\n  - "+k.id.Recipient().String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "winch.yaml")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := writeSecret(dir, "vars.pw"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("winch.yaml is no longer a link: %v", err)
	}
	if data, _ := os.ReadFile(target); len(secretTexts(string(data))) != 1 {
		t.Errorf("target:\n%s", data)
	}
}
