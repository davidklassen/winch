package project

import "github.com/davidklassen/winch/internal/doc"

var projectTopic = doc.Topic{
	Name: "project",
	Text: "project files and directories",
	Blocks: []doc.Block{
		doc.Paragraph(`A project is a directory with a winch.yaml file and the inventories,
pipelines, and recipes that it uses. winch reads the project in the
current directory.`),
		doc.Heading("Minimal project"),
		doc.Paragraph(`One winch.yaml with a name, a host, and one step:`),
		doc.Code(`# winch.yaml
name: demo
hosts:
  web1.example.com:
    address: 192.0.2.10
steps:
  - name: Write the message of the day
    file:
      path: /etc/motd
      content: "Managed by winch.\n"
`),
		doc.Paragraph(`Check it, show the changes, then make them:`),
		doc.Code(`winch validate
winch plan
winch apply

# winch writes /etc/motd on web1.example.com.
`),
		doc.Heading("Hosts"),
		doc.Paragraph(`winch connects with the OpenSSH client and its SSH config. The login
user is root, or has passwordless sudo. A host needs nothing else
installed: winch sends a helper program to /var/lib/winch/ on the
host and runs it there. Run winch doc remote.`),
		doc.Heading("When the project grows"),
		doc.Paragraph(`Move the hosts into inventories, the steps into pipelines, and
groups of steps into recipes:`),
		doc.Code(`winch.yaml               the project file
inventories/
  production.yaml        an inventory: hosts and groups
  test.yaml
pipelines/
  site.yaml              a pipeline: stages and steps
recipes/
  nginx/
    recipe.yaml          a recipe: variables, steps, and handlers
    templates/site.tmpl  the templates of the recipe
    files/tls.conf       the files of the recipe
`),
		doc.Paragraph(`The name of an inventory or a pipeline is its file name without
.yaml. Plan and apply then name the pipeline: winch plan site.`),
		doc.Paragraph(`An inventory, a pipeline, or a recipe can also be a key in
winch.yaml, under inventories, pipelines, or recipes. The value of
the key is the content of the file. A name in both places is an
error.`),
		doc.Heading("Top-level inventory and pipeline"),
		doc.Paragraph(`hosts and groups at the top of winch.yaml are the only inventory of
the project. They work with any number of pipelines. steps,
handlers, parallelism, and health at the top of winch.yaml are the
only pipeline. Then plan and apply take no pipeline name.`),
		doc.Heading("YAML"),
		doc.Paragraph(`All files are YAML 1.2. Only true and false are booleans: yes, no,
on, and off are strings. File modes are strings: mode: "0644".
Unknown keys and duplicate keys are errors. Anchors and aliases
work. Merge keys (<<) do not. winch fmt fixes the indentation and
the step key order.`),
	},
}

var inventoryTopic = doc.Topic{
	Name: "inventory",
	Text: "hosts and groups",
	Blocks: []doc.Block{
		doc.Paragraph(`An inventory lists the hosts that winch manages, puts them in groups,
and gives them values.`),
		doc.Heading("Files"),
		doc.Paragraph(`An inventory is a file in inventories/, such as
inventories/production.yaml, or a key in inventories of winch.yaml.
It holds data and secrets, but no templates or expressions.`),
		doc.Heading("Choosing the inventory"),
		doc.Paragraph(`--inventory <name> names the inventory of a run. inventory in
winch.yaml names a default. A project with one inventory uses it. A
project with more inventories and no default makes each run name
its inventory, so a run against production is always deliberate.`),
		doc.Heading("Groups and values"),
		doc.Paragraph(`The group all contains every host. A host value beats a group
value, and a group value beats a value of all. Two groups of one
host that set different values for one variable, or for user, are
an error, unless the host sets that value too.`),
		doc.Heading("SSH settings"),
		doc.Paragraph(`Every other SSH setting, such as the port or the key, comes from your
SSH config. Its Host blocks match the host name, also when the host
has an address.`),
		doc.Heading("Host patterns"),
		doc.Paragraph(`Host patterns select hosts in the hosts of a stage, in --hosts, and
in winch run and winch exec:`),
		doc.Table([][]string{
			{"web", "the hosts in the group web, or the host named web"},
			{"web,db", "the hosts in web or in db"},
			{"web & prod", "the hosts in web and in prod"},
			{"web & !web3", "the hosts in web, without web3"},
		}),
		doc.Paragraph(`& and ! bind tighter than ",". Hosts keep inventory order. A name
that is neither a group nor a host is an error. A pattern with only
! names is an error: write all & !web, not !web.`),
		doc.Example(`# inventories/production.yaml
hosts:
  mail.acme.com:
    address: 192.0.2.10
  monitor.acme.com:
    address: 192.0.2.20
groups:
  all:
    user: admin
    vars:
      domain: acme.com
  mail:
    hosts: [mail.acme.com]
    vars:
      mail_server: true

# winch.yaml
name: acme
vars:
  domain: example.com
  mail_server: false
steps:
  - name: Install postfix on the mail servers
    pkg:
      name: postfix
    when: !expr vars.mail_server
`),
	},
}

var pipelineTopic = doc.Topic{
	Name: "pipeline",
	Text: "ordered stages that apply steps to hosts",
	Blocks: []doc.Block{
		doc.Paragraph(`A pipeline is an ordered list of stages. Each stage applies its steps
to a set of hosts.`),
		doc.Heading("Files"),
		doc.Paragraph(`A pipeline is a file in pipelines/, such as pipelines/site.yaml, or
a key in pipelines of winch.yaml. winch plan site and winch apply
site run it.`),
		doc.Heading("One stage or many"),
		doc.Paragraph(`Most pipelines run the same steps on every host. Such a pipeline
holds the steps directly. It is one stage with the name of the
pipeline. A pipeline whose hosts have different roles, or that must
finish on some hosts before it starts on others, has stages.`),
		doc.Heading("Order"),
		doc.Paragraph(`Stages run in order. A stage starts when the previous stage finished
on all its hosts. Inside a stage, each host runs its steps in order,
without waiting for other hosts. A stage that matches no host is
skipped. --stages runs only some stages, and --hosts only some
hosts.`),
		doc.Heading("Steps of a stage"),
		doc.Paragraph(`A step in a stage can use a module directly. It cannot use template,
source, or the key of repo: those read the files of a recipe.`),
		doc.Heading("Failures"),
		doc.Paragraph(`A failed host takes no part in later stages. The other hosts go on.
A new run is the resume: steps that already succeeded check as ok.`),
		doc.Example(`# pipelines/site.yaml
stages:
  - name: base
    hosts: all
    parallelism: 1
    steps:
      - timezone:
          name: Etc/UTC
  - name: web
    hosts: web
    health:
      command: systemctl is-active nginx
      stable: 10
      timeout: 120
    steps:
      - recipe: nginx

# winch.yaml
name: acme
inventories:
  production:
    hosts:
      web1.acme.com: {}
      web2.acme.com: {}
    groups:
      web:
        hosts: [web1.acme.com, web2.acme.com]
recipes:
  nginx:
    steps:
      - pkg:
          name: nginx
`),
	},
}

var recipeTopic = doc.Topic{
	Name: "recipe",
	Text: "reusable groups of steps",
	Blocks: []doc.Block{
		doc.Paragraph(`A recipe is a named group of steps that you can use again, with its own
variables, templates, and files.`),
		doc.Heading("Files"),
		doc.Paragraph(`A recipe is a directory in recipes/ with a recipe.yaml, and optional
templates/ and files/ directories. Or it is a key in recipes of
winch.yaml, without templates or files. winch loads every recipe for
every command, also a recipe that no pipeline uses.`),
		doc.Heading("Names"),
		doc.Paragraph(`A recipe name has lowercase letters, digits, and _. It can be the
name of a module.`),
		doc.Heading("Running a recipe"),
		doc.Paragraph(`A step runs a recipe with recipe: <name>. A recipe step has only
name, recipe, vars, and when. A recipe runs at most once per host in
a run. Two stages can run the same recipe when their hosts do not
overlap. A recipe cannot run another recipe.`),
		doc.Heading("Templates and files"),
		doc.Paragraph(`template reads from the templates/ directory of the recipe, and
source from files/. Paths can name subdirectories. A template file
uses the language of !tpl. Run winch doc templates.`),
		doc.Example(`# recipes/nginx/recipe.yaml
require:
  - !expr facts.os.id in ["debian", "ubuntu"]
vars:
  nginx_port: 80
steps:
  - pkg:
      name: nginx
  - name: Configure the site
    file:
      path: /etc/nginx/sites-enabled/default
      template: site.tmpl
      validate: nginx -t
    notify: reload
  - service:
      name: nginx
      running: true
      enabled: true
handlers:
  reload:
    - service:
        name: nginx
        reloaded: true

# recipes/nginx/templates/site.tmpl
server {
    listen {{ .vars.nginx_port }};
}

# winch.yaml
name: acme
hosts:
  web1.acme.com: {}
steps:
  - recipe: nginx
    vars:
      nginx_port: 8080
`),
	},
}

var stepTopic = doc.Topic{
	Name: "step",
	Text: "keys that every step has",
	Blocks: []doc.Block{
		doc.Paragraph(`A step is one action on a host: a module with its arguments, or a
recipe.`),
		doc.Heading("Form"),
		doc.Paragraph(`A step is a map. It has one module key, such as pkg or file, with the
arguments of the module as a map. Or it has recipe with the name of
a recipe. Run winch doc <module> for the arguments of a module.`),
		doc.Heading("Computed values"),
		doc.Paragraph(`Any module argument can be a template or an expression, and so can
then. when takes an expression. loop takes a list or an expression.`),
		doc.Heading("Evaluation"),
		doc.Paragraph(`On each host, winch evaluates when. When it is false, winch skips the
step. Then winch evaluates loop, and the arguments for each element.
winch checks the step on the host, and apply changes what differs.`),
		doc.Heading("Results"),
		doc.Paragraph(`A step that runs a command counts as changed: a cmd, and a service
with restarted or reloaded. When a step fails, its host stops. Other
hosts go on.`),
		doc.Heading("Key order"),
		doc.Paragraph(`winch fmt puts the step keys in this order: name, the module or
recipe, vars, when, loop, then, confirm_access, notify.`),
		doc.Example(`# winch.yaml
name: demo
hosts:
  web1.example.com: {}
vars:
  sites: [blog, shop]
steps:
  - name: Install nginx
    pkg:
      name: nginx
  - name: Write the sites
    file:
      path: !tpl /etc/nginx/sites-enabled/{{ .item }}.conf
      content: !tpl "# {{ .item }}\n"
    when: !expr len(vars.sites) > 0
    loop: !expr vars.sites
    then: nginx -t
    notify: reload
handlers:
  reload:
    - service:
        name: nginx
        reloaded: true
`),
	},
}

var handlersTopic = doc.Topic{
	Name: "handlers",
	Text: "steps that run after a change",
	Blocks: []doc.Block{
		doc.Paragraph(`A handler is a list of steps that runs once, after a step that notifies
it changes something.`),
		doc.Heading("Declaring a handler"),
		doc.Paragraph(`handlers is a map in a recipe or in a stage. Each key is a handler
name, and its value is a list of steps. A handler name has lowercase
letters, digits, and _.`),
		doc.Heading("Notifying a handler"),
		doc.Paragraph(`notify on a step names a handler of the current recipe or stage, or
<recipe>.<handler> of another recipe. That recipe must run in the
same pipeline, on at least one host where the step runs. On a host
where it does not run, winch drops the notification.`),
		doc.Code(`# winch.yaml
name: demo
hosts:
  web1.example.com: {}
steps:
  - recipe: nginx
  - file:
      path: /etc/nginx/conf.d/gzip.conf
      content: "gzip on;\n"
    notify: nginx.reload
recipes:
  nginx:
    steps:
      - pkg:
          name: nginx
    handlers:
      reload:
        - service:
            name: nginx
            reloaded: true

# A change of gzip.conf reloads nginx once, at the end of the stage.
`),
		doc.Heading("When a handler runs"),
		doc.List(
			`A handler runs at most once per recipe run on a host. A handler of
a stage runs at most once per stage run.`,
			`A handler runs after the last step of its recipe. When its recipe
already ran on that host, it runs at the end of the current stage.`,
			`A handler of a stage runs after the last step of the stage and
after the recipe handlers at the end of the stage. It runs before
the health gate.`,
			`Handlers run in the order that the recipe or the stage declares
them.`,
		),
		doc.Heading("Handler steps"),
		doc.Paragraph(`A handler step can have when. It cannot use notify or run a recipe.
Only a handler step and winch run can use restarted and reloaded of
service.`),
		doc.Heading("Pending handlers"),
		doc.Paragraph(`When a step notifies a handler, winch marks the handler as pending on
the host before the step changes anything. The mark goes when the
handler succeeds. When a run stops first, the handler stays pending.
It runs the next time its recipe or stage runs on that host. The
plan shows a handler that will run with "!".`),
	},
}

var variablesTopic = doc.Topic{
	Name: "variables",
	Text: "named values for hosts, groups, and recipes",
	Blocks: []doc.Block{
		doc.Paragraph(`Variables are named values that steps, templates, and expressions
read.`),
		doc.Heading("Sources"),
		doc.Paragraph(`Each host has its own value. A value comes from these sources. A
later source replaces an earlier one:`),
		doc.OrderedList(
			`the default`,
			`the vars of the groups of the host, then of the host`,
			`the vars of the recipe step`,
			`--set vars.<name>=<value>`,
		),
		doc.Paragraph(`Maps and lists do not merge.`),
		doc.Heading("Defaults"),
		doc.Paragraph(`A default is declared once: in vars of winch.yaml, or in vars of the
recipe that owns it. A recipe's own defaults start with the recipe
name and _. A default can be a !secret, a template, or an
expression. It sees vars, host, and facts, but not match(). A cycle
between defaults is an error.`),
		doc.Heading("Variables without a default"),
		doc.Paragraph(`A variable without a default needs no declaration. A read of it is
enough, and the variable is required where it is read. A variable
that may stay unset needs a default, such as relay_host: "".`),
		doc.Heading("Names and reads"),
		doc.Paragraph(`A variable name has lowercase letters, digits, and _. A read names
the variable: vars.domain, .vars.domain, $.vars.domain, or
host.vars.domain. Any other read of the whole map, such as
keys(vars) or range .vars, is an error. A map variable holds data
that a step reads by key: vars.users[item]. host.vars holds the
variables of the host without the vars of a recipe step.`),
		doc.Heading("Types"),
		doc.Paragraph(`Variables have no types. A value keeps the type that YAML gives it.
--set parses its value as YAML. Quote a value that YAML would
change: --set 'vars.php_version="8.0"'.`),
		doc.Example(`# winch.yaml
name: demo
hosts:
  mail.acme.com:
    vars:
      relay_host: smtp.acme.com
  web1.acme.com: {}
groups:
  all:
    vars:
      admin_email: ops@acme.com
vars:
  domain: acme.com
  relay_host: ""
steps:
  - recipe: motd
    vars:
      motd_text: Managed by winch
recipes:
  motd:
    vars:
      motd_text: Welcome
    steps:
      - file:
          path: /etc/motd
          content: !tpl "{{ .vars.motd_text }} on {{ .vars.domain }}\n"
      - file:
          path: /etc/admin_email
          content: !tpl "{{ .vars.admin_email }}\n"
      - file:
          path: /etc/relay_host
          content: !tpl "{{ .vars.relay_host }}\n"
        when: !expr vars.relay_host != ""
`),
	},
}

var templatesTopic = doc.Topic{
	Name: "templates",
	Text: "text with values filled in (!tpl)",
	Blocks: []doc.Block{
		doc.Paragraph(`A template is text in which winch fills in the values of each host.`),
		doc.Heading("Syntax"),
		doc.Paragraph(`The !tpl tag marks a template, a Go text/template. It builds text,
such as a path or a line. The template files of a recipe use the
same language.`),
		doc.Heading("Data"),
		doc.Paragraph(`A template reads these names with a leading dot:`),
		doc.Table([][]string{
			{".vars", "the variables of the host, with the vars of the recipe step"},
			{".facts", "the facts of the host; run winch doc facts"},
			{".host", "name, short, address, groups, and vars of the host"},
			{".item", "the current element in a step with loop"},
		}),
		doc.Paragraph(`Inside range, "." is the element. $.vars reads the variables.`),
		doc.Heading("Where templates go"),
		doc.Paragraph(`Any module argument can be a template or an expression, and so can
then.`),
		doc.Heading("Functions and actions"),
		doc.Paragraph(`A function takes its arguments after its name, separated by spaces:
{{ join .vars.names ", " }}. Templates also have the actions of Go's
text/template: if, else, range, with, define, template, block,
break, and continue, and the variables $x := value.`),
		doc.Heading("Missing values"),
		doc.Paragraph(`A template that reads a missing map key fails. Use get for a key
that may be missing. A template that prints a null value fails.`),
		doc.Heading("Quoting"),
		doc.Paragraph(`A value goes into a command as it is. Quote a value that must stay
one word with quote. Quote a YAML value that starts with a quote, [,
{, &, *, or !, or that contains ": " or " #". A template that starts
with {{ needs quotes.`),
		doc.Heading("When they run"),
		doc.Paragraph(`winch evaluates templates on the machine that runs winch, during the
plan. They cannot read the result of a step. winch checks each one
when it loads the project: an unknown name or a syntax error is an
error. An error while winch evaluates one for a host fails that
host. The other hosts go on.`),
		doc.Example(`# winch.yaml
name: demo
hosts:
  web1.acme.com: {}
vars:
  sites: [blog, shop]
  admins: [ann, bob]
steps:
  - name: Write the sites
    file:
      path: !tpl /etc/nginx/sites-enabled/{{ .item }}.conf
      content: !tpl "server_name {{ .item }}.{{ .host.short }};\n"
    loop: !expr vars.sites
  - name: Allow the admins
    file:
      path: /etc/ssh/sshd_config.d/admins.conf
      content: !tpl "AllowUsers{{ range .vars.admins }} {{ . }}{{ end }}\n"
`),
	},
}

var expressionsTopic = doc.Topic{
	Name: "expressions",
	Text: "computed values (!expr)",
	Blocks: []doc.Block{
		doc.Paragraph(`An expression computes a value for each host, such as a list, a
number, or true or false.`),
		doc.Heading("Syntax"),
		doc.Paragraph(`The !expr tag marks an expression in the language of expr
(expr-lang.org). Its result keeps its type: a list, a number, a
boolean, a map, or a string.`),
		doc.Heading("Data"),
		doc.Paragraph(`An expression reads these names without a leading dot:`),
		doc.Table([][]string{
			{"vars", "the variables of the host, with the vars of the recipe step"},
			{"facts", "the facts of the host; run winch doc facts"},
			{"host", "name, short, address, groups, and vars of the host"},
			{"item", "the current element in a step with loop"},
			{"match(p)", "the hosts that match the host pattern p, with the fields\nof host"},
		}),
		doc.Paragraph(`match(p) reads the inventory, not the --hosts selection. A host from
match() has only the vars that need no facts. A default cannot use
match().`),
		doc.Heading("Where expressions go"),
		doc.Paragraph(`Any module argument can be an expression or a template, and so can
then. when takes an expression. loop takes a list or an expression.`),
		doc.Heading("Operators"),
		doc.Table([][]string{
			{"+ - * / % **", "arithmetic"},
			{"== != < > <= >=", "comparison"},
			{"and or not", "logic, also && || !"},
			{"in", "membership in a list or a map"},
			{"contains startsWith endsWith", "text tests"},
			{"matches", "regular expression test"},
			{"c ? a : b", "choice"},
			{"a ?? b", "a, or b when a is nil"},
			{"[] ?.", "read an element or a key"},
			{"x[i:j] 1..3", "slice and range"},
			{"|", "pipe: vars.name | lower()"},
		}),
		doc.Heading("Predicates"),
		doc.Paragraph(`In a predicate, such as the second argument of filter, # is the
element, and .name reads the key name of a map element:
filter(vars.users, .uid >= 1000).`),
		doc.Heading("Missing values"),
		doc.Paragraph(`A missing map key is nil. A module argument whose expression gives
null fails the host.`),
		doc.Heading("Quoting"),
		doc.Paragraph(`Quote a YAML value that starts with a quote, [, {, &, *, or !, or
that contains ": " or " #".`),
		doc.Heading("When they run"),
		doc.Paragraph(`winch evaluates expressions on the machine that runs winch, during
the plan. They cannot read the result of a step. winch checks each
one when it loads the project: an unknown name or a syntax error is
an error. An error while winch evaluates one for a host fails that
host. The other hosts go on. $env and now() are errors in every
expression.`),
		doc.Example(`# winch.yaml
name: demo
hosts:
  mail.acme.com: {}
  web1.acme.com: {}
vars:
  mail_server: false
  domain: acme.com
  admins: [ann, bob]
  mailname: !expr 'vars.mail_server ? vars.domain : host.name'
steps:
  - name: Set the mail name
    file:
      path: /etc/mailname
      content: !expr 'vars.mailname + "\n"'
    when: !expr vars.mail_server
  - name: Add the admins
    user:
      name: !expr item
      groups: [sudo]
    loop: !expr sort(vars.admins)
  - name: List the other hosts
    file:
      path: /etc/peers
      content: !expr 'join(map(filter(match("all"), .name != host.name), .address), "\n") + "\n"'
`),
	},
}

var factsTopic = doc.Topic{
	Name: "facts",
	Text: "values that winch reads from each host",
	Blocks: []doc.Block{
		doc.Paragraph(`Facts are values that winch reads from each host before the plan, such
as the OS release.`),
		doc.Heading("Reading a fact"),
		doc.Paragraph(`Expressions read a fact as facts.os.id, and templates as
{{ .facts.os.id }}. Facts are a fixed set. A read of an unknown fact
is an error.`),
		doc.Code(`# winch.yaml
name: demo
hosts:
  web1.example.com: {}
steps:
  - recipe: base
recipes:
  base:
    require:
      - !expr facts.os.id == "debian" and facts.os.version == "13"
    steps:
      - reboot:
          if_required: true
        when: !expr facts.reboot_required

# The plan fails a host that is not Debian 13. A host that needs a
# reboot reboots.
`),
		doc.Heading("When winch reads them"),
		doc.Paragraph(`winch reads the facts once per host per run, before the first step,
and again after a reboot. They describe the host before the run.`),
	},
}

var secretsTopic = doc.Topic{
	Name: "secrets",
	Text: "encrypted values in the project",
	Blocks: []doc.Block{
		doc.Paragraph(`A secret is a value that the project keeps encrypted and winch never
prints.`),
		doc.Heading("Format"),
		doc.Paragraph(`A secret is encrypted with age for the recipients in winch.yaml. The
!secret tag marks it, followed by the ciphertext in base64 on one
line.`),
		doc.Heading("Where a secret stands"),
		doc.Paragraph(`A !secret stands only in a variable value: in the vars of an
inventory, and in the defaults of winch.yaml and of recipes, at any
depth of a list or a map. --set cannot give a secret.`),
		doc.Heading("Commands"),
		doc.Table([][]string{
			{"winch secret init", "make an age key, add it to recipients"},
			{"winch secret generate vars.<name>", "write a random password into the inventory"},
			{"winch secret encrypt", "encrypt a value from stdin"},
			{"winch secret rekey", "encrypt all secrets for the current recipients"},
		}),
		doc.Heading("The age key"),
		doc.Paragraph(`winch secret init makes a key at ~/.config/winch/age.key, or at the
path in WINCH_AGE_KEY. It makes a key only when no key is there.
With WINCH_AGE_IDENTITY_CMD, it makes no key and adds the public key
of the command's key.`),
		doc.Paragraph(`winch reads the age identity from the output of the command in
WINCH_AGE_IDENTITY_CMD, such as op read op://infra/winch/key.
Without it, winch reads the file in WINCH_AGE_KEY, or else
~/.config/winch/age.key. winch validate needs no identity.`),
		doc.Heading("A new member"),
		doc.Paragraph(`A new member runs winch secret init and sends the change for review.
The new key can read the secrets after a member who can read them
runs winch secret rekey.`),
		doc.Heading("Output"),
		doc.Paragraph(`A variable is secret when its value is a !secret, or when its
default reads a secret variable. The plan, diffs, errors, logs, and
JSON show (secret) in place of a secret, also a part of a value that
comes from a secret. A filter replaces each secret value in all text
that winch prints, also in output from the host. The filter also
hides private keys, age identities, passwords in URLs, and
well-known tokens.`),
		doc.Heading("Secrets in commands"),
		doc.Paragraph(`A secret in a command does not show in the process list of the host.
A program that the command starts with the secret as an argument,
such as psql -c, does show it.`),
		doc.Heading("Warnings and errors"),
		doc.List(
			`winch warns about text in project files that looks like a private
key or a token, and is not a !secret.`,
			`winch warns about a file step whose content reads a secret and
whose mode is missing or lets others read it.`,
			`A !secret in a certbot hook is an error: certbot stores its hooks
in a file that other users can read. A hook that reads a secret
through match() fails the host.`,
		),
		doc.Example(`# inventories/production.yaml
hosts:
  db1.acme.com: {}
groups:
  all:
    vars:
      db_password: !secret YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...

# winch.yaml
name: acme
recipients:
  - age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
steps:
  - file:
      path: /etc/app/db.env
      content: !tpl "DB_PASSWORD={{ .vars.db_password }}\n"
      mode: "0600"
`),
	},
}

var workflowTopic = doc.Topic{
	Name: "workflow",
	Text: "how to plan and apply changes",
	Blocks: []doc.Block{
		doc.Paragraph(`A run of winch plans the changes, asks for approval, and then applies
them.`),
		doc.Heading("Plan and apply"),
		doc.Paragraph(`winch plan shows the changes and changes nothing. winch apply shows
the same plan, asks, and then makes the changes. For each host, the
plan connects to the host, reads the facts, evaluates the steps,
checks the requirements of the recipes, and checks each step on the
host. Apply checks each step again right before it changes it. The
second check decides.`),
		doc.Heading("Plan marks"),
		doc.Table([][]string{
			{"+", "create"},
			{"~", "change"},
			{"-", "remove"},
			{"?", "unknown: a cmd without creates or unless"},
			{"!", "a handler, or a pending then, gate, or assert that will run"},
			{"*", "a reboot, assert, or health gate that runs during apply"},
		}),
		doc.Heading("Plan hash"),
		doc.Paragraph(`The last line of a plan is its hash, such as plan a3f9c2e1d07b4c58.
The hash covers the project name, the hosts with the host name and
port that ssh resolves for them and their login users, the stages,
the evaluated steps, the check results, and the pending handlers and
then commands. winch apply --check <hash> applies only when the new
plan has that hash, without the question.`),
		doc.Heading("Without a terminal"),
		doc.Paragraph(`apply without --yes or --check prints the plan and exits 5. Its last
line is the command that applies that plan.`),
		doc.Heading("What winch changes"),
		doc.Paragraph(`winch changes only what steps declare. Deleting a step changes
nothing on the host. To remove a thing, declare it with absent:
true. The plan fails a host when two steps manage the same path,
package, unit, user, or group with different arguments.`),
		doc.Heading("Stopping and resuming"),
		doc.Paragraph(`The first Ctrl-C lets the running step of each host finish, starts
no new step, and ends with the summary. A second Ctrl-C closes the
connections to the hosts. A new run is the resume: steps that already
succeeded check as ok, and pending handlers run.`),
		doc.Heading("Access to the host"),
		doc.Paragraph(`winch keeps its access to each host.`),
		doc.List(
			`A step that stops, disables, masks, or removes the SSH server
fails: "this cuts off winch's access".`,
			`Some steps get the rollback of confirm_access without it: a change
of the login user's authorized_keys, ~/.ssh, or home directory,
groups added to the login user, a change of /etc/pam.d, and a
change of /etc/sudoers or /etc/sudoers.d when the login user is not
root. Every firewall step gets it too. The plan marks such a step.
Run winch doc step.confirm_access.`,
			`A step that changes sshd's config while ssh.socket is active, as on
Ubuntu, restarts ssh.socket. It gets the same protection.`,
			`After the last step of a host that changed something, winch checks
the access once more. When it fails, the host fails, and nothing
rolls back.`,
		),
		doc.Heading("Changing the SSH port"),
		doc.Paragraph(`The access check connects to the port in your SSH config. So a change
of sshd's Port in one run always rolls back. Move sshd to a new port
in three runs:`),
		doc.OrderedList(
			`Let sshd listen on the old and the new port.`,
			`Change the port in the SSH config.`,
			`Remove the old port from sshd.`,
		),
		doc.Heading("Exit codes"),
		doc.Table([][]string{
			{"0", "success"},
			{"1", "one or more hosts failed"},
			{"2", "plan --exit-code: apply would change something"},
			{"3", "invalid command line or project; nothing ran"},
			{"4", "one or more hosts were unreachable, and no step failed"},
			{"5", "confirmation needed; nothing changed"},
			{"6", "the plan hash differs from --check; nothing changed"},
		}),
		doc.Paragraph(`When several apply, the first in the order 3, 1, 4, 6, 5, 2, 0 wins.`),
		doc.Heading("JSON output"),
		doc.Paragraph(`--json writes one JSON object per line on stdout. Each has type and
time. The types:`),
		doc.Table([][]string{
			{"version", "the format version; always first"},
			{"diagnostic", "an error or a warning, with file, line, col, and message"},
			{"planned", "the check of one step"},
			{"applied", "the apply of one step"},
			{"host", "a host finished, failed, or was unreachable"},
			{"exec", "the output of winch exec on one host"},
			{"summary", "the counts, the plan hash, and the exit code; always last"},
		}),
		doc.Paragraph(`A step event has host and address, such as mail.acme.com:nginx#3[0]:
the host, the stage or recipe, the step number from 1, and the loop
index from 0.`),
		doc.Example(`winch plan site
winch apply site
winch apply site --check a3f9c2e1d07b4c58
winch plan site --exit-code
`),
	},
}

var remoteTopic = doc.Topic{
	Name: "remote",
	Text: "how winch reaches a host and runs there",
	Blocks: []doc.Block{
		doc.Paragraph(`winch works on a host through one SSH connection, the session, with a
helper program at the other end.`),
		doc.Heading("What a host needs"),
		doc.List(
			`Debian 13, Ubuntu 24.04, or Ubuntu 26.04, on amd64 or arm64.`,
			`Login as root, or as a user with passwordless sudo.`,
			`A POSIX login shell that prints nothing on stdout before winch
starts a command.`,
			`/var/lib/winch/ on a file system that allows running programs.`,
		),
		doc.Paragraph(`Nothing else needs to be installed. The machine that runs winch is
Linux or macOS with the OpenSSH client.`),
		doc.Heading("SSH settings"),
		doc.Paragraph(`winch runs your ssh, so ~/.ssh/config applies: Port, IdentityFile,
ProxyJump, and every other setting. Its Host blocks match the host
name of the inventory, also when the host has an address. The
address and the user of the inventory override the SSH config.
--user overrides both.`),
		doc.Code(`# ~/.ssh/config
Host *.acme.com
  Port 2222
  IdentityFile ~/.ssh/acme_ed25519

# inventories/production.yaml
hosts:
  web1.acme.com:
    address: 192.0.2.10
    user: admin

# winch logs in to 192.0.2.10 on port 2222 as admin,
# with the key ~/.ssh/acme_ed25519.
`),
		doc.Paragraph(`winch also passes these options. They win over the SSH config:`),
		doc.Table([][]string{
			{"ConnectTimeout=15\nServerAliveInterval=15\nServerAliveCountMax=3", "a host that does not answer fails\nand does not hang the run"},
			{"RemoteCommand=none\nPermitLocalCommand=no\nClearAllForwardings=yes\nForwardAgent=no\nForwardX11=no", "the SSH config does not replace\nor add to the command of winch"},
		}),
		doc.Heading("Host keys and passphrases"),
		doc.Paragraph(`When stdin and stderr are terminals, ssh can ask for a new host key
or a key passphrase. Sessions then start one at a time, in inventory
order, so each question belongs to one host. After the start, hosts
run in parallel.`),
		doc.Paragraph(`Without a terminal, or with --batch, winch passes BatchMode=yes and
sessions start in parallel. A host that needs a question is then
unreachable. Accept the host key and load the key into ssh-agent
first:`),
		doc.Code(`ssh -o HostName=192.0.2.10 -l admin web1.acme.com
ssh-add ~/.ssh/acme_ed25519
winch apply site --batch

# ssh asks no questions; the apply question stays.
`),
		doc.Paragraph(`The access checks and the connections after a reboot always use
BatchMode=yes. Run winch doc workflow for the access checks.`),
		doc.Heading("When a connection fails"),
		doc.Paragraph(`A host is unreachable when ssh fails before the session starts: the
name does not resolve, the connection is refused or takes more than
15 seconds, or the host key or the login fails. winch then exits 4
when no step failed. For an unknown host key, the error names the ssh
command to run once. For a refused login, it names ssh-add.`),
		doc.Paragraph(`Only one winch run works on a host at a time. When another run holds
the host, the error names that run and the process ID of its helper.
When that run is gone, end the process.`),
		doc.Heading("The session"),
		doc.Paragraph(`A session is one ssh process with the helper at the other end. All
work on a host goes through it. It opens at the first work of the
host and stays open across stages. It closes when the host has no
more work, and at the apply question, which can wait for a long
time. The access checks open their own connections.`),
		doc.Paragraph(`winch keeps the helper in /var/lib/winch/bin/ and sends it when it is
missing. The helper exits when the session ends and leaves no
process, except a confirm_access timer until it ends.`),
		doc.Paragraph(`The helpers for amd64 and arm64 are inside the winch binary. A winch
built with go install has none: plan, apply, run, and exec fail
before they contact a host. Install a release.`),
		doc.Heading("How commands run"),
		doc.Paragraph(`Every command on the host, also one that a module runs, such as
apt-get or systemctl, runs as root in /, with this environment:`),
		doc.Table([][]string{
			{"LC_ALL", "C.UTF-8"},
			{"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			{"HOME", "/root"},
			{"umask", "022"},
		}),
		doc.Paragraph(`The commands of cmd, assert, unless, validate, then, health, and the
certbot hooks run through sh -e, with stdin from /dev/null. A command
of several lines stops at its first failed line.`),
		doc.Paragraph(`A cmd with dir runs in that directory. A cmd with user runs as that
user, with the home of that user as HOME. It starts no login
session: PAM does not run, so the login umask and limits of the user
do not apply.`),
		doc.Heading("The time limit"),
		doc.Paragraph(`A command stops after 10 minutes, or after the timeout of a cmd
step in seconds. The helper sends SIGTERM to the command and its
child processes, and SIGKILL 10 seconds later to those that still
run. The step fails, and the error shows the last 10 lines of
output. apt-get in pkg, repo, and upgrade has no time limit.`),
		doc.Paragraph(`When the connection to winch ends, the helper lets the running
command finish within its limit, and then exits. A package install
is not cut off in the middle. winch exec is different: on Ctrl-C, or
when its session breaks, its command gets SIGINT, and SIGKILL after
10 seconds.`),
		doc.Heading("What winch leaves on the host"),
		doc.Paragraph(`winch keeps its files in /var/lib/winch/:`),
		doc.Table([][]string{
			{"bin/", "the helper"},
			{"handlers/<project>", "pending handlers"},
			{"then/<project>", "pending then commands"},
			{"checks/<project>", "pending health gates and asserts"},
			{"certbot-hooks/<project>", "pending certbot hooks"},
			{"downloads/<project>", "checksum, owner, and group of each unpack"},
			{"firewall.list", "the firewall table after its last load"},
			{"rollback/<project>/", "old files for confirm_access, during a run"},
			{"reboot", "the boot ID and the error of a failed\nreboot, until the next boot"},
			{"lock", "the session lock"},
		}),
		doc.Paragraph(`To remove winch from a host, delete /var/lib/winch/. Pending
handlers, then commands, health gates, asserts, and certbot hooks
are then lost. The next run of winch starts from the state of the
host.`),
	},
}
