package cli

import (
	"fmt"
	"io"
	"strings"
)

// command is a command of winch and the text of its --help. Texts keep the
// line breaks of the terminal.
type command struct {
	name, summary string
	examples      []example
	usage         []string
	description   []string
	// flags are the flags that the command takes.
	flags []flagDoc
	// see are the winch doc pages to read next.
	see []string
}

type example struct{ comment, command string }

// flagDoc is a flag of a command. Its name decides how Main parses it.
type flagDoc struct{ name, value, def, text string }

const docIntro = `Winch is a server configuration tool. It describes the desired state
of your servers in declarative YAML and provides commands to manage
that state.`

// subcommands returns the commands one word below c, in help order, each
// with its last word.
func subcommands(c command) ([]command, []string) {
	var subs []command
	var words []string
	for _, sub := range commands {
		parent, word := "", sub.name
		if i := strings.LastIndex(sub.name, " "); i >= 0 {
			parent, word = sub.name[:i], sub.name[i+1:]
		}
		if parent == c.name {
			subs, words = append(subs, sub), append(words, word)
		}
	}
	return subs, words
}

// writeHelp writes the --help text of c: a summary line, examples, usage,
// description, subcommands, flags, and the pages to read next.
func writeHelp(out io.Writer, c command) {
	if c.name == "" {
		fmt.Fprintf(out, "%s\n", docIntro)
	} else {
		fmt.Fprintf(out, "winch %s: %s\n", c.name, c.summary)
	}
	fmt.Fprint(out, "\nExamples:\n")
	for _, e := range c.examples {
		fmt.Fprintf(out, "  # %s\n  %s\n", e.comment, e.command)
	}
	fmt.Fprint(out, "\nUsage:\n")
	for _, u := range c.usage {
		fmt.Fprintf(out, "  %s\n", u)
	}
	for _, p := range c.description {
		fmt.Fprintf(out, "\n%s\n", p)
	}
	subs, words := subcommands(c)
	if len(subs) > 0 {
		width := 0
		for _, w := range words {
			width = max(width, len(w))
		}
		fmt.Fprint(out, "\nCommands:\n")
		for i, sub := range subs {
			fmt.Fprintf(out, "  %-*s  %s\n", width, words[i], sub.summary)
		}
	}
	if len(c.flags) > 0 {
		fmt.Fprint(out, "\nFlags:\n")
		for _, f := range c.flags {
			head := strings.TrimSpace(f.name + " " + f.value)
			text := strings.ReplaceAll(f.text, "\n", "\n"+strings.Repeat(" ", 30))
			fmt.Fprintf(out, "  %-28s%s\n", head, text)
			if f.def != "" {
				fmt.Fprintf(out, "%30sdefault: %s\n", "", f.def)
			}
		}
	}
	if len(subs) > 0 {
		cmd := strings.TrimSpace("winch " + c.name)
		fmt.Fprintf(out, "\n%s\n", wrap(fmt.Sprintf("Run \"%s <command> --help\" for the arguments and flags of a command.", cmd), 72))
	}
	if len(c.see) > 0 {
		fmt.Fprintf(out, "\nSee: %s\n", strings.Join(c.see, ", "))
	}
}

var (
	setFlag       = flagDoc{name: "--set", value: "vars.<name>=<value>", text: "variable value; repeatable"}
	jsonFlag      = flagDoc{name: "--json", text: "JSON events on stdout"}
	inventoryFlag = flagDoc{name: "--inventory", value: "<name>", def: "inventory in winch.yaml", text: "inventory for the run"}
	hostsFlag     = flagDoc{name: "--hosts", value: "<pattern>", def: "all", text: "only these hosts"}
	stagesFlag    = flagDoc{name: "--stages", value: "<names>", def: "all", text: "only these stages, such as mail,monit"}
	userFlag      = flagDoc{name: "--user", value: "[<host>=]<name>", def: "from the inventory", text: "SSH login user, for all hosts or one;\nrepeatable"}
	batchFlag     = flagDoc{name: "--batch", text: "no questions from ssh"}
	yesFlag       = flagDoc{name: "--yes", text: "no apply question"}
	checkFlag     = flagDoc{name: "--check", value: "<hash>", text: "plan hash that the apply needs"}
)

var mainCommand = command{
	examples: []example{
		{"check the project without contacting a host", "winch validate"},
		{"show the changes of the pipeline site on the test inventory", "winch plan site --inventory test"},
		{"make those changes after a question", "winch apply site --inventory test"},
	},
	usage: []string{"winch <command> [arguments] [flags]"},
	flags: []flagDoc{
		{name: "--version", text: "version and platform, as winch version"},
	},
	see: []string{"winch doc"},
}

var commands = []command{
	{
		name:    "validate",
		summary: "check the project without contacting a host",
		examples: []example{
			{"check the project", "winch validate"},
			{"check the project with the inventory production", "winch validate --inventory production"},
			{"check the project with a value for one variable", "winch validate --set vars.release=1.4.2"},
		},
		usage: []string{"winch validate [flags]"},
		description: []string{
			"Validate loads the project and checks it. It connects to no host.",
			`It checks the schemas, the names, the module arguments, the variable
reads and values, the expressions, and the templates.`,
			`It loads the inventory of --inventory, or of inventory in winch.yaml.
Without both, it checks every inventory.`,
			`It does not decrypt secrets and needs no age identity. It checks that
each !secret is an age file. It warns about a secret whose number of
recipients differs from the recipients list, and names winch secret
rekey.`,
			`A --set value parses as YAML. Quote a value that YAML would change:
--set 'vars.php_version="8.0"'.`,
		},
		flags: []flagDoc{
			{name: "--inventory", value: "<name>", def: "inventory in winch.yaml, else all", text: "inventory to check"},
			setFlag,
			jsonFlag,
		},
		see: []string{"winch doc project", "winch doc variables"},
	},
	{
		name:    "fmt",
		summary: "format the project files",
		examples: []example{
			{"format winch.yaml, the inventories, the pipelines, and the recipes", "winch fmt"},
		},
		usage: []string{"winch fmt"},
		description: []string{
			`Fmt fixes the indentation and the step key order of the project files:
winch.yaml, the inventories, the pipelines, and the recipes.`,
			"It indents with two spaces, and indents list items under their key.",
			`It puts step keys in this order: name, the module or recipe key, vars,
when, loop, then, confirm_access, notify. Steps in flow style keep
their key order. A comment above a key that moves to the first place
goes above the "-" of its step.`,
			`It keeps comments, blank lines, quoting, anchors, flow style, and line
ends. It writes a file only when the result decodes to the same values.
It prints each file that it changes.`,
			`When a file does not parse, or fmt cannot keep the layout of a file,
fmt shows the error, exits with code 3, and changes no file.`,
		},
		see: []string{"winch doc step"},
	},
	{
		name:    "plan",
		summary: "show the changes and change nothing",
		examples: []example{
			{"show the changes of the pipeline site", "winch plan site"},
			{"use the inventory production", "winch plan site --inventory production"},
			{"plan with a value for one variable", "winch plan site --set vars.nginx_port=8080"},
			{"plan two stages on the web hosts without web3", "winch plan site --hosts 'web & !web3' --stages nginx,site"},
			{"exit with code 2 when apply would change something", "winch plan site --exit-code"},
		},
		usage: []string{"winch plan [<pipeline>] [flags]"},
		description: []string{
			`Plan shows the changes that winch apply would make, and the plan hash.
It changes nothing.`,
			`Leave out the pipeline name when the steps are at the top of
winch.yaml.`,
			`A host pattern is a group or a host, with "," for union, "&" for
intersection, and "!" for exclusion. Each stage runs on the hosts in
both its hosts and --hosts. The stages of --stages run in pipeline
order.`,
			"A --set value parses as YAML.",
			`With a terminal, ssh can ask questions, and sessions start one at a
time. Without one, or with --batch, ssh asks nothing, and sessions
start in parallel.`,
			`With --exit-code, plan exits with code 2 when the plan has changes,
unknown steps, pending handlers, a pending then, or a pending gate or
assert.`,
		},
		flags: []flagDoc{
			inventoryFlag,
			hostsFlag,
			stagesFlag,
			userFlag,
			setFlag,
			batchFlag,
			{name: "--exit-code", text: "exit code 2 for a plan with changes"},
			jsonFlag,
		},
		see: []string{"winch doc workflow", "winch doc pipeline", "winch doc inventory"},
	},
	{
		name:    "apply",
		summary: "show the changes, ask, then make them",
		examples: []example{
			{"plan the pipeline site, ask, and make the changes", "winch apply site"},
			{"apply on the test inventory without the question", "winch apply site --inventory test --yes"},
			{"apply the stage mail on the mail hosts", "winch apply site --hosts mail --stages mail"},
			{"apply only the plan that you checked before", "winch apply site --check a3f9c2e1d07b4c58"},
		},
		usage: []string{"winch apply [<pipeline>] [flags]"},
		description: []string{
			`Apply shows the plan of a pipeline, asks for approval, and then makes
the changes.`,
			`Leave out the pipeline name when the steps are at the top of
winch.yaml.`,
			`winch asks only when stdin and stderr are terminals. Without a
terminal, and without --yes or --check, apply prints the plan and exits
with code 5. Its last line is the command that applies the plan with
its hash.`,
			`--check replaces the question. When the new plan has another hash,
apply exits with code 6 and changes nothing.`,
			`A host pattern is a group or a host, with "," for union, "&" for
intersection, and "!" for exclusion. Each stage runs on the hosts in
both its hosts and --hosts. The stages of --stages run in pipeline
order.`,
			"A --set value parses as YAML.",
			`With a terminal, ssh can ask questions, and sessions start one at a
time. Without one, or with --batch, ssh asks nothing, and sessions
start in parallel. The apply question stays.`,
			`The first Ctrl-C lets the running step on each host finish and starts
no new step. A second Ctrl-C ends the sessions at once.`,
		},
		flags: []flagDoc{
			inventoryFlag,
			hostsFlag,
			stagesFlag,
			userFlag,
			setFlag,
			batchFlag,
			yesFlag,
			checkFlag,
			jsonFlag,
		},
		see: []string{"winch doc workflow", "winch doc pipeline", "winch doc inventory"},
	},
	{
		name:    "run",
		summary: "plan and apply one module step",
		examples: []example{
			{"upgrade all packages on the mail hosts", "winch run mail upgrade mode=full"},
			{"install two packages on the mail hosts without mail2", "winch run 'mail & !mail2' pkg name=[htop,curl]"},
			{"restart monit on the monitor hosts", "winch run monitor service name=monit restarted=true"},
			{"write /etc/motd only when the plan has this hash", "winch run web file path=/etc/motd content=hello --check a3f9c2e1d07b4c58"},
		},
		usage: []string{"winch run <pattern> <module> [key=value ...] [flags]"},
		description: []string{
			`Run plans one module step on the hosts of the pattern, asks, and
applies it.`,
			`A host pattern is a group or a host, with "," for union, "&" for
intersection, and "!" for exclusion.`,
			`Each value parses as YAML: name=[htop,curl] is a list. Quote a value
that YAML would change, such as mode='"0644"'. A value that YAML
rejects, such as *x, @x, or [x, is an error that says to quote it.`,
			`The step runs in a stage named run. Unlike a pipeline step, it can use
restarted and reloaded. Run rejects assert. Use winch exec for a check.`,
			`winch asks only when stdin and stderr are terminals. Without a
terminal, and without --yes or --check, run prints the plan and exits
with code 5. Its last line is the command that applies the plan with
its hash.`,
			`--check replaces the question. When the new plan has another hash, run
exits with code 6 and changes nothing.`,
			`With a terminal, ssh can ask questions, and sessions start one at a
time. Without one, or with --batch, ssh asks nothing, and sessions
start in parallel. The apply question stays.`,
		},
		flags: []flagDoc{
			inventoryFlag,
			userFlag,
			batchFlag,
			yesFlag,
			checkFlag,
			jsonFlag,
		},
		see: []string{"winch doc <module>", "winch doc inventory", "winch doc workflow"},
	},
	{
		name:    "exec",
		summary: "run a shell command on hosts",
		examples: []example{
			{"show the uptime of every host", "winch exec all -- uptime"},
			{"show the last 50 log lines of the app container on the web hosts", "winch exec web -- docker logs app --tail 50"},
			{"check nginx on the web hosts without web3, as JSON", "winch exec 'web & !web3' --json -- systemctl is-active nginx"},
		},
		usage: []string{"winch exec <pattern> [flags] -- <command ...>"},
		description: []string{
			`Exec runs a shell command on the hosts of the pattern, in parallel, and
shows its output. It makes no plan and asks no question.`,
			`A host pattern is a group or a host, with "," for union, "&" for
intersection, and "!" for exclusion.`,
			`winch joins the words after -- with spaces and runs them through sh -c
as root, in /.`,
			`Each host shows one block: the host name, then the output. Hosts with
the same output and exit code share one block. A command that exits
non-zero adds "exit status N" to its block. winch exits with code 1
when the command fails on a host.`,
			"With --json, each host gives one exec event with output and exit_code.",
			`Ctrl-C stops the commands. Each host sends SIGINT to the command, and
SIGKILL when it still runs after 10 seconds.`,
			`With a terminal, ssh can ask questions, and sessions start one at a
time. Without one, or with --batch, ssh asks nothing, and sessions
start in parallel.`,
		},
		flags: []flagDoc{
			inventoryFlag,
			userFlag,
			batchFlag,
			{name: "--json", text: "one exec event per host on stdout"},
		},
		see: []string{"winch doc inventory", "winch doc remote"},
	},
	{
		name:    "secret",
		summary: "manage secrets and the age key",
		examples: []example{
			{"make your age key and add it to the recipients", "winch secret init"},
			{"write a random password into the inventory", "winch secret generate vars.monit_password"},
			{"encrypt the content of a file", "winch secret encrypt < dkim.key"},
			{"encrypt the output of a command", "openssl rand -hex 16 | winch secret encrypt"},
			{"encrypt all secrets again after a change of the recipients", "winch secret rekey"},
		},
		usage: []string{"winch secret <command>"},
		description: []string{
			"Secret encrypts values with age for the recipients in winch.yaml.",
			`winch reads the age identity from the stdout of the command in
WINCH_AGE_IDENTITY_CMD, which runs through sh -c. Without it, winch
reads the file that WINCH_AGE_KEY names, or else
~/.config/winch/age.key. Both variables set is an error.`,
		},
		see: []string{"winch doc secrets"},
	},
	{
		name:    "secret init",
		summary: "add an age key to the recipients",
		examples: []example{
			{"make a key when there is none, and add it to the recipients", "winch secret init"},
			{"use the key at another path", "WINCH_AGE_KEY=~/keys/acme.key winch secret init"},
		},
		usage: []string{"winch secret init"},
		description: []string{
			`Init makes an age key when there is none, prints its public key, and
adds the public key to recipients in winch.yaml when it is not in the
list.`,
			`The key is the file that WINCH_AGE_KEY names, or else
~/.config/winch/age.key. A new key gets mode 0600, and its directory
0700.`,
			`With WINCH_AGE_IDENTITY_CMD, init makes no key and reads the public key
from the stdout of the command. Both variables set is an error.`,
			`The new key can read the secrets only after a member who can read them
runs winch secret rekey.`,
		},
		see: []string{"winch doc secrets"},
	},
	{
		name:    "secret generate",
		summary: "write a random password as a secret",
		examples: []example{
			{"write a password into the vars of the group all", "winch secret generate vars.monit_password"},
			{"write a password into the vars of one host", "winch secret generate vars.db_password --host db1.acme.com"},
			{"write a password into the inventory production", "winch secret generate vars.db_password --inventory production"},
		},
		usage: []string{"winch secret generate vars.<name> [flags]"},
		description: []string{
			`Generate makes a random password of 32 letters and digits, encrypts it
for the recipients in winch.yaml, and writes it as a !secret value into
the inventory.`,
			`It writes into the vars of the group all, or of the host of --host. The
file keeps its comments and layout.`,
			`Something in the project must read the variable. The variable must not
be in those vars yet, also not as null.`,
		},
		flags: []flagDoc{
			{name: "--inventory", value: "<name>", def: "inventory in winch.yaml", text: "inventory to write"},
			{name: "--host", value: "<name>", def: "the group all", text: "host whose vars get the value"},
		},
		see: []string{"winch doc secrets"},
	},
	{
		name:    "secret encrypt",
		summary: "encrypt a value from stdin",
		examples: []example{
			{"encrypt the content of a file", "winch secret encrypt < dkim.key"},
			{"encrypt the output of a command", "openssl rand -hex 16 | winch secret encrypt"},
		},
		usage: []string{"winch secret encrypt"},
		description: []string{
			`Encrypt reads a value from stdin, encrypts it for the recipients in
winch.yaml, and prints it as a !secret value for a variable.`,
			`A value of one line loses its trailing newline. A value of more lines
stays as it is.`,
			`A !secret stands only in a variable value: in inventory vars, and in
the defaults of winch.yaml and of recipes.`,
		},
		see: []string{"winch doc secrets"},
	},
	{
		name:    "secret rekey",
		summary: "encrypt all secrets again",
		examples: []example{
			{"encrypt all secrets again for the recipients in winch.yaml", "winch secret rekey"},
		},
		usage: []string{"winch secret rekey"},
		description: []string{
			`Rekey encrypts all secrets in winch.yaml, the inventories, and the
recipes again for the recipients in winch.yaml. It lists the files it
rewrote.`,
			"Run it after a change of the recipients.",
			`It writes through a symbolic link to its target. When a secret does not
decrypt, rekey changes no file.`,
			`winch reads the age identity from the stdout of the command in
WINCH_AGE_IDENTITY_CMD, which runs through sh -c. Without it, winch
reads the file that WINCH_AGE_KEY names, or else
~/.config/winch/age.key. Both variables set is an error.`,
		},
		see: []string{"winch doc secrets"},
	},
	{
		name:    "doc",
		summary: "show the reference",
		examples: []example{
			{"list the topics and the modules", "winch doc"},
			{"show a topic", "winch doc project"},
			{"show one key of a topic", "winch doc step.when"},
			{"show the keys of a module and an example step", "winch doc file"},
			{"show the full text of one key", "winch doc file.mode"},
			{"show a key of a list element", "winch doc firewall.allow.tcp"},
			{"print the whole reference as JSON", "winch doc --json"},
		},
		usage: []string{"winch doc [<topic> | <module>][.<key>...]", "winch doc --json"},
		description: []string{
			`Doc shows the reference: the index of topics and modules, a topic, the
keys of one module with an example step, or the full text of one key
or function.`,
			`It needs no project. The text comes from the definitions that the load
checks use, so it matches the installed version.`,
			"An unknown module or key is an error with \"did you mean\".",
		},
		flags: []flagDoc{
			{name: "--json", text: "whole reference as one JSON document"},
		},
	},
	{
		name:    "version",
		summary: "print the version and the platform",
		examples: []example{
			{"print the version and the platform", "winch version"},
		},
		usage: []string{"winch version", "winch --version"},
		description: []string{
			`Version prints the version of winch and the platform, such as
winch v0.1.0 darwin/arm64.`,
		},
	},
}
