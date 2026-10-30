package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

const secretHelp = `Examples:
  winch secret init
  winch secret generate vars.monit_password
  winch secret encrypt < dkim.key
  openssl rand -hex 16 | winch secret encrypt
  winch secret rekey

Encrypt secrets with age for the recipients in winch.yaml.

Usage: winch secret <command>

Commands:
  init      Make an age key, and add its public key to the recipients.
  generate  Write a random password as a secret into the inventory.
  encrypt   Encrypt a value from stdin, and print it as a !secret value.
  rekey     Encrypt all secrets in the project again for the recipients.

winch reads the age identity from the stdout of the command in
WINCH_AGE_IDENTITY_CMD, which runs through sh -c. Without it, winch reads
the file that WINCH_AGE_KEY names, or else ~/.config/winch/age.key. Both
variables set is an error.
`

const initHelp = `Examples:
  winch secret init
  WINCH_AGE_KEY=~/keys/acme.key winch secret init

Make an age key when there is none, print its public key, and add the public
key to recipients in winch.yaml when it is not in the list.

Usage: winch secret init

The key is the file that WINCH_AGE_KEY names, or else ~/.config/winch/age.key.
With WINCH_AGE_IDENTITY_CMD, init makes no key and reads the public key from
the stdout of the command. Both variables set is an error.

The new key can read the secrets only after a member who can read them runs
winch secret rekey.
`

const generateHelp = `Examples:
  winch secret generate vars.monit_password
  winch secret generate vars.db_password --host db1.acme.com
  winch secret generate vars.db_password --inventory production

Make a random password of 32 letters and digits, encrypt it for the
recipients in winch.yaml, and write it as a !secret value into the vars of
the group all in the inventory. The file keeps its comments and layout.

Usage: winch secret generate vars.<name> [flags]

Something in the project must read the variable, and it must not be in
those vars yet.

Flags:
  --inventory <name>            The inventory to write.
  --host <name>                 Write into the vars of this host.
`

const encryptHelp = `Examples:
  winch secret encrypt < dkim.key
  openssl rand -hex 16 | winch secret encrypt

Encrypt a value from stdin for the recipients in winch.yaml, and print it
as a !secret value for a variable.

Usage: winch secret encrypt

A value of one line loses its trailing newline. A value of more lines
stays as it is.
`

const rekeyHelp = `Examples:
  winch secret rekey

Encrypt all secrets in winch.yaml, the inventories, and the recipes again
for the recipients in winch.yaml, and list the files it rewrote. Run it
after a change of the recipients.

Usage: winch secret rekey

winch reads the age identity from the stdout of the command in
WINCH_AGE_IDENTITY_CMD, which runs through sh -c. Without it, winch reads
the file that WINCH_AGE_KEY names, or else ~/.config/winch/age.key. Both
variables set is an error. When a secret does not decrypt, rekey changes no
file.
`

func secretUsage(ctx context.Context, env Env, f *flags, args []string) int {
	fmt.Fprint(env.stderr, secretHelp)
	return exitInvalid
}

func secretInit(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		printError(env.stderr, "winch: secret init takes no arguments")
		return exitInvalid
	}
	identity, err := env.identity()
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	key, made, err := identity.Init(ctx)
	if made {
		fmt.Fprintf(env.stdout, "made the age key %s\n", identity.Path)
	}
	if err != nil {
		printError(env.stderr, fmt.Sprintf("winch: %v", err))
		return exitInvalid
	}
	fmt.Fprintf(env.stdout, "public key: %s\n", key)
	sealed, err := project.HasSecrets(env.Dir)
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	added, err := project.AddRecipient(env.Dir, key)
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	if !added {
		return exitOK
	}
	fmt.Fprintln(env.stdout, "added the public key to recipients in winch.yaml")
	if sealed {
		fmt.Fprintln(env.stdout, "a member who can read the secrets must now run winch secret rekey")
	}
	return exitOK
}

func secretGenerate(ctx context.Context, env Env, f *flags, args []string) int {
	name, ok := "", false
	if len(args) == 1 {
		name, ok = strings.CutPrefix(args[0], "vars.")
	}
	if !ok || name == "" {
		printError(env.stderr, "winch: secret generate needs one variable: vars.<name>")
		return exitInvalid
	}
	file, err := project.WriteSecret(env.Dir, f.inventory, f.host, name, secret.Password())
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	where := "the group all"
	if f.host != "" {
		where = fmt.Sprintf("host %q", f.host)
	}
	fmt.Fprintf(env.stdout, "wrote vars.%s into the vars of %s in %s\n", name, where, file)
	return exitOK
}

func secretEncrypt(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		printError(env.stderr, "winch: secret encrypt takes no arguments")
		return exitInvalid
	}
	recs, err := project.Recipients(env.Dir)
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	in, err := io.ReadAll(env.In)
	if err != nil {
		printError(env.stderr, fmt.Sprintf("winch: read stdin: %v", err))
		return exitInvalid
	}
	value, err := secret.OneLine(string(in))
	if err != nil {
		printError(env.stderr, fmt.Sprintf("winch: %v", err))
		return exitInvalid
	}
	text, err := secret.Encrypt(value, recs)
	if err != nil {
		printError(env.stderr, fmt.Sprintf("winch: encrypt: %v", err))
		return exitInvalid
	}
	fmt.Fprintf(env.stdout, "!secret %s\n", text)
	return exitOK
}

func secretRekey(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		printError(env.stderr, "winch: secret rekey takes no arguments")
		return exitInvalid
	}
	identity, err := env.identity()
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	n, files, err := project.Rekey(ctx, env.Dir, identity)
	if err != nil {
		printError(env.stderr, err.Error())
		return exitInvalid
	}
	fmt.Fprintf(env.stdout, "rekeyed %s in %s\n", count(n, "secret"), count(len(files), "file"))
	for _, file := range files {
		fmt.Fprintf(env.stdout, "  %s\n", file)
	}
	return exitOK
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
