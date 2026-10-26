package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

const secretHelp = `Examples:
  winch secret encrypt < dkim.key
  openssl rand -hex 16 | winch secret encrypt
  winch secret rekey

Encrypt secrets with age for the recipients in winch.yaml.

Usage: winch secret <command>

Commands:
  encrypt   Encrypt a value from stdin, and print it as a !secret value.
  rekey     Encrypt all secrets in the project again for the recipients.

winch reads the age identity from the stdout of the command in
WINCH_AGE_IDENTITY_CMD, which runs through sh -c. Without it, winch reads
the file that WINCH_AGE_KEY names, or else ~/.config/winch/age.key. Both
variables set is an error.
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
for the recipients in winch.yaml. Run it after a change of the recipients.

Usage: winch secret rekey

winch reads the age identity from the stdout of the command in
WINCH_AGE_IDENTITY_CMD, which runs through sh -c. Without it, winch reads
the file that WINCH_AGE_KEY names, or else ~/.config/winch/age.key. Both
variables set is an error. When a secret does not decrypt, rekey changes no
file.
`

func secretUsage(ctx context.Context, env Env, f *flags, args []string) int {
	fmt.Fprint(env.Err, secretHelp)
	return exitInvalid
}

func secretEncrypt(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		printError(env.Err, "winch: secret encrypt takes no arguments")
		return exitInvalid
	}
	recs, err := project.Recipients(env.Dir)
	if err != nil {
		printError(env.Err, err.Error())
		return exitInvalid
	}
	in, err := io.ReadAll(env.In)
	if err != nil {
		printError(env.Err, fmt.Sprintf("winch: read stdin: %v", err))
		return exitInvalid
	}
	value, err := secret.OneLine(string(in))
	if err != nil {
		printError(env.Err, fmt.Sprintf("winch: %v", err))
		return exitInvalid
	}
	text, err := secret.Encrypt(value, recs)
	if err != nil {
		printError(env.Err, fmt.Sprintf("winch: encrypt: %v", err))
		return exitInvalid
	}
	fmt.Fprintf(env.Out, "!secret %s\n", text)
	return exitOK
}

func secretRekey(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		printError(env.Err, "winch: secret rekey takes no arguments")
		return exitInvalid
	}
	identity, err := env.identity()
	if err != nil {
		printError(env.Err, err.Error())
		return exitInvalid
	}
	n, files, err := project.Rekey(ctx, env.Dir, identity)
	if err != nil {
		printError(env.Err, err.Error())
		return exitInvalid
	}
	fmt.Fprintf(env.Out, "rekeyed %s in %s\n", count(n, "secret"), count(files, "file"))
	return exitOK
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
