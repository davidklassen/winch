package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

func secretUsage(ctx context.Context, env Env, f *flags, args []string) int {
	c, _ := commandNamed("secret")
	writeHelp(env.stderr, c)
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
