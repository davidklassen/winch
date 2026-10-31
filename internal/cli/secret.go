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
		env.fail(usage("takes no arguments"))
		return exitInvalid
	}
	identity, err := env.identity()
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	sealed, err := project.HasSecrets(env.Dir)
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	key, made, err := identity.Init(ctx)
	if err != nil {
		env.fail(usage("%v", err))
		return exitInvalid
	}
	if made != nil {
		if err := identity.WriteKey(made); err != nil {
			env.fail(usage("%v", err))
			return exitInvalid
		}
		fmt.Fprintf(env.stdout, "made the age key %s\n", identity.Path)
	}
	fmt.Fprintf(env.stdout, "public key: %s\n", key)
	edit, err := project.AddRecipient(env.Dir, key)
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	if edit == nil {
		return exitOK
	}
	if err := edit.Write(); err != nil {
		env.fail(err)
		return exitInvalid
	}
	fmt.Fprintf(env.stdout, "added the public key to recipients in %s\n", edit.File)
	if sealed {
		fmt.Fprintln(env.stdout, "a member who can read the secrets must run winch secret rekey")
	}
	return exitOK
}

func secretGenerate(ctx context.Context, env Env, f *flags, args []string) int {
	name, ok := "", false
	if len(args) == 1 {
		name, ok = strings.CutPrefix(args[0], "vars.")
	}
	if !ok || name == "" {
		env.fail(usage("needs one variable: vars.<name>"))
		return exitInvalid
	}
	file, err := project.WriteSecret(env.Dir, f.inventory, f.host, name, secret.Password())
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	where := "the group all"
	if f.host != "" {
		where = "host " + f.host
	}
	fmt.Fprintf(env.stdout, "wrote vars.%s into the vars of %s in %s\n", name, where, file)
	return exitOK
}

func secretEncrypt(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		env.fail(usage("takes no arguments"))
		return exitInvalid
	}
	recs, err := project.Recipients(env.Dir)
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	in, err := io.ReadAll(env.In)
	if err != nil {
		env.fail(usage("read stdin: %v", err))
		return exitInvalid
	}
	value, err := secret.OneLine(string(in))
	if err != nil {
		env.fail(usage("%v", err))
		return exitInvalid
	}
	text, err := secret.Encrypt(value, recs)
	if err != nil {
		env.fail(usage("encrypt: %v", err))
		return exitInvalid
	}
	fmt.Fprintf(env.stdout, "!secret %s\n", text)
	return exitOK
}

func secretRekey(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) != 0 {
		env.fail(usage("takes no arguments"))
		return exitInvalid
	}
	identity, err := env.identity()
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	n, files, err := project.Rekey(ctx, env.Dir, identity)
	if err != nil {
		env.fail(err)
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
