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
	return writeSecret(env, args, func() (string, error) { return secret.Password(), nil })
}

func secretEncrypt(ctx context.Context, env Env, f *flags, args []string) int {
	return writeSecret(env, args, func() (string, error) {
		in, err := io.ReadAll(env.In)
		if err != nil {
			return "", usage("read stdin: %v", err)
		}
		value, err := secret.OneLine(string(in))
		if err != nil {
			return "", usage("%v", err)
		}
		return value, nil
	})
}

// writeSecret encrypts the value of plain and writes it at the path in args,
// or prints it without a path.
func writeSecret(env Env, args []string, plain func() (string, error)) int {
	if len(args) > 1 {
		env.fail(usage("takes one path at most"))
		return exitInvalid
	}
	var write func(string) (string, error)
	if len(args) == 1 {
		edit, err := project.SecretAt(env.Dir, args[0])
		if err != nil {
			env.fail(err)
			return exitInvalid
		}
		write = edit.Write
	} else {
		recs, err := project.Recipients(env.Dir)
		if err != nil {
			env.fail(err)
			return exitInvalid
		}
		write = func(value string) (string, error) {
			text, err := secret.Encrypt(value, recs)
			if err != nil {
				return "", usage("encrypt: %v", err)
			}
			return "!secret " + text, nil
		}
	}
	value, err := plain()
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	line, err := write(value)
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	fmt.Fprintln(env.stdout, line)
	return exitOK
}

func secretDecrypt(ctx context.Context, env Env, f *flags, args []string) int {
	if len(args) > 1 {
		env.fail(usage("takes one path at most"))
		return exitInvalid
	}
	identity, err := env.identity()
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	var at, text string
	if len(args) == 1 {
		at = args[0]
	} else {
		if env.Terminal {
			env.fail(usage("give a path, or a !secret value on stdin"))
			return exitInvalid
		}
		in, err := io.ReadAll(env.In)
		if err != nil {
			env.fail(usage("read stdin: %v", err))
			return exitInvalid
		}
		fields := strings.Fields(string(in))
		if len(fields) > 0 && fields[0] == "!secret" {
			fields = fields[1:]
		}
		switch len(fields) {
		case 0:
			env.fail(usage("stdin holds no !secret value"))
			return exitInvalid
		case 1:
			text = fields[0]
		default:
			env.fail(usage("stdin holds more than one value; give one !secret value"))
			return exitInvalid
		}
	}
	plain, err := project.Decrypt(ctx, env.Dir, at, text, identity)
	if err != nil {
		env.fail(err)
		return exitInvalid
	}
	fmt.Fprint(env.plainOut, plain)
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
