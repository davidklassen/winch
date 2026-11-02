package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

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
		if env.Terminal {
			what := "Secret"
			if len(args) == 1 {
				what = "Secret for " + args[0]
			}
			return promptValue(env, what)
		}
		if f, ok := env.In.(*os.File); ok && IsTerminal(f) {
			return "", usage("stdin is a terminal, but stderr is not, so winch cannot ask for the secret; pipe the value, or run with stderr on the terminal")
		}
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

// promptValue asks for one line twice on the terminal, without echo. The
// first prompt names what. A signal ends the prompt, so that it does not
// leave the echo off.
func promptValue(env Env, what string) (string, error) {
	var signals chan os.Signal
	if f, ok := env.In.(*os.File); ok {
		if err := discardInput(f); err != nil {
			return "", usage("discard the typed input: %v", err)
		}
		signals = make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM)
		// Notify turns on a SIGHUP that nohup ignores.
		if !signal.Ignored(syscall.SIGHUP) {
			signal.Notify(signals, syscall.SIGHUP)
		}
		defer signal.Stop(signals)
		restore, err := echoOff(f)
		if err != nil {
			return "", usage("turn off the echo of the terminal: %v", err)
		}
		defer restore()
	}
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		var lines [2]string
		in := bufio.NewReader(env.In)
		for i, prompt := range []string{what + ": ", "Confirm secret: "} {
			fmt.Fprint(env.stderr, prompt)
			line, err := in.ReadString('\n')
			// The terminal does not echo the newline either.
			fmt.Fprintln(env.stderr)
			if err != nil && !errors.Is(err, io.EOF) {
				done <- result{err: usage("read the terminal: %v", err)}
				return
			}
			lines[i] = line
		}
		value, err := secret.OneLine(lines[0])
		if err != nil {
			done <- result{err: usage("%v", err)}
			return
		}
		if again, _ := secret.OneLine(lines[1]); again != value {
			done <- result{err: usage("the two values differ")}
			return
		}
		done <- result{value: value}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-signals:
		fmt.Fprintln(env.stderr)
		return "", usage("interrupted; nothing was written")
	}
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
		if re, ok := errors.AsType[*project.RekeyError](err); ok && len(re.Rewrote) > 0 {
			fmt.Fprintf(env.stdout, "rewrote %d of %s:\n", len(re.Rewrote), count(re.Files, "file"))
			for _, file := range re.Rewrote {
				fmt.Fprintf(env.stdout, "  %s\n", file)
			}
		}
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
