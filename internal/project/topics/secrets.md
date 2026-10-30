encrypted values in the project

A secret is a value that the project keeps encrypted and winch never
prints. It is encrypted with age for the recipients in winch.yaml. The
!secret tag marks it, followed by the ciphertext in base64 on one line.
A !secret stands only in a variable value: in the vars of an inventory,
and in the defaults of winch.yaml and of recipes, at any depth of a list
or a map.

    vars:
      monit_password: !secret YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...

    winch secret init                  make an age key and add it to recipients
    winch secret generate vars.<name>  write a random password into the inventory
    winch secret encrypt               encrypt a value from stdin
    winch secret rekey                 encrypt all secrets for the current recipients

winch secret init makes a key at ~/.config/winch/age.key, or at the path
in WINCH_AGE_KEY, only when no key is there. With
WINCH_AGE_IDENTITY_CMD, it makes no key and adds the public key of the
command's key. A new member runs it and sends the change for review. The
new key can read the secrets after a member who can read them runs winch
secret rekey.

winch reads the age identity from the output of the command in
WINCH_AGE_IDENTITY_CMD, such as op read op://infra/winch/key. Without
it, winch reads the file in WINCH_AGE_KEY, or else
~/.config/winch/age.key. winch validate needs no identity.

A variable is secret when its value is a !secret, or when its default
reads a secret variable. The plan, diffs, errors, logs, and JSON show
(secret) in place of a secret, also a part of a value that comes from
a secret. A filter replaces each secret value in all text that winch
prints, also in output from the host. The filter also hides private
keys, age identities, passwords in URLs, and well-known tokens.

- --set cannot give a secret.
- winch warns about text in project files that looks like a private key
  or a token, and is not a !secret.
- winch warns about a file step whose content reads a secret and whose
  mode is missing or lets others read it.
- A !secret in a certbot hook is an error: certbot stores its hooks in
  a file that other users can read.
