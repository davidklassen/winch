# Changelog

## v0.4.1

### Fixed

- Login protection:
  - a handler whose access check passed keeps the files of the steps
    that notified it. Before, a later failed step of the handler put
    them back while the service ran the new config;
  - after a rollback of a handler's guarded step, apply no longer
    prints a false `put back ...: the handler ... did not run`;
  - putting back the file of a notifying step in a directory that the
    run created removes only that file. Before, it removed the whole
    directory with the files of other steps;
  - on a failed host, the put-back line prints after the error of the
    host.
- `winch exec` runs while a variable of the project has no value. It
  runs no step, so a value that only a later run makes, such as a
  join key, no longer blocks it.
- `winch validate` checks the plain keys of a block that also holds an
  `!expr` key, such as a firewall rule with `tcp: 70000` and an
  expression in `from`.
- A tagged value that starts with `{{`, such as
  `path: !tpl {{ vars.d }}/x`, fails with
  `a value that starts with "{{" needs quotes` at its line. Before,
  YAML's error named the line above, with no hint.
- A failed `apt-get update` shows only apt's warnings and errors, not
  a line for each index file.
- A failed `validate` names what it removed or put back: a file, a
  symbolic link, or a directory.
- `winch doc` states rules it left out: `enabled` on a unit from an
  init script, two matching lines in `line`, no `%s` in `validate`,
  `cmd` as `user` in `dir`, the files that each session touches,
  what `secret generate` makes, `{{ }}` without `!tpl`, and how the
  summary counts hosts.

## v0.4.0

### Breaking changes

- Templates use the expression language of `!expr`. `!tpl` values and
  template files no longer run on Go's text/template. To migrate:
  - drop the leading dot: `{{ .vars.domain }}` is `{{ vars.domain }}`,
    `{{ .host.name }}` is `{{ host.name }}`, `{{ .item }}` is
    `{{ item }}`;
  - `{{ range .vars.list }}` is `{{ for x in vars.list }}`, and the
    body reads `x` in place of `.`. `{{ range $k, $v := .vars.map }}`
    is `{{ for k, v in vars.map }}`;
  - functions take their arguments in parentheses, as in `!expr`:
    `{{ join .vars.names ", " }}` is `{{ join(vars.names, ", ") }}`,
    `{{ quote .vars.x }}` is `{{ quote(vars.x) }}`;
  - `with`, `define`, `template`, `block`, `break`, `continue`, and
    `$x :=` variables are gone.
  An old template fails to load, with the file, line, and column. Also:
  - printing null fails, and a list or a map prints as JSON;
  - `if` takes true or false: `{{ if vars.name }}` on a string fails.
    Write `{{ if vars.name != "" }}`;
  - `keys`, `values`, and `toPairs` of an empty map give an empty list,
    not null; a bare `now` is a load error.
- The `assert` module is gone. An `assert` step is an unknown module.
  Use a health gate on the stage: its `command` runs after the stage on
  each host that changed. Pending assert records on a host show in the
  plan as gone, and apply removes them.
- A failure in a stage stops the pipeline after that stage. Before, the
  later stages ran on the other hosts. The hosts of the failed stage
  finish it; each host of a later stage with a change fails with `not
  started: <host> failed in stage <stage>`. To go on without a failed
  host, leave it out with `--hosts`.

### Added

- Read other hosts: `hosts` lists every host of the inventory, with
  `name`, `address`, `groups`, `vars`, and `facts`. `match()` works in
  templates and defaults, and its hosts have facts and all their
  variables. New facts: `ssh.ed25519`, `ssh.ecdsa`, `ssh.rsa`,
  `net.ipv4`, and `net.ipv6`.
- Templates: `for` over a map, in sorted key order; `for key, value in
  ...` over a map or a list; `{{ /* comment */ }}`.
- A health gate `command` can be a `!tpl`. It reads the data of the
  host.
- `absent: true` on `unit` stops the unit, removes its links and file,
  and runs daemon-reload. On `repo`, it removes the source and its key.
- Firewall rules can have both `tcp` and `udp`, or only `from` to
  accept all traffic from those sources.
- `cmd` has `changes`: the PAM or sudo paths that the command changes,
  such as with `pam-auth-update`. The step gets the access check and
  the rollback, as a file step in `/etc/pam.d` does.
- `join` takes numbers as well as strings.

### Fixed

- Login protection:
  - the access check after the run also runs when a step fails or after
    the first Ctrl-C, on a host that changed something;
  - when a run ends before a `confirm_access` handler ran, only the
    files of the steps that notified it go back, and apply prints `put
    back <paths>: the handler <recipe>.<handler> did not run`. Before,
    the files of the whole recipe went back;
  - the rollback timer of a guarded `cmd` starts when the command ends;
  - apply prints `access check passed`, and the plan marks a changed
    firewall step. On a failed host, these lines print after the error;
  - a failed restore at the session end shows its error.
- Secrets:
  - a value built from another host's secret is masked, also in JSON;
  - a file that others can read and that holds another host's secret
    gets the load warning;
  - private key blocks are masked in file diffs, also in JSON;
  - a format placeholder such as `{}` or `%s` in a URL password no
    longer warns.
- `pkg`:
  - after a repo change or an `upgrade`, the plan fails on a package
    name that apt does not know or that only other packages provide.
    Before, apply failed at that step after earlier steps had changed
    the host;
  - the plan simulates earlier installs at the versions they planned.
- `cmd` runs `unless` as the step's `user`, in its `dir`. The plan
  shows the stderr of a failed `unless`.
- The error of a failed command shows the output up to its last 64 KiB,
  not its last 10 lines.
- A failed `then` on a loop step names the step, not an element.
- `service`: `enabled` fails on a runtime-enabled unit without
  `[Install]` and on a unit from an init script, and works on an
  indirect unit with its own install rules.
- `user` never creates `/nonexistent`.
- A file, dir, or link step with `absent: true` gets a plan note when
  an earlier package can create its path.
- The first hosts of a parallel stage start together.
- A passed health gate prints `health passed: <command>`.
- Messages: `notify` to a handler of another stage says so; `join` and
  `get` say why they fail; `secret generate` on a variable that nothing
  reads says what to do; `secret init` names the key it uses; and more
  errors name the fix.
- `winch doc` fixes for `cmd`, `service`, `user`, `firewall`, `secret
  init`, the secrets page, and handlers.
- Built with Go 1.27.4, which fixes GO-2026-6859 in `net/http`.

## v0.3.0

### Added

- `ssh_config` in `winch.yaml` names an SSH config file, relative to the
  project directory, such as the one that Lima or Vagrant writes. winch
  passes it to every `ssh` it runs, with `-F`, so ssh reads that file
  instead of `~/.ssh/config`. `~` in the path is not expanded.
- Load warnings:
  - a `source` file with an execute bit, in a step without `mode`: the
    host file gets `0644`. Set `mode: "0755"`;
  - a file in `/etc/cron.d/` or `/etc/cron.daily/` and the like whose
    name has a character other than letters, digits, `_`, and `-`, such
    as `backup.sh`: cron skips it. A file in `/etc/sudoers.d/` whose
    name has a `.` or ends in `~`: sudo skips it.
- Errors give a hint for habits from other tools:
  - a template that calls an expression function, such as `keys`;
  - a host pattern with `*` or `?`: host patterns have no wildcards;
  - a host pattern with `:`: join names with `,`;
  - a map literal in an expression: put it in parentheses, as in
    `map(list, ({key: .x}))`.

### Fixed

- A `firewall` step that enables `winch-firewall.service` also starts
  it. Before, the rules were loaded, but the unit was `inactive` until
  the next boot.
- The plan of a `pkg` step simulates with the earlier `pkg` steps of
  the run, in order. It no longer lists a package that an earlier step
  installs under "also install", and a package that one step installs
  and a later step removes counts as removed.
- The warning for a user that does not exist yet names the earlier
  `pkg` step whose package can create it, such as `postgres` from
  `postgresql`. It shows once per host and user, not again in each file
  step with that owner.
- Each pending certbot `deploy_hook` and `post_hook` has its own time
  limit. Before, a slow first hook left the next one less time.
- Apply no longer prints `download <url>` and `unpack into <dir>` lines
  of their own. The step line shows the download.
- `winch doc`:
  - the firewall page says that a port Docker publishes stays open, and
    to publish on `127.0.0.1` when only a local proxy reaches the
    container;
  - `user.password` names `openssl passwd -6`;
  - `sqlquote` says that it is for PostgreSQL, with `E` before the
    quote;
  - `facts.os.arch` lists `amd64` and `arm64`;
  - `winch exec --help` says that stdin is `/dev/null`;
  - the pages state more checks and warnings, such as the warning for
    a `then` command that restarts sshd after a change of its config.

## v0.2.1

### Fixed

- A run with a `repo` or `upgrade` step no longer breaks a host whose
  apt sources use `mirror+file:`, as Debian's cloud images do. In
  v0.2.0, every later session on such a host failed with
  `/var/lib/winch/apt/lists/auxfiles/... is not a directory or a regular
  file`. On a host that has this error, v0.2.1 works with no change.

## v0.2.0

### Breaking changes

- `secret generate` and `secret encrypt` take a path and write the
  `!secret` value there. `--host` and `--inventory` are gone. Use a path
  such as `hosts.db1.vars.x` or `inventories.prod.groups.all.vars.x`.
  `vars.x` now writes the default in `winch.yaml`, not the vars of group
  `all`. A value that exists is replaced. Without a path, the commands
  print the `!secret` value.
- `secret encrypt` on a terminal asks for the value twice, without echo.
- `plan`, `apply`, `run`, and `exec` fail on an inventory without hosts.
  Add a host, or use `validate`, which still passes.
- A `user` password that is not a crypt hash fails at load, not at the
  check. Write a hash, such as the output of `mkpasswd`.
- The plan fails in new cases:
  - a step that writes below the unpack directory of a later `download`:
    move the step after the `download`;
  - a changed step that notifies a `confirm_access` handler in a stage
    that `--stages` leaves out: add the stage to `--stages`;
  - a step that gives a path in a `dir` `recurse` tree another owner or
    group: use one owner, or leave the path out of the tree. A `file`
    with content and no `owner` counts as root, so it needs `owner` there;
  - a `pkg` or `upgrade` check after a changed `repo`, when the source
    cannot refresh. This failed at apply before: fix the source.
- A health gate whose command exits 126 or 127 fails at once, with no
  retry. Fix the command.
- The plan and JSON show the diff of `copy_from` and `stock`, so the
  content of those files reaches logs. A source with a secret shows
  `(secret)`.
- `upgrade` refreshes its own package index in `/var/lib/winch/apt` and
  leaves apt's index as it is. A later `pkg` install shows and runs its
  own refresh.
- The access check runs a program, so a sudo `noexec` rule fails it. Any
  change in the login user's `~/.ssh` gets the access check and rollback,
  not only `authorized_keys`.
- Unit files and drop-ins of `ssh.service` and `ssh.socket` count as
  sshd's config. They can give new warnings, and a restart of an active
  `ssh.socket` under the access check. A changed sshd file that no guarded
  reload tested goes back at the end of the session. Reload sshd in a
  `service` handler with `confirm_access: true`.
- The rollback of a dead timer no longer runs when a session starts. The
  plan shows it as `! rollback of an earlier run`, and apply runs it
  first. JSON has a `planned` event with the address `<host>:rollback`.
- The plan hash changed: a `--check` hash from v0.1.0 fails. Run `plan`
  again.
- A pending `then` from v0.1.0 no longer matches its step, except a `cmd`
  whose command has no final newline. The plan shows a note, apply removes
  the record, and the `then` does not run. Run the command yourself.
- SIGTERM and SIGHUP act as Ctrl-C in `plan`, `apply`, `run`, and `exec`.
- winch keeps the masked content of each file that holds a secret in
  `/var/lib/winch/masked/<project>/`, and a plan compares removed lines with
  it. Until a run has applied a step on such a file, its removed lines show as
  `(line hidden: may hold a secret)`, and so does a line that winch did not
  write.

### Added

- `winch secret decrypt` prints a secret.
- `winch exec --timeout`.
- `winch --help` and `winch doc` name the user guide.
- The plan warns when a step writes a secret where every user can read
  it, and when no guarded reload tests a change of sshd's config, also
  before a `reboot`, an `upgrade` of openssh-server, or a restart of
  `ssh.socket`.
- The plan notes a handler that the run does not reach.
- The plan lists the web server reload of certbot's nginx and apache
  plugins.

### Fixed

- The plan changes nothing outside `/var/lib/winch`, except what your
  `unless` commands do.
- The plan reads the host as the earlier steps of the run leave it: a
  `copy_from` source, a `stock` archive, paths through a link that a step
  moves, and packages from the sources of a changed `repo`.
- Secret masking: all text from the host passes the secret parts of its
  host, also outside a step. Text between two secrets stays visible. A
  plain check error shows in full beside a value from a secret.
- A plan diff no longer shows an old secret after a rotation, such as a
  multi-line secret that loses a line.
- A slow rollback no longer runs twice: a lock on its job tells a live timer
  from a dead one, whatever the time.
- A rollback of a switch between `ssh.service` and `ssh.socket` starts the
  stopped unit again. A guarded sshd reload saves the sshd config that
  other recipes changed.
- Pending records of a renamed recipe or handler show in the plan, and
  apply removes them.
- The plan shows the `user` and `dir` of a `cmd` step.

## v0.1.0

### Added

- Projects in YAML: hosts, groups, variables, recipes, and pipelines
  of steps, with templates and `!expr` expressions.
- `winch plan` shows the changes on each host and a plan hash.
  `winch apply` shows the plan, asks, and makes the changes.
  `--check <hash>` applies only the plan that a person reviewed. A
  second run changes nothing.
- Modules: `pkg`, `repo`, `upgrade`, `debconf`, `file`, `dir`, `link`,
  `download`, `line`, `service`, `unit`, `user`, `group`, `hostname`,
  `timezone`, `firewall`, `certbot`, `reboot`, `assert`, and `cmd`.
- Handlers that run after a change. Health gates: a host fails when
  its check does not pass after a stage.
- Lockout protection: after a `service` step with `confirm_access`, or
  a change of the login user's access, a second SSH connection checks
  the access. When the check fails, winch puts the old files back.
- Secrets encrypted with age in the project. `(secret)` replaces each
  secret value in the output.
- Many hosts in one run, with stages and host patterns.
- `winch run` plans and applies one module step.
- `winch exec` runs a shell command on hosts.
- `winch validate` checks the project without contacting a host.
- `winch fmt` formats the project files.
- `winch doc` shows the reference of every module and key.
- JSON output with `--json`, and color on a terminal.
- Servers: Debian 13, Ubuntu 24.04, and Ubuntu 26.04, on amd64 and
  arm64. Controllers: macOS and Linux, on amd64 and arm64.
