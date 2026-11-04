# Changelog

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
