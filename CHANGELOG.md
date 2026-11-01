# Changelog

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
