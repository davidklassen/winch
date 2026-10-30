named values for hosts, groups, and recipes

Variables are named values that steps, templates, and expressions
read. Each host has its own value. A value comes from a default, the
inventory, the vars of a recipe step, or --set vars.<name>=<value>. A
later source replaces an earlier one: the default, then the vars of
groups, then of hosts, then the vars of the recipe step, then --set.
Maps and lists do not merge.

A default is declared once: in vars of winch.yaml, or in vars of the
recipe that owns it. A recipe's own defaults start with the recipe name
and _. A variable without a default needs no declaration; a read of it
is enough, and the variable is required where it is read. A variable
that may stay unset needs a default, such as relay_host: "". A variable
name has lowercase letters, digits, and _.

```yaml
# winch.yaml
name: demo
hosts:
  mail.acme.com:
    vars:
      relay_host: smtp.acme.com
  web1.acme.com: {}
groups:
  all:
    vars:
      admin_email: ops@acme.com
vars:
  domain: acme.com
  relay_host: ""
steps:
  - recipe: motd
    vars:
      motd_text: Managed by winch
recipes:
  motd:
    vars:
      motd_text: Welcome
    steps:
      - file:
          path: /etc/motd
          content: !tpl "{{ .vars.motd_text }} on {{ .vars.domain }}\n"
      - file:
          path: /etc/admin_email
          content: !tpl "{{ .vars.admin_email }}\n"
      - file:
          path: /etc/relay_host
          content: !tpl "{{ .vars.relay_host }}\n"
        when: !expr vars.relay_host != ""
```

A default can be a !secret, a template, or an expression. It sees
vars, host, and facts, but not match(). A cycle between defaults is an
error.

A read names the variable: vars.domain, .vars.domain, $.vars.domain,
or host.vars.domain. Any other read of the whole map, such as
keys(vars) or range .vars, is an error. A map variable holds data that
a step reads by key: vars.users[item]. host.vars holds the variables of
the host without the vars of a recipe step.

Variables have no types. A value keeps the type that YAML gives it.
--set parses its value as YAML; quote a value that YAML would change:
--set 'vars.php_version="8.0"'.
