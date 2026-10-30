Variables, templates, and expressions.

A variable is a named value. Each host has its own value. A value comes
from a default, the inventory, the vars of a recipe step, or --set
vars.<name>=<value>. A later source replaces an earlier one: the
default, then the vars of groups, then of hosts, then the vars of the
recipe step, then --set. Maps and lists do not merge.

A default is declared once: in vars of winch.yaml, or in vars of the
recipe that owns it. A recipe's own defaults start with the recipe name
and _. A variable without a default is required where it is read. A
variable that may stay unset needs a default, such as relay_host: "".
A variable name has lowercase letters, digits, and _.

Two tags mark values that winch computes. A value without a tag is
plain text.

- !tpl is a Go text/template. It builds text, such as a path or a line.
  Template files of a recipe use the same language.
- !expr is an expr expression (expr-lang.org). Its result keeps its
  type: a list, a number, a boolean, a map, or a string.

Both read the same names. A template starts a name with a dot, and an
expression does not:

    vars      the variables of the host, with the vars of the recipe step
    facts     the facts of the host; run winch doc facts
    host      name, short, address, groups, and vars of the host
    item      the current element in a step with loop
    match(p)  the hosts that match the host pattern p, with the fields
              of host; expressions only

```yaml
# winch.yaml
name: demo
hosts:
  mail.acme.com: {}
  web1.acme.com: {}
vars:
  mail_server: false
  domain: acme.com
  admins: [ann, bob]
  mailname: !expr 'vars.mail_server ? vars.domain : host.name'
steps:
  - name: Set the mail name
    file:
      path: /etc/mailname
      content: !tpl "{{ .vars.mailname }}\n"
    when: !expr vars.mail_server
  - name: Add the admins
    user:
      name: !tpl "{{ .item }}"
      groups: [sudo]
    loop: !expr sort(vars.admins)
  - name: List the other hosts
    file:
      path: /etc/peers
      content: !expr 'join(map(filter(match("all"), .name != host.name), .address), "\n") + "\n"'
```

A read names the variable: vars.domain, .vars.domain, $.vars.domain,
or host.vars.domain. Any other read of the whole map, such as
keys(vars) or range .vars, is an error. A map variable holds data that
a step reads by key: vars.users[item].

Inside range in a template, "." is the element; $.vars reads the
variables. A template that reads a missing map key fails; use get for a
key that may be missing. In an expression, a missing map key is nil.

Quote a value that starts with a quote, [, {, &, *, or !, or that
contains ": " or " #". A template that starts with {{ needs quotes.

Expressions and templates run on the controller, during the plan. They
cannot read the result of a step. winch checks each one when it loads
the project: an unknown name or a syntax error is an error. An error
while winch evaluates one for a host fails that host; the other hosts
go on. $env and now() are errors in every expression.

expr operators: + - * / % ** == != < > <= >=, and or not (or && || !),
in, contains, startsWith, endsWith, matches (a regular expression),
c ? a : b, a ?? b, [] and ?. to read, x[i:j], 1..3, and the pipe |:
vars.name | lower(). Run winch doc functions for the functions.
