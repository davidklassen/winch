text with values filled in (!tpl)

A template is text in which winch fills in the values of each host.
The !tpl tag marks a template, a Go text/template. It builds text, such
as a path or a line. The template files of a recipe use the same
language.

A template reads these names with a leading dot:

    .vars   the variables of the host, with the vars of the recipe step
    .facts  the facts of the host; run winch doc facts
    .host   name, short, address, groups, and vars of the host
    .item   the current element in a step with loop

Any module argument can be a template or an expression, and so can
then.

```yaml
# winch.yaml
name: demo
hosts:
  web1.acme.com: {}
vars:
  sites: [blog, shop]
  admins: [ann, bob]
steps:
  - name: Write the sites
    file:
      path: !tpl /etc/nginx/sites-enabled/{{ .item }}.conf
      content: !tpl "server_name {{ .item }}.{{ .host.short }};\n"
    loop: !expr vars.sites
  - name: Allow the admins
    file:
      path: /etc/ssh/sshd_config.d/admins.conf
      content: !tpl "AllowUsers{{ range .vars.admins }} {{ . }}{{ end }}\n"
```

Inside range, "." is the element; $.vars reads the variables. A
template that reads a missing map key fails; use get for a key that
may be missing. A template that prints a null value fails.

A function takes its arguments after its name, separated by spaces:
{{ join .vars.names ", " }}. Templates also have the actions of Go's
text/template: if, else, range, with, define, template, block, break,
and continue, and the variables $x := value. A value goes into a
command as it is; quote a value that must stay one word.

Quote a YAML value that starts with a quote, [, {, &, *, or !, or that
contains ": " or " #". A template that starts with {{ needs quotes.

winch evaluates templates on the controller, during the plan. They
cannot read the result of a step. winch checks each one when it loads
the project: an unknown name or a syntax error is an error. An error
while winch evaluates one for a host fails that host; the other hosts
go on.
