The keys of every step.

A step is a map. It has one module key, such as pkg or file, with the
arguments of the module as a map. Or it has recipe with the name of a
recipe. Run winch doc <module> for the arguments of a module.

```yaml
# winch.yaml
name: demo
hosts:
  web1.example.com: {}
vars:
  sites: [blog, shop]
steps:
  - name: Install nginx
    pkg:
      name: nginx
  - name: Write the sites
    file:
      path: !tpl /etc/nginx/sites-enabled/{{ .item }}.conf
      content: !tpl "# {{ .item }}\n"
    when: !expr len(vars.sites) > 0
    loop: !expr vars.sites
    then: nginx -t
    notify: reload
handlers:
  reload:
    - service:
        name: nginx
        reloaded: true
```

On each host, winch evaluates when. When it is false, winch skips the
step. Then winch evaluates loop, and the arguments for each element.
The helper checks the step on the host, and apply changes what differs.

A step that runs a command counts as changed: a cmd, and a service with
restarted or reloaded. When a step fails, its host stops; other hosts
go on.

winch fmt puts the step keys in this order: name, the module or
recipe, vars, when, loop, then, confirm_access, notify.
