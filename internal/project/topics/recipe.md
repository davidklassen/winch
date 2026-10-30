A reusable unit: variables, requirements, steps, and handlers.

A recipe is a directory in recipes/ with a recipe.yaml, and optional
templates/ and files/ directories. Or it is a key in recipes of
winch.yaml, without templates or files. A step runs a recipe with
recipe: <name>.

```yaml
# recipes/nginx/recipe.yaml
require:
  - !expr facts.os.id in ["debian", "ubuntu"]
vars:
  nginx_port: 80
steps:
  - pkg:
      name: nginx
  - name: Configure the site
    file:
      path: /etc/nginx/sites-enabled/default
      template: site.tmpl
      validate: nginx -t
    notify: reload
  - service:
      name: nginx
      running: true
      enabled: true
handlers:
  reload:
    - service:
        name: nginx
        reloaded: true
```

```yaml
# winch.yaml
name: acme
hosts:
  web1.acme.com: {}
steps:
  - recipe: nginx
    vars:
      nginx_port: 8080
```

```text
# recipes/nginx/templates/site.tmpl
server {
    listen {{ .vars.nginx_port }};
}
```

template reads from the templates/ directory of the recipe, and source
from files/. Paths can name subdirectories. A template file uses the
language of !tpl; run winch doc values.

A recipe name has lowercase letters, digits, and _. It can be the name
of a module. winch loads every recipe for every command, also a recipe
that no pipeline uses.

A recipe runs at most once per host in a run. Two stages can run the
same recipe when their hosts do not overlap. A recipe step has only
name, recipe, vars, and when. A recipe cannot run another recipe.
