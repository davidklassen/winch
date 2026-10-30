ordered stages that apply steps to hosts

A pipeline is an ordered list of stages. Each stage applies its steps to
a set of hosts. It is a file in pipelines/, such as
pipelines/site.yaml, or a key in pipelines of winch.yaml. winch plan
site and winch apply site run it.

Most pipelines run the same steps on every host. Such a pipeline holds
the steps directly, and is one stage with the name of the pipeline. A
pipeline whose hosts have different roles, or that must finish on some
hosts before it starts on others, has stages. They run in order:

```yaml
# pipelines/site.yaml
stages:
  - name: base
    hosts: all
    parallelism: 1
    steps:
      - timezone:
          name: Etc/UTC
  - name: web
    hosts: web
    health:
      command: systemctl is-active nginx
      stable: 10
      timeout: 120
    steps:
      - recipe: nginx
```

```yaml
# winch.yaml
name: acme
inventories:
  production:
    hosts:
      web1.acme.com: {}
      web2.acme.com: {}
    groups:
      web:
        hosts: [web1.acme.com, web2.acme.com]
recipes:
  nginx:
    steps:
      - pkg:
          name: nginx
```

A stage starts when the previous stage finished on all its hosts.
Inside a stage, each host runs its steps in order, without waiting for
other hosts. A stage that matches no host is skipped. --stages runs
only some stages, and --hosts only some hosts.

A step in a stage can use a module directly. It cannot use template,
source, or the key of repo: those read the files of a recipe.

A failed host takes no part in later stages; the other hosts go on. A
new run is the resume: steps that already succeeded check as ok.
