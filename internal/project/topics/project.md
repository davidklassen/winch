project files and directories

A project is a directory with a winch.yaml file and the inventories,
pipelines, and recipes that it uses. winch reads the project in the
current directory:

    winch.yaml               the project file
    inventories/
      production.yaml        an inventory: hosts and groups
      test.yaml
    pipelines/
      site.yaml              a pipeline: stages and steps
    recipes/
      nginx/
        recipe.yaml          a recipe: variables, steps, and handlers
        templates/site.tmpl  the templates of the recipe
        files/tls.conf       the files of the recipe

The project file is winch.yaml or winch.yml. An inventory, a pipeline,
and a recipe file can end in .yaml or .yml too. The name of an inventory
or a pipeline is its file name without the extension. Two files for one
name are an error.

An inventory, a pipeline, or a recipe can also be a key in winch.yaml,
under inventories, pipelines, or recipes. The value of the key is the
content of the file. A name in both places is an error.

hosts and groups at the top of winch.yaml are the only inventory of
the project, with any number of pipelines. steps and handlers at the
top of winch.yaml are the only pipeline of the project. Then winch plan
and winch apply take no pipeline name.

A minimal project to copy:

```yaml
# winch.yaml
name: demo
```

```yaml
# inventories/test.yaml
hosts:
  web1.example.com:
    address: 192.0.2.10
groups:
  all:
    user: admin
```

```yaml
# pipelines/site.yaml
steps:
  - pkg:
      name: nginx
```

Check it, show the changes, then make them:

    winch validate
    winch plan site
    winch apply site

winch connects with the OpenSSH client and its SSH config. The login
user is root, or has passwordless sudo. A host needs nothing else
installed: winch sends its helper binary to /var/lib/winch on the host.

All files are YAML 1.2. Only true and false are booleans: yes, no, on,
and off are strings. File modes are strings: mode: "0644". Unknown keys
and duplicate keys are errors. Anchors and aliases work; merge keys
(<<) do not. winch fmt fixes the indentation and the step key order.
