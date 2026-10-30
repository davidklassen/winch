The read-only values about a host.

Facts are a fixed set. Expressions read them as facts.os.id, and
templates as {{ .facts.os.id }}. A read of an unknown fact is an
error. winch reads the facts once per host per run, before the first
step, and again after a reboot. They describe the host before the run.

```yaml
# winch.yaml
name: demo
hosts:
  web1.example.com: {}
steps:
  - recipe: base
recipes:
  base:
    require:
      - !expr facts.os.id == "debian" and facts.os.version == "13"
    steps:
      - reboot:
          if_required: true
        when: !expr facts.reboot_required
```
