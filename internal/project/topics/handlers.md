Steps that run after a step changed something.

handlers is a map in a recipe or in a stage. Each key is a handler name,
and its value is a list of steps. notify on a step names a handler.

```yaml
# winch.yaml
name: demo
hosts:
  web1.example.com: {}
steps:
  - recipe: nginx
  - file:
      path: /etc/nginx/conf.d/gzip.conf
      content: "gzip on;\n"
    notify: nginx.reload
recipes:
  nginx:
    steps:
      - pkg:
          name: nginx
    handlers:
      reload:
        - service:
            name: nginx
            reloaded: true
```

notify names a handler of the current recipe or stage, or
<recipe>.<handler> of another recipe. That recipe must run in the same
pipeline, on at least one host where the step runs. On a host where it
does not run, winch drops the notification.

- A handler name has lowercase letters, digits, and _.
- A handler runs at most once per recipe run on a host, and a handler
  of a stage at most once per stage run.
- A handler runs after the last step of its recipe. When its recipe
  already ran on that host, it runs at the end of the current stage. A
  handler of a stage runs after the last step of the stage, before the
  health gate.
- Handlers run in the order that the recipe or the stage declares them.
- A handler step cannot use notify or run a recipe. Only a handler step
  and winch run can use restarted and reloaded of service.

When a step notifies a handler, the helper records it on the host
before the step changes anything. The record goes when the handler
succeeds. When a run stops first, the handler stays pending, and it
runs the next time its recipe or stage runs on that host. The plan
shows a handler that will run with "!".
