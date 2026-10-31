# winch

Winch is a server configuration tool. It describes the desired state
of your servers in declarative YAML and provides commands to manage
that state.

winch has no release yet. The project format can still change.

## Example

`winch.yaml`:

```yaml
name: web

hosts:
  web1.example.com: {}

steps:
  - pkg:
      name: nginx
  - file:
      path: /var/www/html/index.html
      content: |
        <p>Hello from winch.</p>
  - service:
      name: nginx
      enabled: true
      running: true
```

`winch plan` shows the changes and changes nothing:

```
$ winch plan
web1.example.com
  web
    + pkg nginx
        refresh the package index
        install nginx
        other packages: known after the refresh
    + file /var/www/html/index.html
        create directory /var/www (owner root, group root, mode 0755)
        create directory /var/www/html (owner root, group root, mode 0755)
        owner root, group root, mode 0644
        @@ -0,0 +1,1 @@
        +<p>Hello from winch.</p>
    ~ service nginx
        nginx.service does not exist yet
        enable
        start

1 host: 1 to change, 0 unchanged, 0 unknown
plan 3fdb9990e92eae10
```

`winch apply` shows the same plan, asks, and makes the changes. A
second run finds nothing to do:

```
$ winch apply
1 host: 0 to change, 1 unchanged, 0 unknown
```

## Install

Build winch from source with Go 1.27 and make:

```
git clone https://github.com/davidklassen/winch
cd winch
make build    # bin/winch
```

`go install` builds a winch that cannot connect to servers: the
helper programs that winch sends to them are built by `make`.

## Requirements

- Servers: Debian 13, Ubuntu 24.04, or Ubuntu 26.04, on amd64 or
  arm64. The login user is root or has passwordless sudo.
- Your machine: Linux or macOS, with the OpenSSH client.

## Documentation

`winch doc` lists the topics: project files, values, running, and the
modules. `winch doc <topic>` shows one. `winch <command> --help` shows
the examples of each command.

## Try it on a VM

`examples/demo` puts a small web site on one VM. It needs QEMU.
`make vm` starts the VM `demo`. In a second terminal, run the
`export` line that `make vm` prints, then:

```
cd examples/demo
export WINCH_AGE_KEY=age.key
../../bin/winch plan site
../../bin/winch apply site
ssh demo "curl -s http://localhost/about"
```

`age.key` decrypts the demo secrets. Keep the key of a real project
out of the project directory.

## Development

```
make test               # unit tests
make test-integration   # integration tests in QEMU VMs
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
