# winch

winch configures Linux servers over SSH. You describe the desired state
in YAML. winch reads the current state, shows the difference, and
changes only what differs. It installs nothing on the servers in
advance.

winch is in early development and is not ready for use.

## Requirements

- Hosts: Debian with apt, on `linux/amd64` or `linux/arm64`, with
  passwordless `sudo` for the login user.
- Controller: Linux or macOS with the OpenSSH client.

## Build and test

```
make build              # bin/winch
make test               # unit tests
make test-integration   # integration tests in Debian VMs (QEMU)
```

The integration tests need QEMU. `make vm-image` downloads the Debian
cloud image.

## License

Apache License 2.0. See [LICENSE](LICENSE).
