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

## Demo

`examples/demo` puts a small web site on one host, `demo`. `make vm`
starts a VM with that name. In a second terminal, run the `export` line
that `make vm` prints, then:

```
cd examples/demo
export WINCH_AGE_KEY=age.key
../../bin/winch plan site
../../bin/winch apply site
ssh demo "curl -s http://localhost/about"
```

`age.key` decrypts the demo secrets. It is for the demo only: keep the
age identity of a real project out of the project directory.

The VMs have 1 GB of memory and an 8 GB disk. `make vm MEM=4G DISK=16G`
makes them bigger. `FORWARD=udp:1194,tcp:8080` forwards more ports of
each VM. `make vm` prints the host port of each forward.

## License

Apache License 2.0. See [LICENSE](LICENSE).
