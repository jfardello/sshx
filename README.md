# sshx

sshx connects OpenSSH to credentials stored in **gopass** or a desktop
**Secret Service** provider, including KeePassXC, GNOME Keyring and KWallet.

Two authentication modes are available:

- **Password SSH/SCP:** a stored password is supplied through a controlling PTY,
  without `sshpass`, password arguments or password environment variables.
- **Native SSH agent:** registered software keys are retrieved for local signing,
  with optional confirmation, destination restrictions and constrained forwarding.

Credential stores remain read-only from sshx. Key registration and volatile
`ssh-add` imports are separate operations.

## Installation

Release binaries are available for Linux AMD64 and macOS ARM64 from
[GitHub Releases](https://github.com/jfardello/sshx/releases/latest).
OpenSSH clients must be available in `PATH`; Windows is not supported.

After extraction, the binary can be installed with:

```sh
install -d -m 0755 "$HOME/.local/bin"
install -m 0755 sshx "$HOME/.local/bin/sshx"
```

The installation directory must be in the shell's `PATH`. A source build requires
Go 1.26.6 or later:

```sh
go build -o sshx ./cmd/sshx
```

[Getting started](docs/getting-started.md) covers provider prerequisites and setup.

## Password authentication

An existing stored credential can be discovered and selected with:

```sh
sshx credentials list
sshx ssh alice@server.example
sshx scp alice@server.example file.txt :/tmp/
```

Direct gopass can be selected explicitly:

```sh
sshx ssh servers/alice@server.example --credential-backend gopass
```

[Password authentication](docs/password-authentication.md) explains matching,
options and file transfers. [Provider setup](docs/providers.md) includes desktop
integration and the KWallet storage schema.

## Key authentication

Once a matching key is [registered](docs/agent/README.md) and authorized on the
destination, a command-scoped agent can serve OpenSSH:

```sh
sshx agent run -- ssh alice@server.example
```

OpenSSH discovers registered keys through the agent; no local identity file is
required. The agent shuts down when SSH exits.
[Agent operation](docs/agent/running.md) covers shared sockets and systemd.

## Documentation

The documentation is available as a [Docsify site](https://jfardello.github.io/sshx/)
and as [Markdown on GitHub](docs/README.md).

- [Getting started](docs/getting-started.md)
- [Configuration and CLI precedence](docs/configuration.md)
- [Providers](docs/providers.md)
- [Native agent](docs/agent/README.md)
- [ssh-add compatibility](docs/agent/ssh-add.md)
- [Destination policies](docs/agent/destination-policies.md)
- [Forwarding](docs/agent/forwarding.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security](docs/security.md)
- [Command reference](docs/reference/commands.md)
- [Development and testing](docs/development/testing.md)
