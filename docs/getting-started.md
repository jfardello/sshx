# Getting started

## Requirements

sshx requires a Unix system and OpenSSH clients available in `${PATH}`. Windows is
not yet supported. Release binaries target Linux AMD64 and macOS ARM64.

Password connections require either direct gopass or, on Linux, a D-Bus session
bus and Secret Service provider. Key-based connections require a registered
software key or an optional volatile import. Provider availability and public-key
authorization on the destination are separate prerequisites.

## Installation

Binaries are available from [GitHub Releases](https://github.com/jfardello/sshx/releases/latest).
After the matching archive has been extracted, installation into a directory in
`PATH` can be performed with:

```sh
install -d -m 0755 "$HOME/.local/bin"
install -m 0755 sshx "$HOME/.local/bin/sshx"
sshx --help
```

The shell's `PATH` must include the installation directory. A source build requires
Go 1.26.6 or later and runs from the repository root:

```sh
go build -o sshx ./cmd/sshx
```

Secret Service access uses pure Go D-Bus support and does not require CGO.

## First password connection

A credential must already exist in a [configured provider](providers.md).
Discovery lists metadata without decrypting passwords:

```sh
sshx credentials list
sshx ssh alice@server.example
```

For direct gopass, an existing entry can be selected explicitly:

```sh
sshx ssh servers/alice@server.example --credential-backend gopass
```

The expected result is an authenticated SSH session. Server host-key verification
remains OpenSSH's responsibility. [Password authentication](password-authentication.md)
explains credential matching, SCP, and command arguments.

## First public-key connection

The [agent quick start](agent/README.md) covers storage and registration. Once an
enabled record and matching remote authorized_keys entry exist:

```sh
sshx agent run -- ssh alice@server.example
```

OpenSSH discovers registered keys through the agent; no local identity file is
required. Private material is retrieved by the agent.
`sshx agent run` owns the temporary agent's lifetime. Ordinary `sshx ssh` remains
the password wrapper and does not automatically register keys or start an agent.

## Next steps

[Configuration](configuration.md) describes defaults and CLI precedence.
[Troubleshooting](troubleshooting.md) separates discovery, authorization, provider,
and terminal failures. [Security](security.md) explains the trust boundaries.
