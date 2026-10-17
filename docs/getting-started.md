# Getting started

## Requirements

sshx requires a Unix system and OpenSSH clients available in `${PATH}`. Windows is
not yet supported. Release binaries target Linux AMD64 and macOS ARM64.

Both authentication methods read credentials from a provider. Direct gopass
needs an initialized store; Linux desktop providers need a session D-Bus and an
available Secret Service. [Provider setup](providers.md) covers both choices.

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

The [password guide](password-authentication.md#first-password-connection) starts
with storing a password, checking discovery, and connecting. The remote account
must accept password authentication. No key registration is needed.

## First public-key connection

The [key guide](agent/README.md) starts with an existing private key, loading it
into a provider, and registering it for one destination. The remote account must
already authorize the matching public key. The guide uses a temporary agent
that shuts down when SSH exits.

`sshx ssh` selects password authentication; `sshx agent run -- ssh` makes stored
keys available to ordinary OpenSSH. The two workflows remain separate.

## Next steps

[Configuration](configuration.md) describes defaults and CLI precedence.
[Troubleshooting](troubleshooting.md) separates discovery, authorization, provider,
and terminal failures. [Security](security.md) explains the trust boundaries.
