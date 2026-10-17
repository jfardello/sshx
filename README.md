# sshx

sshx connects OpenSSH to credentials stored in **gopass** or a desktop
**Secret Service** provider, including GNOME Keyring, KeePassXC and KWallet.

| Authentication | How it works | Start here |
| --- | --- | --- |
| Stored passwords | Supply a stored password to SSH or SCP through a controlling terminal | [First password connection](docs/password-authentication.md#first-password-connection) |
| SSH keys | Retrieve registered keys for local signing through a native SSH agent | [First key connection](docs/agent/README.md) |

sshx reads credentials from the provider. Its registration command creates a
local public-key record; private material remains in the credential store.

[Installation and requirements](docs/getting-started.md) cover release binaries,
source builds and provider prerequisites. [Provider setup](docs/providers.md)
includes password and private-key loading commands for gopass, Secret Service,
and the KWallet schema variant.

## Documentation

Read the [documentation site](https://jfardello.github.io/sshx/) or browse the
same [Markdown on GitHub](docs/README.md).

- [Configuration and CLI precedence](docs/configuration.md)
- [Key registration](docs/agent/registration.md)
- [Running the agent](docs/agent/running.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security boundaries](docs/security.md)
- [Command reference](docs/reference/commands.md)
- [Development and testing](docs/development/testing.md)
