# sshx

![Logo](assets/sshx-logo.svg ':size=200x200')

> SSH keys and passwords from encrypted storage

sshx connects OpenSSH to credentials stored in gopass or desktop Secret Service
providers such as KeePassXC, GNOME Keyring and KWallet. It supports password SSH/SCP
and a native SSH agent for software keys. Credential stores remain read-only from
sshx; provisioning uses the provider's management tools.

## Getting started

[Installation and first connection](getting-started.md) covers requirements and
setup. Linux AMD64 and macOS ARM64 binaries are available from
[GitHub Releases](https://github.com/jfardello/sshx/releases/latest).

An existing credential can be selected with `sshx ssh alice@server.example`.
For a new password entry, the following examples prompt interactively for the
secret. Secret Service requires an available provider on the session bus;
`auto` uses it on Linux and falls back to direct gopass only when unavailable.

<!-- tabs:start -->

#### **GNOME Keyring**

```sh
secret-tool store --label='alice@server.example' \
  service sshx sshx.target alice@server.example
sshx ssh alice@server.example
```

#### **KWallet**

The QtKeychain attributes make the password entry visible in the KWallet app:

```sh
secret-tool store --label='sshx/alice@server.example' \
  service sshx sshx.target alice@server.example \
  xdg:schema org.qt.keychain server sshx type plaintext user alice@server.example
sshx ssh alice@server.example
```

#### **gopass**

An initialized gopass store can hold the password at an explicit path:

```sh
gopass insert servers/alice@server.example
sshx ssh servers/alice@server.example --credential-backend gopass
```

Direct gopass and a gopass Secret Service bridge have different lookup contracts.
[Provider setup](providers.md) explains the distinction.

<!-- tabs:end -->

The password wrapper supplies the password through a controlling pseudo-terminal.
For keys, a [registered agent identity](agent/README.md) can be used with:

```sh
sshx agent run -- ssh alice@server.example
```

The agent retrieves private material for local signing. OpenSSH discovers its
registered public identities; private keys are not sent to SSH servers.

## Common tasks

- [Connect or transfer files with a stored password](password-authentication.md)
- [Configure gopass, KWallet, KeePassXC, or GNOME Keyring](providers.md)
- [Configure command defaults](configuration.md)
- [Make a first key-based connection](agent/README.md)
- [Run a shared or systemd agent](agent/running.md)
- [Import keys with ssh-add](agent/ssh-add.md)
- [Require local signing approval](agent/confirmation.md)
- [Restrict destinations](agent/destination-policies.md)
- [Enable constrained forwarding](agent/forwarding.md)
- [Diagnose connection failures](troubleshooting.md)

## Reference and development

[Commands](reference/commands.md), [security boundaries](security.md), and
[agent protocol](reference/agent-protocol.md) describe behavior and limits.
[Architecture](development/architecture.md), [testing](development/testing.md),
and [provider smoke tests](development/secret-service-smoke-tests.md) cover
implementation and validation. Source is available on
[GitHub](https://github.com/jfardello/sshx).
