# sshx

![Logo](assets/sshx-logo.svg ':size=200x200')

> SSH keys and passwords from encrypted storage

sshx connects OpenSSH to credentials stored in gopass or desktop Secret Service
providers, including GNOME Keyring, KeePassXC and KWallet. Existing SSH, SCP and
Git clients can use the native agent for keys; the password wrapper handles
password-based SSH and SCP. Credential storage stays with the chosen provider.

## Getting started

Start with [installation and requirements](getting-started.md), then choose an
authentication method:

| Method | First connection |
| --- | --- |
| Stored password | [Store a password and connect](password-authentication.md#first-password-connection) |
| SSH private key | [Store a key, register it, and connect](agent/README.md) |

The [provider guide](providers.md) contains loading instructions for gopass,
Secret Service and the KWallet schema variant. No registry JSON needs to be
written for a first key connection; `sshx agent register` creates the public record.

## After the first connection

- [Transfer files and run remote commands](password-authentication.md#ssh-connections)
- [Save command defaults](configuration.md)
- [Run a shared or systemd agent](agent/running.md)
- [Require signing approval or enter a key passphrase](agent/confirmation.md)
- [Understand destination restrictions](agent/destination-policies.md)
- [Import temporary keys with ssh-add](agent/ssh-add.md)
- [Enable constrained forwarding](agent/forwarding.md)
- [Diagnose connection and registration failures](troubleshooting.md)

## Reference and development

[Commands](reference/commands.md), [registration details](agent/registration.md),
[security boundaries](security.md), and the [agent protocol](reference/agent-protocol.md)
provide the full contracts. [Architecture](development/architecture.md),
[testing](development/testing.md), and [provider smoke tests](development/secret-service-smoke-tests.md)
cover implementation and validation. Source is available on
[GitHub](https://github.com/jfardello/sshx).
