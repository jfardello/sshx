# Key authentication quick start

This guide stores an existing key in a provider, registers it for
`alice@server.example`, and starts an SSH connection with a temporary agent.
[Installation](../getting-started.md#installation) is the only sshx setup required.

## Prerequisites

The examples use an existing `~/.ssh/id_ed25519` private key and its matching
`~/.ssh/id_ed25519.pub`. Other supported key formats are listed in the
[registration reference](registration.md#validation-and-lifetime).

The server must already authorize the public key in the remote account's
`~/.ssh/authorized_keys`. The server's host key must also have been verified
through a trusted channel and saved in the local `~/.ssh/known_hosts` through
OpenSSH's normal trust process. A successful ordinary `ssh alice@server.example`
connection is a useful prerequisite check. Merely collecting a key with
`ssh-keyscan` does not verify its authenticity.

The public key in `authorized_keys` identifies the account's key; the host key
in `known_hosts` identifies the server. Registration uses both roles separately.

## Store the private key

Choose one provider and follow its loading instructions:

- [Direct gopass](../providers.md#gopass-private-keys)
- [Secret Service, including GNOME Keyring](../providers.md#secret-service-private-keys)
- [KWallet schema variant](../providers.md#kwallet-private-keys)

Those examples store the complete private-key file. Provider unlocking must be
completed before registration; the provider guide explains the steps for each
backend.

If the SSH key itself has a passphrase, registration asks for it through a
hidden terminal prompt. Later signing needs a configured
[passphrase helper](confirmation.md#enable-and-run). This key passphrase is
separate from the GPG passphrase or wallet password protecting the provider.

## Register an existing key

Run the command matching the selected provider. These alternatives create the
same local ID, `work-key`; only one is needed.

For direct gopass:

```sh
sshx agent register work-key \
  --backend gopass --reference ssh-keys/work-key \
  --destination alice@server.example --enable
```

For Secret Service or the KWallet variant:

```sh
sshx agent register work-key \
  --backend secret-service --reference work-key --collection default \
  --destination alice@server.example --enable
```

Success prints the key fingerprint and `Enabled: true`. Registration creates the
local public registry with private file permissions. It reads the existing
provider entry and trusted host pin; it does not upload keys or change remote
`authorized_keys`. Neither hand-written JSON nor `ssh-add` is required.

The destination rule permits signing for the pinned server and exact username.
[Destination policies](destination-policies.md) cover other users, ports, host
rotation and forwarding. [Registration details](registration.md) explain
replacement, confirmation, and validation errors.

## Connect with a command-scoped agent

```sh
sshx agent run -- ssh alice@server.example
```

The expected result is an authenticated SSH session. OpenSSH discovers registered
keys through the agent, which retrieves the private material and signs locally.
The agent shuts down when SSH exits.

A host-restricted identity can be hidden from an ordinary `ssh-add -l` until a
compatible SSH client binds the agent connection to the server. Listing alone
does not prove key retrieval or signing. If authentication fails,
[agent troubleshooting](../troubleshooting.md#agent-refusal) shows how to select
the public key explicitly and disable password fallback during diagnosis.

## Other operating modes

[Running the agent](running.md) covers shared sockets and systemd activation.
[ssh-add compatibility](ssh-add.md) describes temporary imports and locking.
[Confirmation](confirmation.md), [caching](caching.md), and
[forwarding](forwarding.md) are optional next steps.
