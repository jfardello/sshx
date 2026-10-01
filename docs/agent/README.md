# Key authentication quick start

The native agent serves software keys to OpenSSH, Git, SCP and other clients
using `SSH_AUTH_SOCK`. Registration associates an existing private-key entry with
its public key and policy. It does not generate keys or install authorized_keys.

## Prerequisites

The destination must already authorize the public key. Its host key must be
verified through OpenSSH's normal trust process. A direct-gopass example requires
an existing multiline private-key entry at `ssh-keys/work-key`, a matching public
file at `~/.ssh/id_ed25519.pub`, and noninteractive GPG decryption.

Encrypted OpenSSH payloads additionally require a [local prompt helper](confirmation.md).
Provider unlocking is separate from that payload's passphrase.

> [!WARNING]
> **Beware** of changes regarding registration, sshx in under heavy development, current roadmap includes automating agent registration and key management.

## Register an existing key

The following file belongs at `~/.config/sshx/agent.json`, or under the absolute
`XDG_CONFIG_HOME`. The public-key placeholder must contain the algorithm and
base64 fields from the matching `.pub` file, without its comment:

```json
{
  "version": 2,
  "keys": [{
    "id": "work-key",
    "public_key": "ssh-ed25519 <PUBLIC_KEY_BASE64>",
    "enabled": true,
    "policy": "unrestricted-local",
    "backend": "gopass",
    "reference": "ssh-keys/work-key"
  }]
}
```

The registry requires owner-only permissions, a private parent directory, and
trusted non-symlink ancestors. The standard home-directory layout can be prepared
with `install -d -m 0700 "$HOME/.config/sshx"`; the completed file should have mode
`0600`. A nondefault `XDG_CONFIG_HOME` requires the corresponding path instead.

`unrestricted-local` permits arbitrary signing by local socket holders. It is
appropriate only within that trust boundary. [Destination policies](destination-policies.md)
provide pinned host/user restrictions and are mandatory for recognized forwarding.
[Registration](registration.md) covers the full schema and Secret Service keys.

## Connect with a command-scoped agent

```sh
sshx agent run -- ssh alice@server.example
```

The agent retrieves the private key, checks that it matches the registered public
key, and signs locally. When SSH exits, the temporary agent shuts down. No private
key is copied to the destination. OpenSSH discovers registered identities through
the agent; the local `.pub` file is only needed when explicitly selecting a key.
Client configuration such as `IdentitiesOnly yes` can restrict this discovery;
[troubleshooting](../troubleshooting.md#agent-refusal) shows explicit selection.

## Other operating modes

[Running the agent](running.md) covers a shared socket and systemd activation.
[ssh-add compatibility](ssh-add.md) supports separately enabled memory-only
imports. Such imports neither create registry entries nor write backend secrets.
[Confirmation](confirmation.md), [caching](caching.md), and
[forwarding](forwarding.md) are independent opt-in features.

An empty registry is valid. `ssh-add -l` cannot prove backend readiness and may
hide destination-constrained identities until a verified binding exists.
