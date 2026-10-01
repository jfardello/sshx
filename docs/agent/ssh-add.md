# Limited ssh-add compatibility

Mutations are disabled by default. They can be enabled explicitly on the agent process:

```sh
sshx agent start --foreground --allow-key-mutations
# In another terminal:
eval "$(sshx agent env)"
ssh-add ~/.ssh/id_ed25519
ssh-add -l
```

For a temporary command environment:

```sh
sshx agent run --allow-key-mutations -- sh
```

For systemd, `--allow-key-mutations` belongs in the service's existing `ExecStart`
command alongside its socket-activation and helper flags. A unit reload and
service restart are required. Each process needs its own state file; if another agent already owns
the default file, a separate absolute `--state-file` path is required for the temporary agent. A separate state file represents a separate lock and suppression domain.

| Command | Behavior |
| --- | --- |
| `ssh-add -l` / `-L` | List visible public identities; destination filtering still applies |
| `ssh-add key` | Import a supported software key into process memory |
| `ssh-add -d key` | Unload an imported key, or persistently suppress an enrolled key |
| `ssh-add -D` | Unload all imported keys and persistently suppress all enrollments, including later enrollments |
| `ssh-add -t 60 key` | Expire the import 60 seconds after successful addition |
| `ssh-add -c key` | Require the configured local prompt helper to approve each signing request |
| `ssh-add -H known_hosts -h alice@server.example key` | Enforce supported raw-host-key destination constraints |
| `ssh-add -x` / `-X` | Lock/unlock the agent, independently of credential-provider locking |

Ed25519, RSA (2048–8192 bits, SHA-2 signing), and ECDSA P-256/P-384/P-521
are supported. ssh-add decrypts its local file before sending the private key.
Imports never write to gopass, Secret Service, or agent.json. Lazy backend
identities keep their existing retrieval behavior. Removing an identity never
deletes its backend secret or revokes a remote authorized_keys entry.

Imports are memory-only and disappear on shutdown, removal, expiry, or an observed
registry change/recovery. Registry changes discard imports conservatively so a
new enrollment cannot be shadowed by weaker imported policy. Duplicate imports
and collisions with any enrollment (even disabled or suppressed) are rejected;
there is no implicit replacement or policy weakening. Changing an imported key's constraints requires removal followed by a new import. Comments are limited to
128 bytes without control characters, and the combined identity limit is 256.

Lifetime is an authorization deadline, checked before signing and before returning
a signature, independently of `--cache-ttl`. Confirmation is fresh for each use;
`-c` fails at import when no helper is configured. A configured helper may still
deny or fail when called. Imported keys remain in memory while locked, but cannot
sign. Expiry continues while locked. Owned buffers are cleared on unload when no
operation still borrows them; Go and cryptographic implementation copies prevent
any guarantee of secure erasure.

Destination constraints require verified session binding and the supported
[destination policy](destination-policies.md). Unbound listing may hide a
constrained identity. A compatible OpenSSH client binds its session before listing
keys, so it can discover an authorized identity during authentication.
[Explicit identity selection](../troubleshooting.md#agent-refusal) can help diagnose
client configuration or identity-selection problems.
[Constrained forwarding](forwarding.md) is separately opt-in; remote
mutation and lock requests always fail. Certificates, CA constraints, FIDO, smartcards,
max-sign/tag-3 constraints, duplicate constraints, and unknown extensions are
rejected. Malformed or unsupported adds publish no identity and change no existing
key. Private ADD fields are parsed by sshx before any upstream ADD dispatcher.

## Persistent lock and removal state

The default ledger is `$XDG_STATE_HOME/sshx/agent-state.json`, falling back to
`~/.local/state/sshx/agent-state.json`. `--state-file /absolute/path` overrides it.
Its directory must be private (0700); files are owner-only (0600), checked for
ownership, symlinks and hard links, and protected by an exclusive companion lock.
Only one live agent may own a ledger. Updates use an atomic replacement with
file/directory synchronization. Invalid, untrusted, or busy state fails startup;
a failed update fails closed for that process. This canonical, machine-managed file must not be edited manually.

The ledger stores public-key suppression and a salted PBKDF2-SHA256 lock verifier,
never imported private keys or plaintext passwords. Lock passwords are 1–1024
bytes; verification uses 100,000 rounds and constant-time comparison. Failed
unlocks impose a persistent exponential cooldown from 1 to 32 seconds. During
cooldown even the correct password is refused; another attempt should follow the cooldown.

Restarting cannot unlock the agent or restore suppressed keys. Existing state is
honored even if `--allow-key-mutations` is removed (that also disables wire
unlocking). Lock/unlock invalidates backend signer caches and outstanding signing
requests, but preserves connection bindings and their poisoned/forwarded status.

To explicitly reactivate enrollments and clear a forgotten agent lock, the agent must first be stopped, then its ledger reset:

```sh
sshx agent stop --systemd       # or terminate the foreground agent
sshx agent reset-state         # the same --state-file override applies, if configured
# The agent can then be started with its usual command or systemd units.
```

Reset refuses a ledger held by a running process. This is an intentional owner
administrative action, not a credential-provider unlock. It clears all persisted
suppression and agent locking together. Host-clock changes can affect persisted
unlock cooldowns; imported lifetimes use the process monotonic clock.
