# Key registration

Registration associates a public key with an exact existing credential-store entry.
It does not generate keys, install remote authorized_keys, or import private material.
The native agent reads this registry; password-based SSH/SCP commands do not.

## Register an existing provider key

```sh
sshx agent register work-key --backend gopass --reference ssh-keys/work-key \
  --destination alice@server.example --enable

sshx agent register wallet-key --backend secret-service \
  --reference work-key-001 --collection default --unrestricted-local
```

The key must already exist in the provider. Backend and reference are explicit;
Secret Service also requires a collection alias. Neither password-command config
nor agent lifecycle defaults select registration's backend or policy.

Choose `--unrestricted-local` or one or more `--destination user@host` values,
never both. Records are disabled unless `--enable` is supplied. `--confirm` requires
per-request approval when the running agent signs; `--comment` sets public display
metadata. `--replace` permits changes to the requested ID only and is not a merge:
all requested metadata/policy values define the replacement, including disabled
and no-confirmation defaults. Successful output contains only the key fingerprint
and enabled state.

Destination registration reads only `--known-hosts` (default `~/.ssh/known_hosts`),
limited to 1 MiB. Existing pins must already be trusted; registration does not fetch
host keys, resolve aliases through DNS, or read system known-hosts files. Hashed
entries and multiple supported plain keys are accepted. Missing pins, matching
revocations or unsupported/certificate keys, malformed input, and CA-only trust
fail closed. Up to 64 direct edges and 16 pins per destination are supported.

```sh
sshx agent register work-key --backend gopass --reference ssh-keys/work-key \
  --destination 'alice@[2001:db8::1]' --port 2222 \
  --known-hosts /home/alice/.ssh/known_hosts --enable
```

Every destination needs an exact nonempty username. Embedded ports, wildcards,
URIs, whitespace, and IPv6 zone identifiers are rejected. One `--port` applies to
all destinations. The example looks up `[2001:db8::1]:2222` but stores an unbracketed
host label. Host labels and ports are lookup metadata: signing authorization binds
host keys and username, **not a TCP port**.

Provider reads are noninteractive; unlock the wallet or GPG keyring separately.
An encrypted OpenSSH private key then requires its own passphrase through a
no-echo controlling-terminal prompt, not stdin, CLI arguments, or the agent helper.
Without a controlling terminal, registration fails with an actionable error.
The prompt accepts up to 4096 bytes; erase/backspace and kill-line edit hidden
input. Interrupt, quit, and suspend controls cancel registration rather than
leaving a suspended process with echo disabled. Terminal settings are restored.
Provider resources and owned secret buffers are released before registry locking.
A full private/public pair is validated before any public record is published.

## Registry

The registry loader reads `$XDG_CONFIG_HOME/sshx/agent.json` when
`XDG_CONFIG_HOME` is absolute, otherwise `~/.config/sshx/agent.json`.
A missing file means no registered keys. Existing password commands do not read
this file. Only an explicit registration operation writes the registry; provider
credentials are never created or modified by registration.

The file must be a regular file owned by the current user, with no group/other
permissions (`0600` is recommended). Its ancestor directories must be owned by
the current user or the filesystem root owner and must not be writable by other
users. Root-owned sticky ancestors such as `/tmp` are permitted above the private
parent directory. Symlinks, including symlinked ancestors, are rejected.
An owner-only directory (`0700`) is required. Updates should be saved by
renaming a complete replacement file. The maximum registry size is 1 MiB.

An empty registry is:

```json
{"version": 2, "keys": []}
```

The public-key placeholder below represents the algorithm and base64 fields
from the corresponding `.pub` file, without its trailing comment:

```json
{
  "version": 2,
  "keys": [
    {
      "id": "work-key",
      "public_key": "ssh-ed25519 <base64-public-key>",
      "enabled": false,
      "policy": "unrestricted-local",
      "comment": "Work key",
      "backend": "gopass",
      "reference": "ssh-keys/work-key"
    }
  ]
}
```

Registration means associating a public key with one exact existing private-key
entry. It does not generate keys or install `authorized_keys`. `enabled` defaults
to false. Version 1 supports `unrestricted-local`; version 2 also supports
`destination-constrained` with explicit pins and username rules. See
[destination policy](destination-policies.md) for the schema and live
update behavior. Unknown policy/schema fields are rejected. Private keys, passwords and passphrases must not be stored in the registry.

| Field | Contract |
| --- | --- |
| `version` | `1` or `2`; constrained records require `2` |
| `id` | Unique local identifier; letters, digits, `.`, `_`, `-`; maximum 128 characters |
| `public_key` | One canonical SSH public key, without comments or authorized_keys options |
| `enabled` | Boolean; omitted means false |
| `confirm` | Boolean; omitted means false; true requires version 2 and local per-request approval |
| `policy` | Explicitly `unrestricted-local` or `destination-constrained` |
| `destinations` | Required for constrained records; forbidden for unrestricted records |
| `comment` | Optional display label, at most 128 bytes, without control characters |
| `backend` | Exactly `gopass` or `secret-service`; no automatic fallback |
| `reference` | Exact logical gopass path, or stable Secret Service `sshx.id` |
| `collection` | Required Secret Service collection **alias**; omitted for gopass |

Secret Service IDs and aliases use the same syntax as registry IDs. Collection
labels and transient D-Bus object paths are not accepted as persistent references.
Gopass paths must be relative, normalized paths without traversal, control
characters, backslashes, or components starting with `-`.

Duplicate public keys are accepted only when backend, reference, collection,
enabled state, confirmation requirement, and policy are identical. Such aliases collapse to the first
record's identity and comment. Conflicting duplicates reject the whole registry.
Unknown, duplicate, case-altered, or null JSON fields also reject the registry.

## Writer and live-reload behavior

The internal registry writer accepts public records only. Registration finishes
provider access, private/public-key validation, and passphrase prompts before
entering the update transaction.
`agent.ValidateKeyMaterial` shares the signing parser's format, algorithm, size,
and encrypted OpenSSH KDF limits without prompting or modifying borrowed buffers.
An envelope public key alone is not sufficient validation.

An identical decoded record is a no-op, including with replacement requested.
Default/empty optional fields and JSON whitespace do not force a rewrite; destination
edge and pin order remain significant. Changing an existing ID requires explicit
replacement. Only that ID is replaced, in its existing position; new IDs append.
Unrelated records and supported aliases survive, and conflicting aliases reject
the complete transaction. Initially invalid registries are never repaired implicitly.
Actual updates emit version 2; an identical version-1 record remains a no-op.

Writers publish complete validated JSON through the shared secure-update operation.
They reject symlinks, multiply linked targets, and nonprivate registry files; use a
stable sibling lock that fails immediately when busy; and detect external changes
before replacement. New directories use `0700` and replacement files use `0600`.
A post-replacement sync failure reports publication with uncertain durability,
not rollback. JSON formatting need not survive.

Effective registry changes invalidate cached signers and pending authorization
generations and retire volatile imports. Persisted lock/suppression state remains
intact. No-op, formatting-only, and runtime-equivalent alias changes must not
manufacture an effective change. Registration does not install remote keys,
modify provider secrets, or reset agent state.

## Backend contracts

Identity discovery reads public registry data only: no provider calls, secret
reads, unlock requests, or prompts. Internal backend metadata searches use a noninteractive default and exact
attribute matching for Secret Service. Registration uses an exact reference rather
than discovery. Password commands explicitly retain their interactive behavior.

A Secret Service key item must carry these nonsecret string attributes:

```text
service=sshx
sshx.type=ssh-key
sshx.schema=1
sshx.id=<stable-item-id>
```

For example, its registry reference is:

```json
{
  "backend": "secret-service",
  "reference": "work-key-001",
  "collection": "default"
}
```

These fields replace the backend/reference fields in the complete record above.
The adapter resolves the collection alias and stable ID on every read. It pins
calls and session cleanup to the provider's unique bus owner, rejects ambiguous
IDs, rechecks attributes and locks, and rejects results after owner replacement.
The next operation resolves the new owner afresh. Labels and backend public-key
attributes never override the registered public key. Existing password items are
not automatically treated as key items. Plain Secret Service transport continues
to trust the session bus and provider.

Direct gopass key reads use:

```text
gopass show --noparsing --unsafe --nofuzzysearch --nosync --alsoclip=false -- <exact-path>
```

The adapter uses pipes, bounds output, disables debug/profile output, clipboard,
hooks, reference following, and synchronization. GPG receives
`--batch --no-tty --pinentry-mode error`; locked keyrings fail instead of opening
pinentry. Age helper/keychain integration is disabled and passphrase input is
restricted to closed stdin. Unsupported command options fail without retrying
with password-only output. Store-location configuration is preserved. The
verified direct-gopass baseline is **1.17.0 with GPG**; other crypto backends need
their own disposable-provider validation.

## Validation and lifetime

Noninteractive backend key reads accept one unencrypted OpenSSH, PKCS#1 RSA,
SEC1 EC, or PKCS#8 PEM block. Agent signing additionally supports encrypted
OpenSSH through the [local prompt helper](confirmation.md). Supported
algorithms are Ed25519, RSA (2048–8192 bits), and ECDSA P-256/P-384/P-521.
Encrypted PKCS#8, DSA, certificates, FIDO stubs, arbitrary DER, multiple PEM
blocks, and trailing material are rejected. The full derived
public-key blob must match the registered key before a local operation receives
a signer.

Key payloads are limited to 64 KiB, with additional ASN.1 integer/depth limits
and upstream SSH parser bounds. Subprocess output is bounded (64 KiB for
noninteractive reads and 1 MiB for interactive password discovery). Backend
operations have a 30-second timeout and accept caller cancellation. Gopass
cancellation terminates its process group, including helpers holding pipes open.

Private material is owned only for one local operation and byte buffers are
cleared on completion and failure. The internal signer callback must not retain
the signer. Go cannot guarantee erasure of parser allocations or copies. The
optional [signer cache](caching.md) retains parsed keys only under a
revocable provider lease; external GPG/provider caches have separate lifetimes.
Key-read errors expose only known error kinds, never helper output or provider
error text. No backend fallback occurs after key selection.


Private material must already exist in the selected provider. A complete first
connection is described in the [agent quick start](README.md).
