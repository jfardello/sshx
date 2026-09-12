# SSH key registration and credential stores

This is the storage foundation for native agent support (issue #23). It adds
internal registry discovery and validated key reads. It does **not** start an
agent, set `SSH_AUTH_SOCK`, add an import command, or change SSH/SCP password
selection. The agent protocol and command-line integration are separate work.

## Registry

The registry loader reads `$XDG_CONFIG_HOME/sshx/agent.json` when
`XDG_CONFIG_HOME` is absolute, otherwise `~/.config/sshx/agent.json`.
A missing file means no registered keys. Existing password commands do not read
this file. No files or credentials are automatically created or modified.

The file must be a regular file owned by the current user, with no group/other
permissions (`0600` is recommended). Its ancestor directories must be owned by
the current user or the filesystem root owner and must not be writable by other
users. Root-owned sticky ancestors such as `/tmp` are permitted above the private
parent directory. Symlinks, including symlinked ancestors, are rejected.
Use an owner-only directory (`0700`) and save updates by renaming a complete
replacement file. The maximum registry size is 1 MiB.

An empty registry is:

```json
{"version": 1, "keys": []}
```

Example record; replace the public-key placeholder with the algorithm and base64
fields from the corresponding `.pub` file, without its trailing comment:

```json
{
  "version": 1,
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
to false. Enabling a record requires explicit `unrestricted-local` policy.
`destination-constrained` and unknown policy/schema fields are rejected until
policy enforcement is implemented. Never put private keys, passwords, or
passphrases in the registry.

| Field | Contract |
| --- | --- |
| `version` | Exactly `1` |
| `id` | Unique local identifier; letters, digits, `.`, `_`, `-`; maximum 128 characters |
| `public_key` | One canonical SSH public key, without comments or authorized_keys options |
| `enabled` | Boolean; omitted means false |
| `policy` | Explicitly `unrestricted-local` in this phase |
| `comment` | Optional display label, at most 128 bytes, without control characters |
| `backend` | Exactly `gopass` or `secret-service`; no automatic fallback |
| `reference` | Exact logical gopass path, or stable Secret Service `sshx.id` |
| `collection` | Required Secret Service collection **alias**; omitted for gopass |

Secret Service IDs and aliases use the same syntax as registry IDs. Collection
labels and transient D-Bus object paths are not accepted as persistent references.
Gopass paths must be relative, normalized paths without traversal, control
characters, backslashes, or components starting with `-`.

Duplicate public keys are accepted only when backend, reference, collection,
enabled state, and policy are identical. Such aliases collapse to the first
record's identity and comment. Conflicting duplicates reject the whole registry.
Unknown, duplicate, case-altered, or null JSON fields also reject the registry.

## Backend contracts

Identity discovery reads public registry data only: no provider calls, secret
reads, unlock requests, or prompts. Backend metadata searches are separately
available with a noninteractive default and exact attribute matching for Secret
Service. Password commands explicitly retain their interactive behavior.

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

Accepted private-key envelopes are one unencrypted OpenSSH, PKCS#1 RSA, SEC1 EC,
or PKCS#8 PEM block. Supported algorithms are Ed25519, RSA (2048–8192 bits), and
ECDSA P-256/P-384/P-521. Encrypted keys, DSA, certificates, FIDO stubs, arbitrary
DER, multiple PEM blocks, and trailing material are rejected. The full derived
public-key blob must match the registered key before a local operation receives
a signer.

Key payloads are limited to 64 KiB, with additional ASN.1 integer/depth limits
and upstream SSH parser bounds. Subprocess output is bounded (64 KiB for
noninteractive reads and 1 MiB for interactive password discovery). Backend
operations have a 30-second timeout and accept caller cancellation. Gopass
cancellation terminates its process group, including helpers holding pipes open.

Private material is owned only for one local operation and byte buffers are
cleared on completion and failure. The internal signer callback must not retain
the signer. Go cannot guarantee erasure of parser allocations or copies. There
is no sshx signer cache; external GPG/provider caches have separate lifetimes.
Key-read errors expose only known error kinds, never helper output or provider
error text. No backend fallback occurs after key selection.

## Tests and disposable provider matrix

```sh
go test -race ./...
go vet ./...
dbus-run-session --config-file testdata/dbus-session.conf -- \
  env SSHX_SECRET_SERVICE_INTEGRATION=1 \
  go test -race -run '^TestSecretServiceIntegration$' -count=1 ./...
SSHX_GOPASS_KEY_INTEGRATION=1 \
  go test -race -run '^TestGopassKeyIntegration$' -count=1 ./...
```

The gopass test creates temporary HOME/config/store/GPG directories and generated
test keys. It never reads the developer's credential store. It requires gopass,
gpg, and gpgconf. The D-Bus test uses the isolated fake provider, including
cancellation, locked discovery, owner replacement, and recycled object paths.

| Provider | Validation status for this change |
| --- | --- |
| Isolated fake Secret Service | Automated locked discovery, exact reads, cancellation, owner replacement and key mismatch tests |
| gopass 1.17.0 + GPG | Disposable raw-byte retrieval, missing-path rejection, and locked-key refusal tested |
| GNOME Keyring | Manual key-storage matrix not run |
| KWallet | Manual key-storage matrix not run |
| KeePassXC | Manual key-storage matrix not run |
| gopass-secret-service | Manual key-storage matrix not run |

For each real Secret Service provider, use a separate disposable bus/profile.
Create a synthetic multiline key item with the attributes above, then check
unlocked retrieval, locked refusal, duplicate IDs, changed private keys, provider
restart/path reuse, and cancellation. Record the provider version and results;
password smoke-test results alone do not establish key-storage compatibility.
