# Local confirmation and encrypted OpenSSH keys

Per-request signing confirmation and passphrase acquisition are provided through
an explicitly configured local executable. No helper is selected automatically.
Existing records remain noninteractive unless `confirm` is true or their private
key is encrypted. Approvals and passphrases are never cached. An optional
[signer cache](caching.md), disabled by default, can retain decrypted
signers for supported monitored providers.

## Enable and run

Registration's `--confirm` option sets the version-2 `"confirm": true` field
required for per-request approval. Existing records need `--replace` with the
complete desired policy and enablement; see [registration](registration.md).
This applies to both `unrestricted-local` and `destination-constrained`
policies. The existing host-pin rules remain unchanged. Duplicate public-key
aliases must agree on confirmation as well as their other security properties.
Version 1 cannot enable confirmation. Identity listing never prompts.

The optional `sshx-prompt-zenity` executable handles signing confirmation and
masked OpenSSH passphrase entry. On Linux it requires a local Zenity-compatible
dialog program (`qarma`, `zenity` or `matedialog`, in that lookup order); on macOS
it uses the system `osascript`. A source installation can be prepared with:

```sh
go build -o sshx-prompt-zenity ./cmd/sshx-prompt-zenity
install -d -m 0700 "$HOME/.local/bin"
install -m 0700 sshx-prompt-zenity "$HOME/.local/bin/sshx-prompt-zenity"
sshx agent run --prompt-helper "$HOME/.local/bin/sshx-prompt-zenity" -- \
  ssh alice@server.example
```

Release archives also contain the helper. Confirmation offers **Allow once** and
**Reject**, with Reject as the default. Passphrase entry is masked; empty input
denies the request. Each invocation handles one version-1 request and exits.
The helper neither selects password credentials nor implements desktop selection.

The existing optional Tk helper at `contrib/prompt/sshx-prompt` remains supported
for version 1. It uses `/usr/bin/python3` in isolated mode and Python's Tk library:

```sh
install -d -m 0700 "$HOME/.local/bin"
install -m 0700 contrib/prompt/sshx-prompt "$HOME/.local/bin/sshx-prompt"
sshx agent run --prompt-helper "$HOME/.local/bin/sshx-prompt" -- \
  ssh alice@server.example
```

The actual absolute helper path is required; shell commands and PATH lookup are not
accepted. The executable and each ancestor must be owned by the current user or
root, without symlinks or group/other write permission. Root-owned sticky ancestors
such as `/tmp` are permitted above an owned private directory. The helper is
trusted local code; these checks cannot defend against malicious code running as
the same user. The helper's interpreter and imports are also part of that trust.
The path is checked both when configured and before each invocation. These are
pathname checks, without a retained executable handle: a same-user or root
replacement between validation and execution can still substitute the helper or
its dependencies. They do not provide race-free executable pinning.

For systemd, the existing environment and executable path should be retained.
The helper option belongs in the service's ExecStart override:

```ini
[Service]
ExecStart=
ExecStart=/home/alice/.local/bin/sshx agent start --foreground --socket-activation --prompt-helper /home/alice/.local/bin/sshx-prompt
```

The units should be reloaded and the service restarted after configuration changes.
The example uses the Tk installation path; a Zenity installation uses
`/home/alice/.local/bin/sshx-prompt-zenity` instead. The service needs appropriate
desktop session routing (`DISPLAY`, `WAYLAND_DISPLAY`, and when needed
`XAUTHORITY`, `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`). No display,
missing dialog dependencies, cancellation, or helper failure denies the operation.
Nothing falls back to daemon stdin, SSH terminal
prompts, or a remote channel. This is not a universal desktop UI integration.
`--prompt-helper` overrides the separate `agent.prompt-helper` configuration
default. Password-command settings do not configure it; see
[agent defaults](../configuration.md#agent-defaults).

## What approval means

The confirmation dialog authorizes exactly one signing operation. Its identity
includes a fresh random nonce, connection identity, policy generation, selected
algorithm, public key, and SHA-256 digest of the exact bytes to sign. An approval
cannot be reused for an identical retry or another concurrent request.

The helper sees the key fingerprint, algorithm, data digest and request ID.
For a constrained request that has passed authorization, it also sees the bound
host-key fingerprint and requested username approved by policy. It never treats
a stored hostname/comment as cryptographic proof. Unrestricted signing shows
`Destination: UNKNOWN`, even if the client has supplied a binding. Host keys do
not prove network routing or distinguish machines sharing the same host key.

Confirmation occurs before retrieving private material. Provider unlocking is
separate: a locked gopass/GPG or Secret Service backend still fails its
noninteractive read. The OpenSSH passphrase dialog decrypts the retrieved key;
it does not unlock the credential provider and does not grant future signing
consent. With `confirm: true`, each use requires confirmation; an encrypted key also
requires a passphrase on a fresh load. A valid signer-cache hit skips decryption,
not confirmation. With `confirm: false`, only fresh key decryption prompts.

The machine-readable [helper protocol](../reference/agent-protocol.md#prompt-helper-protocol)
is documented separately.

The Zenity helper validates all required request fields, exact field names and
types, IDs and destination status before showing a dialog. Unknown, duplicate,
null or trailing fields/data are rejected. Identity values are quoted and escaped
as ASCII, including controls, bidi characters and markup delimiters. All identity
bytes remain represented; values are not truncated. Escaped text is display only
and does not alter the request ID echoed in the response.

## Bounds and invalidation

There are at most four active signing jobs/prompts, no unbounded approval queue,
and a 30-second total operation deadline including prompts and backend work.
Requests and responses are limited to 16 KiB and passphrases to 4096 bytes. Helper processes run
in a separate process group and are terminated on cancellation or completion;
stdout cannot grow without bound. Connections retain at most one pending frame;
excessive pipelining is rejected. Disconnect or shutdown cancels waiting prompts.
An oversized response also cancels its helper immediately. Process-group cleanup
includes descendants that remain in that group; it cannot contain a descendant
that deliberately detaches into a different group/session.

The Zenity helper additionally has a 30-second local deadline covering input,
dialog work and response collection. Its supervisor isolates the dialog worker
in a process group and kills that group on timeout, cancellation or completion.
A private lifetime pipe makes the worker kill its group if the supervisor dies,
including when the agent sends SIGKILL. It never retries or opens a fallback
prompt. Only the complete protocol response reaches stdout; errors are fixed
and contain no request, passphrase, native stderr or underlying library details.

Authorization is rechecked after confirmation, backend retrieval, passphrase
entry and decryption, and before releasing the result after backend cleanup.
Observed registry, helper or lock changes cancel pending operations and invalidate
their approvals. File-backed policy changes are reread at those checkpoints;
there is no filesystem watcher, so an edit may not dismiss a dialog immediately.
Bindings survive lock transitions. Already delivered signatures cannot be revoked.

Supported encrypted keys are single-key OpenSSH PEM with bcrypt and AES-256-CTR
or AES-256-CBC. Before prompting or KDF work, sshx checks the complete envelope,
the embedded public key, salt length (16–64 bytes), and rounds (1–64). Other
ciphers/KDFs, excessive work, multiple keys and encrypted PKCS#8 are rejected.
Wrong or empty passphrases fail without retry/fallback. The decrypted key must
still match the enrolled public key. KDF computation itself is not interruptible,
but its work is bounded and cancellation is checked before releasing any result.

Owned key/passphrase/response buffers are cleared best-effort, including failure
paths. Go strings, JSON encoding buffers, the Zenity library, native dialog
processes, Tk and Python can retain copies that cannot be reliably erased.
Passphrases travel through private pipes, never command arguments or environment
variables. The helper exits after each operation; no persistent passphrase
storage is implemented.
