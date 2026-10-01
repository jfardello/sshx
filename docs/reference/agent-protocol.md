# Agent protocol

The agent implements a bounded subset of the OpenSSH Unix-socket protocol.
Each connection retains its own binding and denial state. Public registry,
mutation state and bounded signing resources are shared by the server.

## Operations

| Operation | Behavior |
| --- | --- |
| List identities | Public enabled/visible identities only; no provider read |
| Sign | Exact identity and algorithm; policy, lock, confirmation and lifetime checks |
| Session binding | Verified raw-host-key proof retained per connection |
| Add/remove/clear/lock/unlock | Local-only and explicitly enabled; see ssh-add guide |
| Unsupported extensions, SSH1, certificates, FIDO, smartcards | Explicit rejection |

| Key type | Signature flag | Result |
| --- | --- | --- |
| Ed25519 | `0` | `ssh-ed25519` |
| ECDSA P-256/P-384/P-521 | `0` | Corresponding ECDSA format |
| RSA | `2` | `rsa-sha2-256` |
| RSA | `4` | `rsa-sha2-512` |

RSA flag zero requests SHA-1 and is denied. Unknown/combined flags and RSA flags
on another algorithm are denied. RSA public identities still use `ssh-rsa`.

## Session binding

`session-bind@openssh.com` contains a host-key blob, session identifier, host-key
signature and forwarding byte (exactly zero or one). Verification proves key
possession, not host trust. Destination policy supplies the trusted pins.

An ordered sequence of forwarding bindings may end with one authentication
binding. Authentication is terminal: every subsequent bind attempt fails.
While all bindings are forwarding, a replay with the same session and host key
is idempotent and retains the original flag, even if a different flag was requested.
The same session with a different host key poisons the connection. A host key
with a new session may append a hop. Invalid proofs, malformed encoding, excessive
bounds and invalid sequences permanently poison that connection.

Bindings are recorded even while locked. Unlocking never clears provenance,
poisoning or terminal state. Without forwarding opt-in, a verified forwarding
proof is retained but admission fails and the connection remains denied.

Extension success is byte `6`. Unknown extensions receive agent failure `5`;
a failed known binding receives extension failure `28`. Recognition does not
promise unrestricted access or acceptance of every proof.

## Destination and import constraints

The authentication payload must match session ID, service, username, selected
key, algorithm and recorded path. Forwarded signing additionally requires the
final host key inside a hostbound request. The nested destination constraint is
`restrict-destination-v00@openssh.com` inside tag-255 ADD constraints, not a
standalone agent extension.

Lifetime uses tag 1 plus uint32 seconds; confirmation uses tag 2. Duplicate,
unknown, malformed or partially supported constraints reject the whole import.
Ambiguous legacy tag 3/max-sign is rejected before upstream ADD parsing. Raw host
pins are supported; CA pins and certificates are not.

## Resource bounds and dispatch

| Resource | Limit |
| --- | --- |
| Frame/reply payload | 256 KiB |
| Connections | 64 per server |
| Concurrent signing jobs | 4 |
| Identities | 256, also bounded by reply size |
| Private-key payload | 64 KiB |
| Session bindings | 16 per connection |
| Binding attempts | 64 per connection |
| Session identifier | 128 bytes |
| Policy edges | 64 per key |
| Host pins | 16 per hop |
| Nested constraint data | 64 KiB |
| Idle/partial frame read | 30 seconds |
| Reply write | 5 seconds |
| Signing/provider operation | 30 seconds, plus bounded cleanup |

The frame gate validates bodies before dispatch. Malformed fixed-body requests
fail and close the connection; invalid lengths and truncated frames close it.
Owned buffers are cleared best-effort. ADD parsing remains in sshx to preserve
all constraints. Upstream global protocol logging is disabled; sanitized agent
logging uses its own explicit writer.

## Socket activation

Linux activation accepts one listening Unix stream descriptor at fd 3 with
matching `LISTEN_PID` and `LISTEN_FDS=1`. If supplied, `LISTEN_PIDFDID` must match
the process pidfd inode. The endpoint path, type and ownership must be trusted;
`LISTEN_FDNAMES` is not proof of type. The adopted listener is close-on-exec and
activation metadata is cleared. Helpers inherit neither descriptor nor metadata.
The manager-owned socket is not unlinked by the service.

## Prompt helper protocol

sshx invokes the configured executable directly, without arguments or a shell.
It sends one UTF-8 JSON object over a private stdin pipe and closes the pipe:

```json
{
  "version": 1,
  "request_id": "<64 lowercase hexadecimal characters>",
  "operation": "confirm",
  "key_fingerprint": "SHA256:...",
  "data_digest": "<SHA-256 hex digest>",
  "algorithm": "ssh-ed25519",
  "destination": {
    "status": "verified-session-and-policy",
    "host_fingerprint": "SHA256:...",
    "username": "alice"
  }
}
```

Unknown destinations contain only `{"status":"unknown"}`. The helper must make
an explicit local decision and reply once on its private stdout pipe:

```json
{"version":1,"request_id":"<exact received ID>","approved":true}
```

For `operation: "passphrase"`, a successful reply must additionally contain
`"passphrase"` with standard-base64-encoded UTF-8 passphrase bytes. Base64 is only
wire encoding, not protection; the private pipe is the transport. Confirmation
responses must not contain a nonempty passphrase. Operations use distinct request
IDs, so passphrase entry cannot be substituted for signing confirmation. Rejection or cancellation is indicated by `approved: false` or nonzero exit status. Unknown/duplicate fields,
case variants, nulls, trailing JSON, mismatched IDs and malformed responses deny.
Passwords must not appear in arguments, environment variables, logs, files or agent replies.

The helper receives only a fixed PATH/LANG plus HOME and selected desktop routing
variables. It does not inherit agent sockets, activation descriptors, GPG/gopass
configuration, loader overrides or arbitrary caller variables. stderr is discarded;
`--verbose` reports only fixed, secret-safe categories in the agent. The optional
Tk helper defaults confirmation to No and uses masked passphrase input.


## Further reading

[Destination policy](../agent/destination-policies.md),
[forwarding](../agent/forwarding.md), and [security](../security.md) describe the
authorization model and relay limits. Wire formats follow the
[OpenSSH protocol](https://github.com/openssh/openssh-portable/blob/V_10_5_P1/PROTOCOL.agent).
