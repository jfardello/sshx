# Destination constraints

Destination policies associate explicit host-key pins and destination usernames
with an agent identity. Existing version-1 `unrestricted-local` records remain supported.
Policy configuration is registry-based. [Forwarding](forwarding.md)
requires the separate `--allow-forwarding` opt-in.

## Configuration

The following version-2 configuration belongs in `~/.config/sshx/agent.json` (or the corresponding
`$XDG_CONFIG_HOME/sshx/agent.json`):

```json
{
  "version": 2,
  "keys": [{
    "id": "work-key",
    "public_key": "ssh-ed25519 <USER_KEY_BASE64>",
    "enabled": true,
    "policy": "destination-constrained",
    "backend": "gopass",
    "reference": "ssh-keys/work-key",
    "destinations": {
      "version": 1,
      "require_hostbound": false,
      "edges": [{
        "from": {},
        "to": {
          "hostname": "server.example",
          "username": "alice",
          "host_keys": ["ssh-ed25519 <SERVER_HOST_KEY_BASE64>"]
        }
      }]
    }
  }]
}
```

Both placeholders must contain canonical public keys: algorithm, one space,
and base64, without comments or authorized_keys options. `public_key` is the
user's authentication key; `host_keys` contains the server's host keys. Host pins should be verified through an independent trusted channel or an
already verified known_hosts entry. Merely collecting a key with ssh-keyscan does not establish
trust. There is no automatic enrollment, DNS lookup, TOFU or known_hosts import.
The registry requires owner-only permissions and trusted ancestor directories.
Private keys stay in the selected credential store.

`from: {}` means the local origin. A non-origin source requires a hostname label
and pins, and cannot specify a username. Every destination requires a label and
at least one pin. Destination usernames are exact; omitting the username or
setting it empty explicitly allows any username. Wildcards, CA flags, host
certificates and unsupported key formats are rejected. Raw host keys support
Ed25519, RSA 2048–8192 bits and ECDSA P-256/P-384/P-521.

Hostname labels are descriptive. Authorization uses verified host keys, not a
hostname or port claimed by the client. Hosts or ports sharing a host key cannot
be distinguished by this policy. Multiple pins allow an approved rotation
overlap. Duplicate public-key aliases must have identical backend references,
enablement and complete policies; their permissions are never combined.

## Authentication and visibility

A command-scoped connection can be started with `sshx agent run -- ssh alice@server.example`.
A constrained key is hidden until the agent connection has a verified binding
to an approved host/path. Consequently, an ordinary unbound `ssh-add -l` does
not show constrained keys. Identity listing reads public configuration only;
it never opens a credential store. The final username is checked when signing,
because identity-list requests do not contain it.

Before retrieving a private key, signing checks the exact SSH authentication
payload: session identifier, message type, service, username, public key,
algorithm and binding chain. Arbitrary data, missing proofs, mismatches and
trailing fields are denied. A direct single binding permits ordinary `publickey`
authentication by default. The setting `require_hostbound: true` requires
`publickey-hostbound-v00@openssh.com` and an exact destination host-key match in
the signed payload. This stricter setting requires compatible client/server
support. It does not silently fall back to ordinary publickey authentication.
Unrestricted-local records retain unrestricted local signing behavior.

The policy evaluator checks every directed edge in a chain and requires
hostbound authentication for a forwarded constrained path. Visibility at an
intermediate hop requires an approved onward edge. However, the connection
admission gate permits this only with `--allow-forwarding`. Bindings do not prove
physical network routing. See [forwarding](forwarding.md).

ProxyJump uses local SSH clients and separate direct agent bindings. To allow
both authentications, approve origin → bastion and origin → destination.
A bastion → destination edge alone does not authorize that direct destination
binding. Intermediate usernames cannot be established from session bindings.

## Policy updates

File-backed agents securely reread the public registry before listing/signing
and again after private-key operations and cleanup, before returning a signature.
A changed policy, pin, backend reference or enablement advances the generation;
a pending signature admitted under an older generation is discarded. Lock
transitions also invalidate pending signatures. Existing bindings are retained.

Updates should be published atomically by renaming an owner-controlled `0600`
replacement file. A missing registry yields an empty catalog. Malformed or untrusted files
fail closed; a valid replacement permits recovery. Whitespace-only changes do
not invalidate requests. There is no filesystem watcher or guarantee of
observing a transient change restored between checks. In-memory registries
remain snapshots. There is no reload CLI command; SIGHUP still shuts down the
agent. Restarting remains available but is unnecessary for file-backed policy
updates. After host-key rotation, a new SSH connection is required for its new binding.

Bounds: 1 MiB registry, 64 edges per policy, 16 host pins per hop, and the existing
16 bindings per connection. The strict nested destination-constraint wire
decoder is bounded to 64 KiB. It understands the tag-255 key-add constraint, not
a standalone agent extension. Imports require the separate `--allow-key-mutations` option.
