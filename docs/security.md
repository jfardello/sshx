# Security boundaries

sshx connects local credentials to OpenSSH. The operating-system account, root,
credential provider, local session bus, selected helper and underlying OpenSSH
client remain part of the trust boundary.

## Password mode

Passwords are passed through a controlling PTY rather than command arguments or
environment variables. Owned byte buffers are cleared after use, but Go, provider
and terminal implementations can retain copies. Secure erasure is not guaranteed.
Credential metadata can still disclose account or server names. Provider
attributes are searchable metadata and must not contain secrets.

Automatic fallback to gopass occurs only when Secret Service is unavailable,
not after a provider has returned a lookup, lock, cancellation or access error.
OpenSSH remains responsible for server host-key verification and transport.
Configured SSH options have the authority of ordinary client options.

## Agent authority

A Unix socket is a local signing capability. Owner-only directories and sockets
exclude other unprivileged accounts; they do not protect against same-user
malware or root. `unrestricted-local` permits arbitrary signatures. Destination
policies instead check verified host keys and the exact authentication payload.

Listing reads public configuration and does not unlock a provider. Private-key
retrieval is noninteractive, explicit per registry record, bounded, and checked
against the registered public key. No backend fallback occurs. Confirmation
permits one operation; passphrase entry decrypts a payload and does not unlock its
credential provider. A configured helper is trusted executable code.

## Forwarding and host trust

Forwarding is disabled by default and requires destination-constrained keys when
enabled. Every recorded edge must be permitted and the final authentication must
be hostbound. Remote mutation and lock-control requests are denied.

A compromised permitted host can exercise its delegated authority. Recorded
bindings do not prove a physical network route or freshness; transparent relays
can hide hops and replayed proofs can lengthen an apparent chain. Shared host keys
cannot distinguish machines. Unix peer credentials identify a local proxy, not
its remote caller. These limits also mean that a raw relay can appear local.
[Forwarding](agent/forwarding.md) describes the operational implications.

Direct constrained authentication can permit legacy non-hostbound publickey
requests. `require_hostbound: true` removes that compatibility path and requires
support from the client and server. Host pins must come from an independently
trusted source; ssh-keyscan alone does not establish authenticity.

## Lifetime, revocation and storage

Backend signer caching is disabled by default. Supported Secret Service cache
entries require continuing provider readiness and revocation checks. Direct
gopass remains a fresh read. Imported ssh-add keys have a separate memory-only
lifetime and can remain in memory while locked.

Lock and registry/configuration changes invalidate pending signatures and cache
entries. Observed provider changes invalidate cached authority. A signature
already returned cannot be revoked retroactively. Registry refresh happens at
request checkpoints, not through a filesystem watcher.

Agent lock and registered-key suppression survive restart. The ledger contains
public suppression data and a salted lock verifier, not private keys or plaintext
passwords. Offline reset is an explicit administrative action by the local owner.
Removal does not delete backend secrets or revoke remote authorized_keys.

## Diagnostics and reporting

Agent diagnostics use fixed categories; password diagnostics identify the selected
credential. Neither is intended to expose secrets. Reports should exclude secret
values, raw private keys, environment dumps and complete provider attributes.
Reproductions should use [disposable fixtures](development/testing.md).
