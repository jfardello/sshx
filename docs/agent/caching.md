# Optional signer cache

The optional in-memory cache retains parsed signing keys for a bounded lifetime.
It is disabled by default (`--cache-ttl=0`). A short lifetime can be configured:

```sh
sshx agent run --cache-ttl=30s -- ssh alice@server.example
sshx agent start --foreground --cache-ttl=30s
```

For systemd, `--cache-ttl=30s` belongs in the existing service ExecStart alongside
its socket-activation and helper options. Unit reload and service restart are
required after changing the configuration. This is an agent CLI option, not an SSH/SCP YAML setting.
The accepted range is 0–5 minutes. No registry changes are needed.

## Supported providers

Caching is currently available for **Secret Service** with an owner-pinned,
independent D-Bus monitor and noninteractive readiness checks. **Direct gopass
continues loading its key on every request**, even with a nonzero TTL: its current
interface cannot reliably report provider lock/replacement and item-generation
changes. Setting the flag never switches credential backends or weakens checks.
A gopass Secret Service bridge is subject to the Secret Service contract rather
than assumed equivalent to direct gopass; the bridge's notifications must be verified.

On a cache hit, sshx checks the current unique service owner, collection alias,
exact item attributes and identity, item/collection lock state, and item Modified
value before and after signing. These checks do not call GetSecret or unlock the
provider. A continuous private signal handler revokes the generation on provider
signals, service-owner changes or disconnection. It does not rely on the
second-resolution Modified timestamp alone. Signals from the same provider are
handled conservatively: even an unrelated item change can evict a cached key.

The monitor is installed before loading private material and is checked again
after loading. A provider that is unavailable, locked, malformed or unable to
establish monitoring fails the operation. No stale signer is used as fallback.
Providers without the optional monitoring interface use fresh reads. At cache
capacity, new requests likewise use fresh reads rather than retaining more keys.

The contract assumes a conforming provider that reports changes and accurate lock
state. This follows the [Secret Service interfaces and notifications](https://specifications.freedesktop.org/secret-service/latest-single/).
A provider-side change can race with a signature already being delivered; sshx
rejects results once it has observed invalidation, not retroactively.

## Lifetime and ownership

Each entry expires at insertion time plus TTL. Hits never refresh that deadline.
Expiry uses Go's monotonic clock and a timer, so idle entries also expire. A backward clock jump is also treated as expiry. Cache lifetime is not
identity authorization lifetime: every use still requires an enabled enrolled
identity, current destination policy and any required fresh confirmation.
Imported [ssh-add identity lifetimes](ssh-add.md) are enforced separately
and are not implied or extended by cache TTL.

The cache holds at most 16 monitored entries/cleanup slots. Signing remains
bounded to four concurrent jobs. A job borrows its signer until it completes;
eviction prevents new uses, cancels existing uses, and discards late results.
Revocation monitors close outside global state locks. Concurrent cold loads may
replace a prior entry conservatively, causing an older in-flight result to fail.

Lock transitions, registry/policy/reference changes, helper/cache configuration
changes, explicit internal eviction, observed credential changes, deletion,
provider replacement, expiry and shutdown invalidate entries. File-backed
registry changes are observed at existing request/release checkpoints, not via a
filesystem watcher. Shutdown waits for signing jobs and monitor cleanup.
`Server.EvictCache` provides an internal management hook; there is no public
cache-clear subcommand. Restarting also empties the cache.

Confirmation remains per request, including cache hits. A cached decrypted signer
avoids another OpenSSH passphrase prompt until eviction; the passphrase itself
is never retained. Provider unlocking remains separate and noninteractive.
No approvals, raw key payloads, passphrases, or cache files are stored. Parsed
private key objects remain plaintext in process memory during their lifetime.
Owned temporary buffers are cleared, and retired signer references are dropped
once borrowers finish; Go cannot guarantee erasure of parser/crypto/GC copies.
External GPG and provider caches remain outside sshx control.


## Diagnostics

`--verbose` reports cache hits, provider checks and safe bypass/failure categories
without private keys or backend references. [Testing](../development/testing.md)
includes the isolated provider and cache checks.
