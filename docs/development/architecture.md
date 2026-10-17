# Architecture

The executable delegates CLI handling, credential resolution, terminal transport
and native agent work to internal packages.

| Package | Responsibility |
| --- | --- |
| `cmd/sshx` | Executable entry point |
| `internal/cli` | Command parsing, credential selection, agent lifecycle |
| `internal/config` | Strict YAML defaults and precedence |
| `internal/credential` | Shared credential contracts |
| `internal/credential/gopass` | Direct gopass adapter |
| `internal/credential/secretservice` | D-Bus adapter and provider monitoring |
| `internal/keystore` | Backend key-store construction |
| `internal/pty` | Password-mode controlling PTY and stream forwarding |
| `internal/agent` | Registry, socket protocol, policies, signing and lifecycle |
| `internal/sensitive` | Owned sensitive-buffer cleanup |

## Password path

CLI options are merged with YAML defaults before credential access. The selected
provider resolves one credential and returns its password. SSH/SCP starts in a
new session with a PTY as controlling terminal. The wrapper detects the password
prompt, writes the password and continues stream forwarding, resize propagation
and terminal restoration.

Fully interactive sessions share the PTY for all three standard streams.
Redirected sessions preserve separate stdout and stderr and pass file or pipe
stdin directly to the child. A separate inherited slave descriptor establishes
the controlling terminal for password prompts; the parent keeps the slave open
until child exit because OpenSSH closes inherited descriptors before reopening
`/dev/tty`. Terminal messages are forwarded to stderr. Terminal stdin retains
its interactive relay when output is redirected.

## Agent path

A public registry snapshot maps canonical public blobs to backend references and
policies. Each accepted socket gets its own connection adapter and verified
binding state. Listing does not activate providers. Signing checks authorization
before loading private material, then checks the derived public key, signs,
verifies locally and revalidates before releasing a result.

Cold operations own their provider connection and temporary material. Optional
cache entries own monitored provider leases. Volatile imports own memory-only
signers with separate authorization lifetimes. Registry, lock and configuration
transitions advance a shared generation, invalidate caches and cancel pending
work. Connections retain their own bindings across these transitions.

## Lifecycle and ownership

The server retains a trusted parent directory descriptor and the created socket's
identity so shutdown cannot unlink a replacement endpoint. Systemd owns activated
sockets; sshx owns only its adopted descriptor and accepted connections.
Command-scoped instances terminate with their child and clean up their private
runtime directory.

The [protocol reference](../reference/agent-protocol.md) contains bounds and
wire details. [Testing](testing.md) describes fixtures and reproducible checks.
