// Package agent implements sshx's native SSH agent, its public key registry,
// registration preparation, and local signing policy.
//
// # Reading order
//
// Start with api.go for the package entry points, then follow server.go for
// listener lifetime and protocol.go for per-connection request dispatch.
// service.go describes shared runtime state; service_signing.go contains the
// complete signing workflow and its authorization checkpoints. Read policy.go
// and policy_binding.go for destination authorization, then keys_provider.go and
// keys.go for provider reads and private-key parsing.
//
// # File groups
//
// Files share this package so the service can coordinate authorization, lock
// state, registry generations, cache leases and cancellation without exposing
// those internals through additional package interfaces. Filename prefixes group
// responsibilities rather than creating separate state owners:
//
//   - api.go exposes the existing constructors and types; dependencies.go holds
//     private aliases for credential and sensitive-buffer dependencies.
//   - server*.go and endpoint.go manage listeners, connection lifetime, socket
//     ownership checks, activation and endpoint probing.
//   - protocol*.go adapts OpenSSH operations, bounds frames and decodes imported
//     keys; authorization decisions remain in the service and policy code.
//   - service*.go coordinates signing, registry refresh, cache leases, mutations,
//     durable lock/suppression state and sanitized diagnostics.
//   - registry*.go defines public records, reads trusted files, validates JSON
//     and publishes updates. Source documents retain aliases; runtime snapshots
//     deduplicate equivalent identities.
//   - policy*.go verifies session bindings and evaluates destination/forwarding
//     restrictions. Binding state belongs to one connection.
//   - keys*.go validates key formats and encrypted envelopes, scopes provider
//     reads, and checks that private material matches the enrolled public key.
//   - prompt.go configures prompting, constructs bound requests and validates
//     responses. Process launching belongs to internal/helperexec; desktop UI
//     belongs to the separate prompt helper packages.
//   - registration*.go prepares public identities and pinned destination graphs
//     for registration; registry_write.go publishes the validated records.
//
// # State and sensitive material
//
// Each connection owns its binding history and denial state. The key service
// owns shared registry snapshots, generation/lock state, admission capacity,
// imported keys and the signer cache. Registry, lock and helper transitions
// invalidate pending operations through that shared generation mechanism.
//
// Cold signing operations own their provider connection and temporary material;
// cached signers retain separate revocation leases. Keep the checks before and
// after prompts, provider access, decryption, signing and cleanup in the signing
// workflow. File boundaries do not change lock ordering or ownership rules.
// Owned mutable secret buffers are cleared best-effort; parser/runtime copies
// cannot all be erased reliably.
//
// # Tests
//
// Unit-test filenames follow the implementation responsibility. Shared fixtures
// live in test_backend_test.go (stores and service setup), test_keys_test.go
// (generated keys and registry records), test_server_test.go (sockets and frames)
// and test_policy_test.go (bindings, userauth and destination graphs).
// Feature-specific fixtures remain beside their tests. integration_openssh*.go
// and integration_gopass_test.go contain the external-tool interoperability
// fixtures; their existing environment gates control external integration work.
// Benchmarks stay beside the cache tests, and fuzz targets stay with the wire
// and policy behavior they exercise.
package agent
