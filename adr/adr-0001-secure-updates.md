# ADR-0001: Secure file updates and registration semantics

- **Status:** Accepted
- **Date:** 2026-10-07
- **Issue:** [#36](https://github.com/jfardello/sshx/issues/36) (C-01)
- **Scope:** Config editing and public-key registration; no Windows implementation or public age API.

## Context

Config and registry writers need consistent security and failure behavior. This
ADR defines the expected behavior for concurrent edits, system crashes and
cancellation, and assigns responsibility for enforcing each rule. The architecture
should reuse small internal operations rather than a generic persistence framework.

Existing behavior:

| Source | Observed behavior / constraint |
| --- | --- |
| `internal/config/config.go` | Strict YAML, 64 KiB limit, absent/false/empty distinction; reader follows working symlinks and validates opened regular files, but does not enforce registry ownership rules |
| `internal/agent/agent_registry.go` | Descriptor-relative traversal rejects symlinks; trusted ancestors and owner-only regular registry; 1 MiB limit; equivalent public-key aliases collapse in runtime view |
| `internal/agent/agent_mutation_state.go` | Validated lock file, exclusive nonblocking lifetime lock, same-directory temporary file, file sync, rename, directory sync; post-rename sync failure currently shares the generic error |
| `internal/agent/agent_signing.go` | Effective registry changes invalidate signer caches, retire volatile imports and advance authorization generation; lock/suppression state survives |

The state writer is a reference, not a directly reusable edit transaction: config
and registration locks must be short-lived and publication outcomes must be explicit.

## Proposed decision

### 1. File trust and document preservation

- Config readers must retain existing compatibility, including working symlinks;
  dangling links remain errors. Readers must not silently adopt registry permissions.
- Writers must require a clean absolute destination and reject symlinks in the file
  and ancestors. Writers must validate opened handles and retain the trusted parent
  handle; pathname checks alone are insufficient.
- On Unix, ancestors must be owned by the current user or filesystem root owner,
  with no group/other write access. Writers may accept root-owned sticky ancestors
  only above the immediate parent, matching registry traversal. Existing files must
  be current-user-owned regular files with no group/other write access; registry,
  lock and temporary files must additionally have no group/other permissions.
  Writers must reject multiply linked targets and lock files.
- Writers must create missing sshx-owned directories/files with 0700/0600, without
  changing permissions on existing directories, and publish replacements with 0600.
  A future Windows implementation must map access requirements to SID/DACL and
  handle checks, not Unix modes.
- Missing config means defaults; missing registry means no records. Writers may
  create missing lock or target files only after validating the parent. Empty config
  must retain current semantics; an existing empty/invalid registry is not absence.
- Writers must validate bounded complete input and output (config 64 KiB; registry
  1 MiB) and refuse malformed/unknown/duplicate/null fields according to each current
  decoder. Errors must not expose raw document values or private material.
- Config writers must edit YAML nodes to preserve comments and unrelated supported
  settings. Registry writers must edit the full JSON document, retaining record
  order and all aliases; JSON whitespace need not survive. Writers must not serialize
  the deduplicated runtime registry as source.

### 2. Update transaction and outcomes

1. The transaction must validate/open the parent and acquire a per-target exclusive
   advisory lock on a stable sibling `<filename>.lock`. It must fail immediately if
   the lock is busy, without waiting or retrying. The transaction must validate the
   lock as a private, owned regular file and must never unlink it on release.
2. The transaction must read/validate the current document under the lock and capture
   its opened-object identity, contents and relevant metadata, or explicit absence.
3. The transaction must apply the edit and validate the complete replacement. A
   semantic no-op must return unchanged without rewriting the target. Provider/TTY/
   dialog work must not occur while the lock is held.
4. The transaction must exclusively create an unpredictable same-directory temporary
   file with private access. It must write completely, sync and close the file, and
   abort on any failure.
5. The transaction must recheck parent identity/trust, destination identity/contents/
   permissions and context cancellation immediately before publication. Unexpected
   replacement, in-place modification or creation of an absent target must return
   conflict; the transaction must not retry in a way that overwrites another edit.
6. The transaction must atomically replace through the retained parent, then sync
   directory metadata. It must release the lock and remove only its own unpublished
   temporary file.

| Outcome | Meaning |
| --- | --- |
| Unchanged | Validated no-op; this operation published nothing |
| Published | Complete replacement is visible and required syncs succeeded |
| Pre-publication error | This operation did not replace the target; it must report busy/conflict/cancel/invalid/I/O category |
| Published, durability uncertain | Replacement happened but final durability confirmation failed; the operation must report this explicitly and must not claim rollback or retry automatically |

Cancellation observed before replacement must prevent publication. Once replacement
succeeds, the transaction must finish/report the publication outcome even if
cancellation arrives. Cleanup errors must not disguise that outcome. Normal failures
must clean up owned temporary files; crashes may leave private temporary artifacts,
but must never leave partial published documents.

These guarantees serialize cooperating writers. A noncooperating same-user editor
can race the final check and rename: portable file replacement is not filesystem
compare-and-swap. The implementation must not promise prevention of every external
lost update or protection from malicious processes with the same user privileges.
Filesystems without the required locking/atomicity/durability semantics are
unsupported unless an explicit weaker mode is separately designed; the
implementation must not silently degrade.

### 3. Registration and replacement

- Registration must require an explicit backend/exact reference and an explicit
  unrestricted-local policy or destinations. Records must default to disabled;
  confirmation/enablement must be explicit.
- Registration must retrieve and fully validate the private key before acquiring
  the registry lock, using current format/algorithm/64 KiB/KDF restrictions.
  Encrypted OpenSSH keys must use no-echo controlling-terminal input. Extracting an
  envelope public key alone is not validation. Registration must keep provider
  unlock and key passphrase separate, clear owned buffers and never write private
  material to the registry.
- Registration must construct canonical public material, exact reference, policy
  and display metadata. Writers must emit registry version 2 and preserve existing
  records during v1 upgrade.
- The same ID and same validated record must be idempotent, including with
  `--replace`. Registration must compare decoded canonical fields, ignoring JSON
  whitespace and omitted default booleans/empty optional fields. It must preserve
  destination edge/pin ordering and use current structural policy equality rather
  than inventing semantic graph equivalence.
- A differing record must require explicit `--replace`. Registration must replace
  only the requested ID, keeping its position; new IDs must append. Registration
  must reject conflicting aliases rather than modifying them. Unrelated records
  must survive.
- Equivalent public-key aliases must remain allowed under the current validator:
  backend/reference/collection/policy/enabled/confirm/destinations must agree;
  ID/comment may differ. A replacement that leaves conflicting aliases must fail
  the entire transaction; registration must never silently update or remove other
  aliases.
- Registration must validate the entire proposed registry through the same rules
  as the reader. Registration does not install remote keys, change passwords or
  reset agent state.
- The agent must preserve current live reload: effective changes must invalidate
  cached signers, retire volatile imports and invalidate in-flight authorization
  generations; the lock/suppression ledger must remain intact. Formatting-only/
  no-op changes must not manufacture an effective change.

### 4. Destinations and known-hosts

- The CLI must accept repeated `--destination user@host` or `user@[IPv6]`; the
  username must be present and exact, with no wildcard/empty value. The CLI must
  reject embedded ports, URI syntax, whitespace/controls and IPv6 zone identifiers.
  It must accept bare IPv6 after `@` when unambiguous and validate username/hostname
  with existing policy text bounds.
- One `--port` must apply to all destinations, defaulting to 22 with range 1–65535.
  Mixed-port registration requires a later explicit syntax; the CLI must never
  guess from `host:port`.
- Registration must read only the explicit known-hosts file (default
  `~/.ssh/known_hosts`), bounded to a proposed 1 MiB. It must not fetch keys, resolve
  DNS aliases or read system files. It must use OpenSSH-compatible matching,
  including hashed entries and `[host]:port`.
- Registration must collect/deduplicate supported matching plain host keys and
  reject missing pins, matching revoked keys, matching unsupported keys, and
  certificate/CA-only trust. Malformed input must fail closed; registration must
  preserve current host-key validation and caps (16 pins per hop, 64 edges).
- Registration must produce direct origin-to-destination edges with exact username
  and canonical pins. It must store an unbracketed hostname/IPv6 label, not the
  known-hosts lookup spelling: `alice@[2001:db8::1] --port 2222` looks up
  `[2001:db8::1]:2222`, but stores label `2001:db8::1`. Brackets are rejected by
  current policy text validation.
- Host labels and lookup ports do not establish authorization. The existing
  signing policy binds host keys and username, **not a TCP port**; documentation
  must state this distinction.

### 5. Go boundaries (sketch, not implemented API)

Shared internal filesystem code should own locking, opened-object checks and
publication; config should own YAML/setting validation; agent should own registry/
key/policy validation; CLI should own arguments, provider calls and terminal
interaction. Unix descriptors should stay inside the OS implementation. No new
interface is required solely for this ADR.

```go
// Proposed signatures; FilePolicy selects the checks above, not OS flags.
// Publication records whether replacement occurred, including on error.
func UpdateFile(ctx context.Context, path string, policy FilePolicy,
    edit func(current []byte, exists bool) (next []byte, changed bool, err error),
) (Publication, error)

// Retain every validated source record, separately from the runtime view.
func parseRegistryDocument(data []byte) (agentRegistryDocument, error)
func upsertRegistryRecord(doc agentRegistryDocument, record agentKeyRecord,
    replace bool) (next agentRegistryDocument, changed bool, err error)
```

The edit callback must be bounded/local and must not retain borrowed input. It must
validate input and replacement with the domain decoder. Registration must construct
its record before entering `UpdateFile`. Exact naming/package layout is left to
C-03/C-04; future age primitives must not depend on these sshx-internal APIs.

## Test matrix (required in implementation issues)

| Area | Cases and expected evidence |
| --- | --- |
| Config editing | Comments/unrelated supported nodes survive; absent vs false/empty/unset; malformed/oversized input unchanged; symlink reader succeeds but writer refuses |
| File trust | Wrong owner/writable ancestors, target/ancestor symlink swap, FIFO/device, hardlink, permissive lock rejected; opened handle, not only pathname, checked |
| Transactions | Busy lock fails immediately without retry; sequential cooperating edits preserve both changes; external replace/in-place edit/absent-file creation returns conflict; no-op does not rewrite |
| Failure/cancel | Inject write/sync/close/rename/directory-sync failures; cancel before/after publication; distinguish unchanged target from published-but-uncertain; crash leaves complete old/new document |
| Registry | Invalid original refused; v1 upgrade; unrelated records/order/aliases preserved; identical record unchanged; differing ID needs replace; conflicting alias replacement refused |
| Key validation | Supported/encrypted keys, wrong/cancelled passphrase, missing TTY, provider locks, excessive KDF, key-pair mismatch; no secrets in files/errors |
| Destinations | DNS/IPv4/IPv6, exact user, default/nonstandard port, hashed/multiple pins; malformed/revoked/unsupported/CA-only/missing entries rejected; no network calls |
| Live agent | Newly registered key authenticates; destination rejection; locked/suppressed agent remains so; effective reload retires imports/invalidates cache and pending work |

## Consequences and confirmed choices

Writers become stricter than readers and may refuse existing readable dotfiles.
Atomic publication does not imply rollback after rename or protection against
same-user malicious writers. Small shared operations allow a later Windows port
without weakening current Unix behavior.

Confirmed choices:
- Writers must fail immediately on busy edit locks. Registration must replace only
  the requested ID and reject conflicting aliases.
- The 1 MiB known-hosts bound is a proposed resource limit, not current behavior.
