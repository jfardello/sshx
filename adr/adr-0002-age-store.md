# ADR-0002: Importable age store and versioned encrypted format

- **Status:** Accepted
- **Date:** 2026-10-08
- **Issue:** [#50](https://github.com/jfardello/sshx/issues/50) (A-01)
- **Scope:** Public API, format and threat model; no backend implementation or dependency changes.

## Context

The native age backend must also support an independent application similar to
secret-tool and later move to another repository. Exported names in `internal/credential/api.go` are not
externally importable. `internal/keystore/opener.go` currently lacks configured
identity/snapshot inputs; agent signing revalidates registry state, not store state.

This ADR defines the public library boundary, versioned store format, identity
ownership, trust model and transaction guarantees needed by later implementation
issues. It also specifies resource bounds and the limits of recipient verification,
so applications can reuse the store without depending on sshx internals.

The implementation should use maintained `filippo.io/age`, dedicated X25519
identities and individually armored objects. It must not introduce custom
cryptography, infer administrator authority from catalog access, or treat
successful decryption as proof of the complete recipient set.

## Proposed decision

### 1. Package boundary and entry types

- The native age backend should start as an exported Go package,
  `github.com/jfardello/sshx/agestore`, in the existing module. Its implementation
  must remain self-contained, without sshx-internal, Cobra, agent, config-global,
  terminal/dialog, Git or gopass dependencies. A-02 must pin a reviewed compatible
  age release; upstream development source does not select that release.
- The library owns generic entries, encrypted metadata, policy, identities, trust
  mechanisms and filesystem transactions. sshx adapters own SSH-key parsing,
  target validation, registry references and prompt protocols.
- Entries have a bounded namespaced type string, logical path, string metadata map
  and opaque payload bytes. Types such as `sshx.secret`, `sshx.ssh-key` and
  `vault.password` are application conventions, not library dispatch rules.
  The library may list, read and preserve unknown entry types; sshx must reject
  types it cannot use. Unknown structural format versions/fields must fail closed.
- Public API is experimental until implementation review. Package relocation
  changes imports, not store bytes; no module/import names appear in the format.
  Independent format versions change only through explicit migration, never an
  automatic rewrite on open. A separate module can follow independent versioning.

### 2. Formats and access groups

Structural decoders must reject duplicate/unknown fields, null required values,
traversal, inconsistent references and merge-conflict artifacts. Public policy
should use strict YAML; manifests and decrypted envelopes should use JSON.

| Object | Proposed version-1 fields / binding |
| --- | --- |
| Policy | Version, nonempty admin recipients, ordered creation rules with unique ID, path regex and recipients |
| Manifest | Version, store ID, generation nonce, policy object reference/hash, group records mapping rule ID to opaque group ID and catalog reference/hash |
| Group catalog (encrypted) | Version, store/group IDs, effective-recipient digest, entries with stable ID, type, path, metadata, payload object reference/hash |
| Payload (encrypted) | Version, store/group/entry IDs, type, path, metadata, effective-recipient digest, base64 payload bytes; every field checked against catalog |

- Store/group/entry/generation IDs are independently generated 128-bit random
  values encoded as 32 lowercase hex characters. Stable entry IDs survive replace
  and policy migrations. Ciphertext object names use fresh random IDs, never
  paths or types. SHA-256 hashes cover exact object bytes; hashes are integrity
  references, not signatures.
- The library should store immutable public policy objects and armored encrypted
  objects under fixed library-owned directories. `manifest.json` alone selects
  the active snapshot. Object references must contain validated IDs, not arbitrary
  filesystem paths.
- Policy canonicalization must produce deterministic JSON with fixed fields,
  sorted deduplicated recipient lists and original rule order, hashed with SHA-256.
  The parser must reject duplicate input recipients rather than ambiguously
  normalizing them. The effective-recipient digest hashes the canonical sorted union.
- Logical paths must be normalized, relative and slash-separated. The library must
  reject absolute paths, empty/dot/traversal components, backslashes and control
  characters. Go/RE2 rules must be evaluated in order; the first match wins and
  unmatched writes must fail.
- Each rule owns one access group. Writers must encrypt its catalog and every
  entry to the deduplicated union of rule recipients and all administrators.
  The manifest must not contain entry names or targets. Public regexes/rule names,
  recipient keys, group counts, sizes and history still expose operational information.
- Rule IDs map to opaque group IDs. Unchanged groups keep IDs; new rules allocate
  groups. Metadata-only listing decrypts accessible catalogs, not payloads.
  Cross-group duplicate logical paths are rejected when detectable; a member
  cannot prove global uniqueness in catalogs it cannot decrypt. Administrators
  perform the complete check.

### 3. Identity ownership, administrator checks and bounds

- Version 1 must accept only concrete X25519 identities/recipients, not SSH
  identities, plugins or externally implemented identity callbacks. Identity files
  contain bounded X25519 identity text, optionally wrapped in age scrypt encryption.
  The loader must reject identities within the store, unsafe links and permissive access.
- Identity generation must produce protected bytes by default, using a
  caller-supplied passphrase; unencrypted generation requires an explicit option.
  The CLI owns secure no-overwrite file creation and input. The library must not
  prompt or perform hidden discovery.
- An operation loads identities only for its own duration. Administrator-only
  mutation requires deriving the public recipient from a supplied, unlocked
  X25519 secret identity and matching an administrator in the **current accepted
  policy**, before evaluating the new policy. A recipient string or ability to
  decrypt member data is not administrator proof. New admins cannot self-authorize.
- This is enforcement by conforming software, not an access-control barrier against
  someone rewriting their clone. Encryption is not writer authentication;
  repository permissions/review govern accepted changes. No administrator
  signatures, rollback protection or denial of access to old plaintext/history.

| Resource | Proposed hard v1 bound |
| --- | --- |
| Raw entry payload / complete decrypted payload envelope | 64 KiB / 128 KiB |
| Decrypted catalog / armored catalog object | 1 MiB / 2 MiB |
| Armored payload object | 256 KiB |
| Policy / manifest | 256 KiB / 256 KiB |
| Rules/groups; recipients per rule; administrators | 64; 64; 16 (effective union at most 80) |
| Entries per group; metadata per entry; path | 4096; 8 KiB encoded; 1024 UTF-8 bytes |
| Identity sources / decoded identity text / encrypted identity file | 16 / 64 KiB / 256 KiB |
| Passphrase; concurrent KDFs per store handle | 4096 UTF-8 bytes; 1 |
| Scrypt generation and maximum accepted work factor | logN 18 (approximately 256 MiB working memory) |

The library must use bounded readers and validate complete authenticated plaintext
before returning data. It should process catalogs sequentially rather than retain
all plaintext. Exceeding a limit must return an error, not truncated data. Identity
attempts must be limited to configured sources, without automatic wrong-passphrase
retries. A-02 must verify these limits with fixtures, particularly envelope overhead.

The implementation must set age `SetWorkFactor`/`SetMaxWorkFactor` explicitly
instead of accepting its higher default decryption cap (see the
[upstream scrypt implementation](https://github.com/FiloSottile/age/blob/main/scrypt.go)).
Without an application limit, an unexpectedly expensive or maliciously modified
identity file could consume substantial memory and time during unlocking.

A-02 must verify these APIs against the pinned release. Context cancellation must
prevent new work and result release, but upstream scrypt is not interruptible
mid-call; the library must not promise immediate KDF cancellation. Owned mutable
buffers must be cleared on all exits. Age objects, Go strings and parser allocations
cannot be reliably erased. sshx must not cache unlocked identities/signers;
caller-supplied identity lifetime remains the caller's responsibility.

### 4. Trust and achievable recipient checks

- The caller must supply a local trust store keyed by store ID, with accepted
  canonical policy bytes/digest. It must remain outside the shared repository,
  with atomic updates protected by local ownership/access rules. The public API does not choose XDG
  paths. A copied store with the same ID shares that trust identity by design.
- First use is untrusted. Inspection can show bounded validated public policy
  without decrypting secrets; explicit acceptance follows caller review. `Init`
  also returns a policy review for explicit acceptance; no trust-on-first-use.
- Normal list/read/write/sign operations require the exact accepted policy digest.
  A different configured store ID cannot satisfy a registered reference. Agent
  operations never accept policy or prompt for trust.
- Acceptance records the reviewed store ID and digest and rechecks them at commit,
  preventing review/accept races. Local trust changes are serialized and rechecked
  during store publication/sign completion; no accidental acceptance of a newer
  policy. Trust is not signed authorship or protection from same-user tampering.
- `Check` verifies hashes, authenticated bindings, rule placement and recorded
  effective-recipient digests. Age X25519 stanzas do **not** reveal a complete
  verifiable public-recipient inventory. The report must describe recipient
  coverage as **not independently provable**, not “all recipients verified.”
- Conforming writers build recipients from the accepted policy; administrator
  policy apply freshly encrypts affected data. A malicious authorized writer can
  still produce ciphertext with a false recipient claim. Stronger provenance
  would require a separate signed-write design, outside v1.

### 5. Mutations, migrations and read safety

- Local writers must acquire an exclusive lock and fail immediately if busy,
  following ADR-0001. Unlocking, interaction and preparation occur before exclusive
  publication. Writers must recheck the starting manifest/trust and reject
  conflicts rather than retry.
- Writers must stage and sync immutable objects, validate the complete replacement,
  then atomically publish and sync the manifest. Results must distinguish unchanged,
  published and published-but-durability-uncertain outcomes, including errors after
  replacement. Interrupted staging must leave the previous snapshot usable and
  report orphaned objects.
- Members may add/replace/delete only in accessible matching groups. Writers must
  preserve inaccessible group references and must not interpret an undecryptable
  catalog as empty. Exact reads use `{StoreID, EntryID}`; logical-path lookup is separate.
- Policy application requires current administrator possession and successful
  complete discovery. Every path must be evaluated under the proposed rules;
  unmatched paths or corrupt objects must abort the operation. Migration must
  preserve entry IDs and freshly encrypt objects whose group/recipient binding
  changes, while preserving unaffected objects. Administrator changes affect all
  recipient unions. Policy and catalogs must be published through one manifest.
- Local trust and shared manifest cannot be atomically committed together. Policy
  apply publishes the store but does not silently accept the new local policy:
  the operation must return its review and require explicit acceptance. Ordinary
  operations must fail closed until acceptance. A post-publication local failure never rolls back the shared store.
- **Confirmed refinement of the age feature plan:** deletion must remove catalog
  references atomically and defer physical removal of superseded objects in v1.
  Snapshots can read immutable old objects without lifetime locks or blocking
  prompt time. Version 1 excludes online garbage collection; manual cleanup
  requires offline/quiescent use. Reports must distinguish orphans from corruption,
  and cleanup must not automatically delete another operation's staged objects.
  Git history remains separately accessible.
- Snapshot records exact manifest bytes/hash, opened-object identity and accepted
  policy digest. Reads verify referenced hashes/bindings and recheck snapshot
  before returning. Changed manifest/trust yields a stale-snapshot error.
- A short shared completion gate excludes conforming manifest/trust publishers
  while snapshot validity is checked and a noninteractive completion callback
  runs. Agent authorizes first, loads/decrypts fresh material, separately obtains
  any inner SSH-key passphrase, then signs and performs final registry/store
  checks under that gate. The agent must not prompt while holding it and must
  discard the signature if a relevant change is detected.
  This defines a completion linearization point, not a promise that no policy can
  change after completion or before network delivery. Noncooperating same-user
  edits retain the ADR-0001 limitations.

### 6. Public API sketch and second consumer

Names are provisional, not compiled declarations. `Access` holds explicit identity
sources and an operation-local `UnlockFunc`; nil callback never prompts. Trust
storage is injected through a small compare-and-update abstraction whose rules
are specified above; it participates in the completion/publication gate.

```go
func Open(ctx context.Context, root string, opts Options) (*Store, error)
func Init(ctx context.Context, root string, policy Policy, opts Options) (*Store, MutationResult, PolicyReview, error)
func GenerateIdentity(ctx context.Context, opts IdentityOptions) ([]byte, string, error)
func (s *Store) InspectPolicy(ctx context.Context) (PolicyReview, error)
func (s *Store) AcceptPolicy(ctx context.Context, review PolicyReview) error
func (s *Store) Snapshot(ctx context.Context) (*Snapshot, error)
func (s *Snapshot) List(ctx context.Context, access Access) (Listing, error)
func (s *Snapshot) ResolvePath(ctx context.Context, path string, access Access) (Ref, error)
func (s *Snapshot) Read(ctx context.Context, ref Ref, access Access) ([]byte, error)
func (s *Snapshot) Complete(ctx context.Context, use func() error) error
func (s *Store) Put(ctx context.Context, entry Entry, data []byte, access Access, replace bool) (MutationResult, error)
func (s *Store) Delete(ctx context.Context, ref Ref, access Access) (MutationResult, error)
func (s *Store) ApplyPolicy(ctx context.Context, next Policy, access Access) (MutationResult, PolicyReview, error)
func (s *Store) Check(ctx context.Context, access Access) (CheckReport, error)
```

`Init` receives the same trust/gate options as `Open` and reports publication
outcomes even if final sync fails. `Listing` contains accessible entries and an
inaccessible-group count; partial accessibility is not an error or a synthetic
entry. `Open`/`Snapshot` retain no unlocked identities. `Read` returns caller-owned bytes
which the caller clears; mutations borrow input only until return. Unlock callbacks
transfer owned mutable passphrase bytes to the library for clearing. Returned
metadata is a detached copy. Snapshots are immutable, methods hold no lifetime
locks, and concurrency obeys bounded KDF/publication gates.

Errors support `errors.Is`: invalid format/version/path, oversized, untrusted
policy, locked/noninteractive, inaccessible/not found, administrator required,
busy, conflict/stale snapshot, integrity and I/O. The library must preserve context errors; public
messages exclude plaintext, identity text, passphrases and raw dependency errors.
Listing must report inaccessible-group counts without entry names and distinguish
inaccessibility from corruption where cryptographic evidence permits it.

An independent consumer imports only the public package:

```go
import "github.com/jfardello/sshx/agestore"

// Illustrative method calls; setup/error handling omitted, not runnable code.
store, _ := agestore.Open(ctx, absoluteStore, optionsWithLocalTrust)
snap, _ := store.Snapshot(ctx)
ref, _ := snap.ResolvePath(ctx, "production/database", access)
secret, _ := snap.Read(ctx, ref, access)
defer clear(secret)
// Consumer handles its own UI/type semantics and must handle every error.
```

A-02/A-09 must add a compiling separate-module consumer for init/trust/put/list/read/
replace/delete and an import-boundary check. Future extraction changes the module
path in imports and relocates self-contained filesystem code; it must not require
copying sshx agent/CLI packages or converting stores.

## Threat / validation matrix

| Threat or behavior | Required evidence in implementation issues |
| --- | --- |
| Unauthorized disclosure | Alice/Bob/admin versus Carol; no inaccessible metadata; Git-visible secret scan |
| Substitution/corruption | Swapped payloads/catalogs, tampered metadata/hash, truncation and unsupported format fail |
| Policy redirection/admin spoof | First-use/changed policy blocks; review race denied; member decryption/public admin key cannot authorize apply |
| Recipient claims | Check explicitly distinguishes binding consistency from unprovable complete recipient coverage |
| Resource abuse | Every byte/count/KDF bound, excess identity attempts, canceled results and buffer ownership tested |
| Migration/crash/concurrency | Rule/admin moves preserve IDs; inaccessible groups preserved; stage/manifest failure injection; concurrent delete leaves old objects readable but stale snapshot rejected |
| Agent completion | Manifest/trust changes discard pending signatures; no secret access on listing; no prompts under completion gate or caching |
| External reuse | Separate consumer compiles without sshx internals; unknown entry types preserved; module relocation does not change format |

## Consequences and confirmed choices

The library is reusable without coupling future tools to SSH. Strict limits and
fresh unlocks trade capacity/latency for bounded risk. Deferred cleanup increases
repository size; signatures/writer provenance and historical revocation remain out
of scope. This ADR defines planned tests, not executed runtime evidence.

User-confirmed choices:

1. The library should initially be a **public package in the current module**, not
   a separately versioned module.
2. Version 1 must **defer physical object cleanup**, replacing immediate deletion
   with reference removal and offline cleanup.
3. Check output must state that **complete recipient coverage is not independently
   provable**. Signed writes/administrator signatures remain outside v1.
4. Protected identities must use **scrypt logN 18 with a maximum accepted factor of
   18**; stronger imported identities must fail rather than consume more memory.
