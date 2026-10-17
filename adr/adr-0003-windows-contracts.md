# ADR-0003: Native Windows platform and client contracts

- **Status:** Draft — proposed, not implemented or accepted
- **Date:** 2026-10-09
- **Issue:** [#60](https://github.com/jfardello/sshx/issues/60) (W-01), parent [#59](https://github.com/jfardello/sshx/issues/59)
- **Scope:** Windows design/feasibility portion of W-01; compilation isolation, CI and native experiments remain pending review.

## Context

This ADR defines proposed native Windows platform and client contracts for Windows
11 and Server 2022/2025 amd64 with native OpenSSH. It seeks to settle platform
boundaries, security and compatibility expectations, and the storage, logon-session
and launcher recommendations before implementation, without weakening Unix behavior
or [ADR-0001](adr-0001-secure-updates.md)/[ADR-0002](adr-0002-age-store.md).
Compilation is not proof of terminal behavior, pipe security or client capability.
No Windows release is promised by this draft.

Within this proposal, must denotes a requirement, should a recommendation, and may
an option. These terms do not imply acceptance or implementation of this draft.

| Existing seam | Platform dependency / required split |
| --- | --- |
| `internal/pty/pty.go` | Unix PTY, signals/process groups, repeated EOT injection; session mechanics must be separate from bounded one-time password detection |
| `internal/agent/agent_server.go`, `endpoint.go` | Concrete Unix listener/connection, UID/mode/stat traversal and socket cleanup; authenticated endpoint ownership must be separate from protocol |
| `agent_registry.go`, `agent_mutation_state.go`, `internal/config/config.go` | Descriptor-relative access/locks/rename or nonblocking file open; Windows operations must provide handle/access checks without relaxing domain validation |
| `internal/agent/agent_confirm.go` | Executable UID/mode trust, curated Unix environment, process-group cancellation; trusted launching and private-pipe lifecycle must be isolated |
| `internal/credential/gopass/gopass.go` | `Setpgid`/`Kill`, PATH discovery and noninteractive provider environment; owned executable processes must be isolated |
| `internal/cli/agent.go`, `agent_systemd.go` | Unix runtime paths, signals, sh/zsh output and Linux systemctl; platform lifecycle and environment formatting must be separate |
| `internal/cli/command.go:isRemoteOperand` | Any interior colon means remote; drive-letter operands must have explicit local classification |
| `.github/workflows/pr.yml`, `.goreleaser.yaml` | Linux amd64/macOS arm64 only; archive inspection expects two tarballs |

## Proposed decision

### 1. Shared behavior and platform boundaries

- SSH-agent framing, authorization, key validation, confirmation, registry reload,
  cache eligibility and suppression/lock semantics must remain shared. Endpoint
  code must supply deadline-capable connections and bounded cancellable accept/dial;
  shared APIs must not expose Unix listeners/stat structures.
- Platform code must use small OS-specific operations for secure storage, endpoint
  creation/probing, process ownership, terminal access and lifecycle. Windows
  implementations must use `golang.org/x/sys/windows`; any required narrow Win32
  wrappers must undergo review. This work must not introduce a broad rewrite or new
  framework, or an additional dependency without justification.
- Platform isolation must preserve Unix paths, permissions, process behavior,
  release targets and tests. Build constraints must split actual OS-dependent seams,
  including tests. Compile-only Windows stubs must return actionable unsupported
  errors, never success or fallback signing. Shared security tests must not be
  disabled to make builds pass.
- Age must own extraction-ready filesystem code inside its public package and
  follow equivalent contracts, but must not import sshx's internal platform utilities.

### 2. Paths, trusted files and update outcomes

- Windows config/registry/state/trust paths must default to `%LOCALAPPDATA%\sshx`
  and honor absolute XDG config/state overrides individually. Path resolution must
  use Windows known-folder APIs where possible, reject ambiguous
  relative/root-relative/drive-relative overrides, and expose resolved paths through
  config commands.
- Path handling must keep slash-separated logical credential paths distinct from
  OS paths and recognize `C:\...`/`C:/...` as local SCP operands. Argument handling
  must preserve direct argv boundaries and current `-x` splitting, and must never
  reinterpret an argument through a shell.
- **Protected files should use local storage only in v1 (unconfirmed).** Under this
  recommendation, registry/state/trust/identity/helper paths and store mutations
  must reject UNC/network paths until remote locking/durability/security semantics
  are validated. Ordinary SCP local operands may be UNC paths. Storage validation
  must not silently treat a remote drive as trusted local storage.
- Trusted-file checks must validate opened handles, owner SID, DACL and file identity,
  and reject untrusted write/delete/ownership/permission-changing access,
  null/permissive DACLs, substituted reparse points and multiply linked writer
  targets. Trusted system ancestors may be controlled by
  SYSTEM/Administrators/TrustedInstaller; unrelated ordinary users must not be able
  to modify them. Privileged administrators are outside the threat boundary, not
  something restrictive ACLs can defeat.
- Config readers must retain promised symlink compatibility; protected writers and
  identity/helper checks must remain stricter. New private files/directories must
  receive explicit restrictive ACLs, not permissions inferred from Unix mode arguments.
- Protected updates must use Windows locks and same-volume atomic publication with
  verified replacement ACLs, file flushing and object/path revalidation. Busy edits
  must fail immediately. Sharing violations must fail without permission broadening
  or unbounded retries. Update outcomes must distinguish pre-publication failure
  from published/durability-uncertain results. #61 must define supported filesystem
  guarantees rather than assuming Unix fsync has a direct equivalent. Age must
  retain deferred ciphertext cleanup from ADR-0002.

### 3. Named-pipe agent identity and client compatibility

- The agent must use an sshx-specific pipe, never `openssh-ssh-agent`: proposed form
  `\\.\pipe\sshx-<user-token>-<logon-token>`. Tokens must be stable short hashes of
  the current user SID/logon SID, not secrets or authorization evidence. Endpoint
  length must remain within client limits. CLI env/status must target its own logon
  session; an explicit endpoint must not bypass identity validation.
- **Pipes should use logon-session isolation, not just user isolation (unconfirmed).**
  Under this recommendation, an explicit DACL must grant access to the current
  logon SID, reject remote clients, and not grant blanket access to the user's other
  sessions. Account SID alone is too broad.
- The server must create the first instance with first-instance protection and must
  not adopt an occupied name. It must retain owned handles and close only owned
  instances. Limits, deadlines, cancellation and disconnect cleanup must remain enforced.
- Before serving requests, the server must identify the client token/logon SID using
  pipe APIs and revert any impersonation immediately. sshx probes must validate the
  server's process/token/logon identity and trusted executable image using live
  handles; PID alone is not enough. A status List probe proves endpoint/protocol
  readiness, not provider readiness. Clients must not be asked to grant server
  impersonation privileges.
- Windows OpenSSH source at commit
  [`e302fe1`](https://github.com/PowerShell/openssh-portable/tree/e302fe1ed190e408573cf0139252e5db26eeba2f)
  reads the agent environment in `authfd.c` and maps AF_UNIX connection to a named
  pipe in `w32fd.c`/`fileio.c`. This is **source evidence**, not a tested shipped
  client/version guarantee; exact `IdentityAgent` behavior remains a native test.
- That source opens pipes with `GENERIC_READ | GENERIC_WRITE`. Windows generic
  write includes `FILE_CREATE_PIPE_INSTANCE`; a least-rights DACL omitting that
  right may reject these clients. Native tests must evaluate the necessary grant
  restricted to the logon SID, and the server must retain first-instance checks.
  Compatibility documentation must state that malicious same-logon processes cannot
  be excluded by ACLs and must not promise custom server authentication by unmodified
  OpenSSH clients; sshx probes are a separate security check.
- Client compatibility must not downgrade destination/session-binding/hostbound
  requirements if a client lacks them. Constrained operations must fail closed.
  Unrestricted-local use must remain explicitly opt-in; forwarding must remain off
  by default. Supported client versions must be published only after real
  ssh/ssh-add/SCP and negative-policy tests.
- CLI environment output must add escaped PowerShell/cmd formats alongside existing
  Unix formats. Native clients must use the documented pipe endpoint via
  SSH_AUTH_SOCK/IdentityAgent as actually tested. Windows support must not bridge
  WSL/Git Bash sockets or alter Microsoft's service.

### 4. Process, terminal and provider ownership

- Process launching must resolve native exe paths once and launch directly with
  correct Windows quoting, without cmd/PowerShell intermediaries or current-directory
  executable lookup. Helpers must remain explicit absolute trusted executables and
  receive no secret-bearing args.
- Process ownership code must create owned processes suspended where necessary,
  attach Job Objects before execution, then resume. Inherited handles must be limited
  to explicit private pipes or pseudoconsole resources. Bounded cancellation must
  close blocked I/O and kill only owned process trees; it must never terminate
  shared/preexisting GPG agents.
- Environment handling must curate names case-insensitively and supply required
  native execution variables such as SystemRoot/WINDIR and validated TEMP/TMP, plus
  only documented provider/user variables. Provider PATH may be a controlled
  executable search path; helper PATH need not inherit arbitrary entries. Helpers
  must not receive provider secrets, loader injection variables or SSH agent sockets.
- ConPTY must use explicit pseudoconsole/pipe/process-attribute ownership and
  concurrent output draining. Console handling must restore modes on every exit;
  native tests must define redirected input, EOF, resize and Ctrl+C behavior. Windows
  terminal handling must not copy Unix EOT or signal conventions. Unsupported
  console/OpenSSH prerequisites must fail actionably.
- Terminal selection must use current console handles, preserve redirected stdin,
  and relinquish all readers before SSH. GUI helpers must use only the current
  interactive desktop; GUI operations in headless/Core sessions must fail closed.
- Native gopass plus GPG and age are the v1 backends. Explicit Secret Service is
  unavailable; auto must remain gopass, never age. Existing native gopass/GPG key-read
  restrictions must remain noninteractive. Candidate test baseline: gopass **1.17.3**
  (release observed during review) and a native **GnuPG 2.4.x** build; compatibility
  evidence must record the exact GPG version/distribution before claiming support.

### 5. Console packaging and scheduled lifecycle

- `sshx.exe` must remain console-subsystem for normal CLI diagnostics, foreground
  serving and command-scoped sessions. A runtime flag cannot change the PE subsystem.
- **Scheduled startup should use a small GUI-subsystem `sshx-agent-launcher.exe`
  (unconfirmed).** Under this recommendation, the launcher must start the same console
  executable in a private managed-agent role using `CREATE_NO_WINDOW`, supervise its
  owned Job and remain alive until worker exit. This avoids promising that Task
  Scheduler will suppress a console window for a directly launched console executable.
  It is an explicit refinement of the source plan's same-executable-only startup
  assumption, not a second agent engine.
- The proposed launcher must perform no credential work and must use a bounded
  private readiness/error channel; process creation alone is not readiness.
  Failed/partial startup must clean up its worker. Managed diagnostics must be bounded
  and sanitized, never raw secrets. The separate Zenity helper must remain as planned;
  the launcher must not introduce self-hosted prompt dispatch.
- Task Scheduler integration must use explicit per-user installation, interactive
  token, least privilege and no stored password. It must verify task owner/action and
  trusted executable paths before changing the task, without untrusted shell scripts.
  Status must report task state and authenticated pipe readiness. Stop must terminate
  only the owned task/worker; uninstall must preserve credentials, registry and
  lock/suppression state.
- One lifetime lock must protect the default state ledger across user sessions. A
  second logon must fail clearly rather than share mutable state; explicit separate
  ledgers must remain available. Windows must reject systemd/activation options.
- The eventual Windows zip must contain the main exe, launcher, Zenity helper, docs
  and checksums, with CGO disabled. #66 must update build IDs/archive assertions only
  after the launcher decision and runtime prerequisites are validated.

## Feasibility evidence and remaining acceptance

Review host: **Linux amd64, Go 1.26.6**, 2026-10-09. Baseline command:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/sshx-w01-baseline.exe ./cmd/sshx
```

**Failed as expected:** gopass/helper `Setpgid`/`syscall.Kill`, PTY `SIGWINCH`, agent
`unix.Stat_t`/`Openat` and other Unix symbols. This is evidence of needed isolation,
not a completed Windows compilation gate. CGO-free Linux amd64 and macOS arm64
builds passed on the review host; Unix unit tests were not run for this document-only
change. No native Windows versions were tested.

| Gate | Required evidence / current status |
| --- | --- |
| Platform isolation + CI (#60) | Pending: platform isolation must split actual Unix seams and add explicit unsupported Windows paths; CI must provide a green CGO-free amd64 build job and preserve Linux/macOS builds and Unix unit tests |
| Windows 11 / Server 2022 / Server 2025 | Native runs pending; evidence must record exact OS build and OpenSSH executable paths/versions for each, not just OS marketing names |
| Pipe compatibility (#64) | Native tests must cover SSH_AUTH_SOCK, IdentityAgent, ssh-add, generic-access DACL, session binding, destination/hostbound/forwarding failures, cross-session denial and squatting |
| Filesystem/process (#61/#62) | Native evidence must cover ACL/reparse/lock/replace/durability, Job/handle inheritance, parent termination, provider versions and no secret leaks |
| Console/startup (#63/#65) | Native evidence must cover ConPTY and redirected input, no-window launcher/task logon, readiness, desktop/helper availability and duplicate ledgers |
| Release acceptance (#66/#67) | Acceptance must include native CI and a manual interactive matrix, archive/checksum checks and Server Core headless scope; skipped tests must never count as passes |

CI must not add a permanently red compile job or suppress its errors, and this ADR
must not be treated as closing #60. The mandatory job must be added once minimal
platform isolation makes it pass; that implementation slice must follow design
review. This ADR makes no GitHub issue status changes.

## Consequences and review questions

Native support requires security-sensitive Win32 work beyond terminal transport.
Explicit platform contracts preserve Unix behavior; a launcher adds one artifact
but avoids changing normal CLI console semantics. Desktop/logon support does not
imply service hosting, Credential Manager, ARM64 or WSL support.

Recommendations to confirm:

1. **Scheduled startup should use the GUI-only launcher**, while `sshx.exe` remains
   console-based.
2. **Protected storage/mutations should be limited to local filesystems in v1**;
   ordinary SCP local operands may use UNC paths, but protected UNC/network stores
   would remain deferred.
3. **Pipes should be isolated by interactive logon session**, with one owner for the
   default persistent ledger and explicit separate ledgers for additional sessions.

## References

- [Windows named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights): default ACL exposure, generic-write instance rights and logon SID isolation.
- [Windows process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags): CREATE_NO_WINDOW and incompatible combinations.
- [Windows OpenSSH fileio source](https://github.com/PowerShell/openssh-portable/blob/e302fe1ed190e408573cf0139252e5db26eeba2f/contrib/win32/win32compat/fileio.c): named-pipe connection access and identification-level security QoS.
