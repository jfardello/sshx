# Roadmap

Registration and configuration are available through the usage guides below.
The remaining features are planned; scope and interfaces may change, and no
release dates are committed.

## Key registration and configuration management

See [key registration](../agent/registration.md) and
[configuration management](../configuration.md) for the implemented commands and
their current contracts.

## Desktop helper and password selection

The optional Go Zenity helper provides signing approval and masked passphrase
entry alongside the existing version-1 Tk helper; see
[local confirmation](../agent/confirmation.md). Its separate
[version-2 credential-selection protocol](../reference/credential-selection.md)
and list dialog are implemented. Password SSH and its shorthand also provide an
opt-in numbered [terminal picker](../password-authentication.md#choose-a-stored-credential)
with separate SSH UI/helper settings; desktop handoff remains planned.

- Connect desktop selection to exact-reference password SSH, preserving terminal
  requirements, cancellation, redirected input and SSH exit status.
- Keep helpers explicitly configured, requests bounded, and failures default-deny.
  Desktop selection uses a separate protocol and still needs a terminal for SSH.

## Native Windows support

- Target Windows 11 and Server 2022/2025 on AMD64 with native OpenSSH, gopass,
  and age as it becomes available. Secret Service remains unavailable.
- Add ConPTY password SSH/SCP, secure process-tree cleanup, Windows path handling,
  owner/DACL checks, file locking, and atomic replacement.
- Add a user/session-scoped named-pipe agent, PowerShell/cmd environment output,
  and explicit Task Scheduler logon startup with least privilege.
- Port registration/configuration and desktop interaction as those features land;
  ship Windows ZIP artifacts and validate real console, agent, and GUI behavior.
- Defer Credential Manager, ARM64, WSL interoperability, and Windows service hosting.

Age integration builds on existing registration/configuration. Each new feature requires
isolated acceptance tests and existing-platform regression checks before release.
