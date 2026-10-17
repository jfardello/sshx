# Roadmap

Registration and configuration are available through the usage guides below.
The remaining features are planned; scope and interfaces may change, and no
release dates are committed.

## Key registration and configuration management

See [key registration](../agent/registration.md) and
[configuration management](../configuration.md) for the implemented commands and
their current contracts.

## Desktop helper and password selection

- Add an optional Go Zenity helper for signing approval and masked passphrase
  entry, preserving the existing Tk helper and agent protocol.
- Add opt-in terminal or desktop credential selection for password SSH and its
  shorthand. Default behavior, SCP, and credential listing remain unchanged.
- Select from scoped metadata before retrieving one secret; preserve terminal
  ownership, redirected input, cancellation, and SSH exit status.
- Keep helpers explicitly configured, requests bounded, and failures default-deny.
  Desktop selection uses a separate protocol and still needs a terminal for SSH.
- Clarify “shell mode” before implementation: the draft proposes a numbered
  terminal selector, not a persistent command interpreter. The helper can proceed
  independently; desktop dependencies require real session testing.

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
