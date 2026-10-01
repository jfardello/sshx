# Roadmap

These features are planned, not implemented. Scope and interfaces may change;
no release dates are committed. Existing behavior is described in the usage guides.

## Key registration and configuration management

- Add `sshx agent register` to validate an existing stored key and write its public
  identity, exact backend reference, confirmation requirement, and policy.
- Support explicit replacement and optional enablement; default to disabled.
  Destination policies use trusted known_hosts pins, including hashed entries and
  nonstandard ports. Registration does not install remote authorized_keys.
- Add `sshx config` get/set/unset/list/path operations, shorthand key names,
  effective defaults, and comment-preserving YAML edits.
- Persist agent defaults alongside password settings, with explicit CLI overrides.
  Secure atomic updates preserve unrelated settings and agent lock/suppression state.

## Native age backend

- Add an explicitly selected Go age store for passwords and SSH keys, using X25519
  identities kept outside the store, with optional identity passphrase protection.
- Encrypt each entry separately and encrypt metadata catalogs by access group.
  Path rules select recipients; global administrators can access every group.
- Add store initialization, identity generation, add/replace/remove/list/check,
  policy application, and explicit acceptance of changed policy digests.
- Integrate password discovery, registration, and agent signing with stable store
  and entry IDs. Keep identity unlocking separate from SSH-key passphrase prompts;
  initially retain neither unlocked identities nor cached signers.
- Use atomic manifest snapshots and Git-friendly ciphertext. Recipient removal
  re-encrypts current data; historical access still requires credential rotation.

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

Registration/configuration precedes age integration. Each feature requires
isolated acceptance tests and existing-platform regression checks before release.
