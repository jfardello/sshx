# Troubleshooting

Failures should be separated into credential discovery, SSH transport, agent
authorization, and private-key retrieval. A visible identity alone does not prove
that its provider can decrypt the key.

## Password discovery

```sh
sshx credentials list
sshx credentials list alice --credential-backend gopass
sshx ssh alice@server.example --verbose
```

Ambiguous matches require a more specific path, label, or collection. Unexpected
backend selection can result from YAML defaults or a nonempty gopass prefix.
[Configuration](configuration.md) describes explicit empty overrides. A reached
Secret Service provider does not fall back to gopass after a lookup or unlock error.

## Agent refusal

```sh
sshx agent run --verbose -- ssh -vvv -o IdentitiesOnly=yes \
  -o PreferredAuthentications=publickey \
  -i "$HOME/.ssh/id_ed25519.pub" alice@server.example
```

Ordinary `sshx agent run -- ssh alice@server.example` discovers registered keys
without these identity options. The command above selects one matching public
key explicitly and limits authentication to public keys. This helps when
`IdentitiesOnly yes` is configured or many offered keys exhaust the server's
authentication attempts. The `-i` file contains only the public key; the agent
provides the private-key signature. `-vvv` enables OpenSSH diagnostics.

Agent `--verbose` belongs before `--` and is independent of YAML verbosity.
It reports fixed categories for registry, binding, policy, backend, validation,
cache and signing stages. Private keys, passphrases, provider stderr and raw
backend errors are excluded. Child OpenSSH diagnostics are separate.

| Symptom | Checks |
| --- | --- |
| Empty `ssh-add -l` | Missing/disabled registry, lock/suppression, or an unbound destination-constrained identity |
| Policy rejection | User key, trusted host pins, destination username, session binding and required edges |
| Backend failure after authorization | Exact key reference, collection alias, provider availability and noninteractive decryption |
| Key validation failure | Complete supported key payload matching the registered public key |
| State file busy | Another agent owns that ledger; an independent instance needs a different state path |
| Correct unlock password refused | Persistent failed-unlock cooldown has not elapsed |
| Removed key remains absent after restart | Suppression persists; stopped-agent `reset-state` explicitly clears it |
| Forwarded signing refused | Agent opt-in, constrained identity, all edges, and hostbound final authentication |

## Systemd differs from a terminal

```sh
sshx agent status --systemd
systemctl --user show sshx-agent.service -p ExecStart -p Environment
journalctl --user -u sshx-agent.service -f
```

An `ExecStart` override can add `--verbose` while preserving the actual installed
path and other flags. Changes require `systemctl --user daemon-reload` followed by
`systemctl --user restart sshx-agent.service`.

The manager's environment may select another configuration location or omit
paths needed by gopass/GPG. A running socket proves readiness for activation,
not successful signing. A missing registry can produce an empty list without
an explicit startup error. [Agent lifecycle](agent/running.md) explains socket paths.

## Local helper unavailable

The optional Tk helper requires `/usr/bin/python3`, Python Tk support, a trusted
absolute executable path, and appropriate desktop variables such as `DISPLAY`
and, when required, `XAUTHORITY`. The systemd service must have that routing.

No display, absent Tk, cancellation, helper failure or a timed-out operation
causes denial. There is no terminal-prompt fallback. OpenSSH-key passphrase entry
cannot unlock the provider's GPG keyring or desktop collection.
[Confirmation](agent/confirmation.md) describes these separate operations.

## Socket and file trust errors

Registry, helper, state and runtime paths have ownership and ancestor checks.
Symlinks accepted for password `config.yaml` are not generally accepted for agent
security-sensitive paths. Permissions should be corrected only for the intended
files; broad home-directory permission changes are unnecessary.

An existing standalone socket is never overwritten automatically. A stale file
can be removed only after its owning process has been confirmed absent. A
systemd-owned endpoint should be managed through its socket unit.
