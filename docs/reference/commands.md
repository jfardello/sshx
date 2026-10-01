# Command reference

## Password SSH and SCP

```text
sshx <credential> [sshx options] [remote_command]
sshx ssh <credential> [sshx options] [remote_command]
sshx scp <credential> [sshx options] <source> <destination>
sshx credentials list [query] [credential options]
```

| Option | Default | Scope |
| --- | --- | --- |
| `--credential-backend auto\|secret-service\|gopass` | `auto` | Password connections and discovery |
| `--secret-collection <label-or-alias>` | Empty | Secret Service password scope |
| `--gopass-prefix <path>` | Empty | Direct gopass scope; selects gopass in auto mode |
| `--verbose[=true\|false]` | `false` | Password connection diagnostics |
| `-x`, `--options <string>` | Empty | OpenSSH options inserted before the target |

[Configuration](../configuration.md) defines YAML defaults, explicit CLI
precedence, empty overrides, parsing and conflict handling. The full `options`
string is replaced by a CLI occurrence; repeated CLI occurrences concatenate.
A credential named after a subcommand can be selected through explicit `ssh`,
for example `sshx ssh agent`.

## Agent lifecycle

| Command | Purpose | Command-specific options |
| --- | --- | --- |
| `agent start --foreground` | Serve until interrupted | `--socket`, `--socket-activation` |
| `agent run -- command [args...]` | Own an agent for one child command | Child arguments after `--` |
| `agent env` | Emit validated shell environment | `--socket`, `--systemd`, `--shell sh\|zsh` |
| `agent status` | Inspect endpoint or managed unit state | `--socket`, `--systemd` |
| `agent stop --systemd` | Stop socket, then service | `--systemd` |
| `agent reset-state` | Clear lock/suppression while stopped | Shared `--state-file` selection |

The following flags configure an agent started by `start` or `run`. They do not
reconfigure another running process and are not fields in `config.yaml`.

| Flag | Default | Effect |
| --- | --- | --- |
| `--verbose` | `false` | Fixed-category diagnostics on stderr |
| `--prompt-helper <absolute-path>` | None | Local approval and key-passphrase helper |
| `--cache-ttl <duration>` | `0` | Backend signer cache; maximum `5m` |
| `--allow-key-mutations` | `false` | Volatile ssh-add imports, removal and locking |
| `--allow-forwarding` | `false` | Verified destination-constrained forwarding |
| `--state-file <absolute-path>` | XDG state path | Durable lock/suppression domain |

`--state-file` also selects the ledger for offline reset. Flags for `agent run`
belong before `--`; flags after it belong to the child. Linux socket activation
requires `--foreground --socket-activation` and a valid inherited listener.
[Lifecycle](../agent/running.md) documents shutdown and socket ownership.

## Native OpenSSH tools

`SSH_AUTH_SOCK` allows ordinary `ssh`, `scp`, Git and `ssh-add` to reach the agent.
[ssh-add compatibility](../agent/ssh-add.md) lists supported operations and limits.
`ssh-add` imports are separate from [registration](../agent/registration.md).
