# Configuration

## Configuration boundaries

| Mechanism | Scope |
| --- | --- |
| `config.yaml` | Password-command defaults and optional `agent` defaults |
| `agent.json` | Public keys, exact backend references, and per-key policies |
| `sshx agent` flags | Agent lifecycle, helper, caching, mutations, forwarding |
| `agent-state.json` | Machine-managed agent lock and suppression ledger |
| OpenSSH configuration | SSH destinations, transport, and client behavior |

Agent defaults use a separate `agent` mapping. See [registration](agent/registration.md),
[agent commands](reference/commands.md), and [persistent state](agent/ssh-add.md).

## File location and precedence

Command defaults belong in `~/.config/sshx/config.yaml`. If `XDG_CONFIG_HOME`
is an absolute path, sshx reads `$XDG_CONFIG_HOME/sshx/config.yaml` instead.
An empty or relative `XDG_CONFIG_HOME` uses the home-directory fallback.

Precedence is **built-in defaults < configuration file < explicit CLI options**.
A missing or empty file preserves the built-in defaults. sshx reads the file
once per applicable invocation and does not create or modify it. Changes affect
future invocations, not running agents.

## Password-command defaults

```yaml
secret-collection: Login
options: "-o ConnectTimeout=10 -o ServerAliveInterval=30"
```

An alternative configuration for direct gopass is:

```yaml
credential-backend: gopass
gopass-prefix: infrastructure/production
verbose: true
```

| YAML key | CLI option | Default |
| --- | --- | --- |
| `credential-backend` | `--credential-backend` | `auto` |
| `secret-collection` | `--secret-collection` | Empty (unscoped) |
| `gopass-prefix` | `--gopass-prefix` | Empty (unscoped) |
| `verbose` | `--verbose` | `false` |
| `options` | `-x`, `--options` | Empty |

All five fields apply to shorthand SSH, explicit `ssh`, and `scp` commands.
`credentials list` uses the three credential defaults; it ignores valid
`verbose` and `options` fields. Targets, queries, remote commands and copy
operands remain CLI arguments.

The same CLI options override file values, including explicit false or empty
values:

```sh
sshx alice@server.example --verbose=false
sshx alice@server.example --secret-collection Work
sshx alice@server.example --gopass-prefix ""
sshx alice@server.example -x ""
```

The recognized long options also accept `--name=value`. Bare `--verbose`
means true; `--verbose=false` disables it. An explicit empty scope value
clears a file default, while a missing flag argument is still an error.
Duplicate backend/scope flags are rejected even when their values are empty.

A CLI `-x` or `--options` **replaces the complete configured options string**.
Repeated CLI occurrences concatenate in order. Option strings use whitespace
splitting; YAML quotes do not introduce shell quoting or expansion
inside the string. Unknown arguments and everything after `--` retain the
existing pass-through behavior. Native OpenSSH options outside `-x` follow
OpenSSH's own precedence; `-x` provides deterministic replacement of file defaults.

The shared `options` value must suit both SSH and SCP. Command-specific options
such as `ssh -p` or `scp -P` belong in CLI `-x` values or OpenSSH host configuration.

Backend/scope conflicts are checked after merging. Switching a configured
Secret Service collection to gopass requires clearing the collection explicitly:

```sh
sshx alice@server.example --credential-backend gopass \
  --secret-collection "" --gopass-prefix infrastructure/production
```

`auto` with a nonempty gopass prefix still selects gopass. To restore automatic
backend selection, that prefix must also be cleared. Conflict errors identify
whether the
fields came from the CLI, file, or built-in defaults.

## Agent defaults

```yaml
agent:
  cache-ttl: 1m
  prompt-helper: /home/alice/.local/bin/sshx-helper
  verbose: false
```

| Agent YAML key | CLI option | Default |
| --- | --- | --- |
| `verbose` | `--verbose` | `false` |
| `cache-ttl` | `--cache-ttl` | `0s` (disabled); maximum `5m` |
| `prompt-helper` | `--prompt-helper` | Empty (no helper) |
| `allow-forwarding` | `--allow-forwarding` | `false` |
| `allow-key-mutations` | `--allow-key-mutations` | `false` |
| `socket` | `--socket` | Empty (platform/mode default) |
| `state-file` | `--state-file` | Empty (default state ledger) |

`agent start` and `agent run` use agent defaults, independently of the flat
password-command settings. `start`, `env`, and endpoint `status` use the configured
socket; `run` always creates a private temporary socket. `reset-state` uses the
configured state file. `status --systemd` inspects units without using the socket
setting; `stop` does not load config.

Explicit `--verbose=false`, `--cache-ttl=0s`, or `--prompt-helper=""` clears the
corresponding file default. Empty `--socket` and `--state-file` select the built-in
paths. Nonempty paths must be absolute, clean, and contain no control characters;
sshx does not expand `~` or environment variables. Runtime ownership, permissions,
symlink, and helper-executable checks still apply when those paths are used.
Foreground mode, socket activation, systemd selection, shell syntax, and child
arguments remain invocation-only; they must not appear in YAML.

## Validation and security

The file must be one YAML mapping, at most 64 KiB. Only the documented keys and
the `agent` mapping are accepted. Boolean values must be `true` or `false`;
`cache-ttl` must be a duration string, and other scalar settings must be strings.
Unknown/duplicate keys at either level, nulls, aliases, unsupported nesting,
multiple documents, invalid backends, unsafe gopass paths, and invalid agent
settings are rejected, even if a CLI option would replace the invalid field.
File read or validation errors stop applicable commands before credential or
agent filesystem operations. Help and shell completion do not load the file.

Dotfiles symlinks to regular files are supported; dangling links and nonregular
files are errors. For a manually managed file, directory mode `0700` and file
mode `0600` are recommended. Only nonsecret defaults belong in this file.
Configured OpenSSH options have the same authority as options supplied on the
CLI. sshx does not search project directories for configuration.
