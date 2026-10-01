# Configuration

## Configuration boundaries

| Mechanism | Scope |
| --- | --- |
| `config.yaml` | Password SSH/SCP defaults and credential discovery |
| `agent.json` | Public keys, exact backend references, and per-key policies |
| `sshx agent` flags | Agent lifecycle, helper, caching, mutations, forwarding |
| `agent-state.json` | Machine-managed agent lock and suppression ledger |
| OpenSSH configuration | SSH destinations, transport, and client behavior |

Agent options are not YAML fields. See [registration](agent/registration.md),
[agent commands](reference/commands.md), and [persistent state](agent/ssh-add.md).

## Password-command defaults

Command defaults belong in `~/.config/sshx/config.yaml`. If `XDG_CONFIG_HOME`
is an absolute path, sshx reads `$XDG_CONFIG_HOME/sshx/config.yaml` instead.
An empty or relative `XDG_CONFIG_HOME` uses the home-directory fallback.

Precedence is **built-in defaults < configuration file < explicit CLI options**.
A missing or empty file preserves the built-in defaults. sshx reads the file
once per invocation and does not create or modify it.

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

The file must be one YAML mapping, at most 64 KiB. Only the keys above are
accepted, with string values except for the `true`/`false` boolean `verbose`.
Unknown/duplicate keys, nulls, aliases, nested values, multiple documents,
invalid backends and unsafe gopass paths are rejected, even if a CLI option
would replace the invalid field. File read errors stop the command before
credential access. Help and shell completion work without loading the file.

Dotfiles symlinks to regular files are supported; dangling links and nonregular
files are errors. For a manually managed file, directory mode `0700` and file
mode `0600` are recommended. Only nonsecret defaults belong in this file.
Configured OpenSSH options have the same authority as options supplied on the
CLI. sshx does not search project directories for configuration.
