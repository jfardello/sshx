# sshx

> [Gopass](https://www.gopass.pw) integration for SSH and SCP.

`sshx` runs OpenSSH with a password stored in
[gopass](https://www.gopass.pw/), without depending on `sshpass` or exposing
the password through command-line arguments or environment variables.

The `ssh` or `scp` process starts in a new session. Its stdin, stdout, and
stderr are connected to the slave side of a PTY, which is also its controlling
terminal. `sshx` connects the local terminal to the PTY master, tracks window
size changes, and writes the password when it detects an OpenSSH password
prompt. This design follows the model used by
[`clarkwang/passh`](https://github.com/clarkwang/passh).

## Requirements

- `gopass`, `ssh`, and `scp` available in `PATH`.
- A Unix system with PTY support.

## Install from a release

Download a release from [releases](releases/latest) and add to your `$PATH`.

Currently only linux AMD64 and darwin arm64 are being released. 


## Build manually

Manual builds require Go 1.24 or later. From the project root:

```sh
go test ./...
go build -o sshx .
```

Install the resulting binary somewhere in `PATH`, for example:

```sh
mkdir -p "${HOME}/.local/bin"
install -m 0755 sshx "${HOME}/.local/bin/sshx"
```

> [!NOTE]
> Many Unix-like systems should compile without problems, but check whether
> [gopass supports](https://github.com/gopasspw/gopass) the target platform.
> Windows is not supported for now.

## SSH usage

The original syntax remains supported:

```text
sshx <userhost|gopass/path> [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]
```

The explicit `ssh` subcommand is equivalent:

```text
sshx ssh <userhost|gopass/path> [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]
```

Examples:

```sh
sshx user@example.com
sshx ssh servers/user@example.com
sshx ssh user@example.com -x "-p 2222 -L 8080:localhost:8080"
sshx ssh user@example.com uptime
sshx ssh user@example.com --gopass-prefix infrastructure/production --verbose
```

Options supplied through `-x` are inserted before the host in the `ssh`
invocation. All remaining arguments are appended after the host.

## SCP usage

```text
sshx scp <userhost|gopass/path> [--gopass-prefix <path>] [--verbose] [-x '<scp opts>'] <source> <destination>
```

An operand beginning with `:` represents a path on the host resolved from the
credential:

```sh
# Upload
sshx scp user@example.com file.txt :/tmp/

# Download
sshx scp user@example.com :/var/log/app.log ./

# Use an explicit gopass path
sshx scp servers/production/user@example.com backup.tar.gz :/srv/backups/

# Recursive copy through an alternative port
sshx scp user@example.com -x "-r -P 2222" directory/ :/opt/app/
```

The remote host can also be written explicitly:

```sh
sshx scp user@example.com file.txt user@example.com:/tmp/
```

The first version supports local-to-remote and remote-to-local transfers.
Remote-to-remote copies are rejected because they may require two independent
credentials.

Remember that `scp` uses uppercase `-P` for its port option, while `ssh` uses
lowercase `-p`.

## Credential selection

By default, name lookup covers the complete configured gopass tree, including
its mounts. Use `--gopass-prefix` after the credential argument to restrict the
lookup to a logical gopass path:

```sh
sshx ssh user@example.com --gopass-prefix infrastructure/production
sshx scp user@example.com --gopass-prefix infrastructure/production file.txt :/tmp/
```

For name lookup, `sshx` obtains canonical entries with `gopass list --flat`,
optionally scoped to the prefix. It prefers exact relative-path or basename
matches and then falls back to case-insensitive partial matches. A single
result is selected automatically; multiple results are displayed so that an
explicit path can be chosen.

If the credential argument itself contains `/`, it is treated as an exact
gopass path and lookup is skipped. When a prefix is also present, it is
prepended to that explicit path:

```text
servers/user@example.com --gopass-prefix infrastructure/production
→ infrastructure/production/servers/user@example.com
```

Use `--verbose` to write the selected canonical entry path to stderr:

```text
sshx: using gopass entry "infrastructure/production/servers/user@example.com"
```

The path is not logged by default because it may reveal infrastructure or
environment names. The password and decrypted secret contents are never
logged.

The password remains in memory only for the duration of the connection, and
its buffer is cleared before the process exits. SSH keys or an agent should
still be preferred whenever the server supports them.
