# sshx

`sshx` runs OpenSSH with a password stored in a
[freedesktop.org Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
provider or [gopass](https://www.gopass.pw/). It does not depend on `sshpass`
and does not expose the password through command-line arguments or environment
variables.

The `ssh` or `scp` process starts in a new session with a PTY as its controlling
terminal. `sshx` detects the OpenSSH password prompt, writes the password to the
PTY, and then maintains a normal interactive session. This follows the model
used by [`clarkwang/passh`](https://github.com/clarkwang/passh).

## Requirements

- `ssh` and `scp` available in `PATH`.
- A Unix system with PTY support. Windows is not currently supported.
- On Linux with the default `auto` backend: a D-Bus session bus and a Secret
  Service provider such as gopass-secret-service, KeePassXC, or GNOME Keyring.
- For forced legacy mode, automatic fallback, or non-Linux systems: `gopass`
  available in `PATH`.

Secret Service access uses pure Go D-Bus support and does not require CGO.

## Installation

Download a build from
[GitHub Releases](https://github.com/jfardello/sshx/releases/latest) and add it
to your `PATH`. Releases currently target Linux AMD64 and Darwin ARM64.

To build from source, install Go 1.24 or later and run:

```sh
go test ./...
go build -o sshx .
install -m 0755 sshx "${HOME}/.local/bin/sshx"
```

## Backend selection

The default is `--credential-backend auto`:

- On Linux, `sshx` uses Secret Service when it is available.
- On other supported Unix platforms, it uses direct gopass.
- On Linux, it falls back to direct gopass only when the D-Bus session bus or
  Secret Service provider is unavailable.

There is deliberately no fallback after a Secret Service provider has been
reached. No match, a locked store, a dismissed prompt, access denial, malformed
data, and provider failures are reported to the user. This prevents an
unexpected credential from a different backend being selected.

Select a backend explicitly when needed:

```sh
sshx ssh admin@example.com --credential-backend secret-service
sshx ssh admin@example.com --credential-backend gopass
```

`--secret-collection <label-or-alias>` scopes Secret Service. It cannot be used
with gopass. `--gopass-prefix <path>` scopes direct gopass and makes `auto`
select legacy gopass, preserving the original behavior:

```sh
sshx ssh admin@example.com --secret-collection Login
sshx ssh admin@example.com --gopass-prefix infrastructure/production
```

## Credential discovery

List safe credential metadata without decrypting secrets:

```sh
sshx credentials list
sshx credentials list production
sshx credentials list admin@example.com --secret-collection Login
sshx credentials list --credential-backend gopass
sshx credentials list --gopass-prefix infrastructure/production
```

Output has four stable, tab-separated columns:

```text
BACKEND        COLLECTION  LABEL              TARGET
secret-service Login       Production server  admin@example.com
```

Actual output uses tabs. Only backend, collection, label, and resolved target
are printed. Item IDs, complete attribute maps, and secret values are never
displayed. A target that cannot safely be used by OpenSSH is shown as `-`.
Collection names, labels, and targets are still potentially sensitive metadata.

With a query, discovery uses the same priority as SSH and SCP:

1. exact `sshx.target` attribute;
2. exact item label;
3. exact `collection/label`;
4. case-insensitive partial target or label match.

All results at the best matching level are printed, including ambiguous
matches. Use a collection or a more specific identity to narrow the result.

## Credential format

The portable format is a Secret Service item whose secret is the SSH password
and whose attributes include:

```text
sshx.target=admin@example.com
```

`sshx.target` takes precedence over all other target metadata. Do not put a
password in an attribute: Secret Service attributes are searchable metadata,
not protected secret content.

For KeePassXC entries, `sshx` also understands an `ssh://` value in `URL` and
uses `UserName` when the URL does not contain a user. For example:

```text
URL=ssh://server.example.com
UserName=admin
```

If neither mapping exists, a non-empty item label without whitespace is used
as the OpenSSH destination.

## Provider setup

### gopass-secret-service

[gopass-secret-service](https://github.com/nikicat/gopass-secret-service)
provides the Secret Service D-Bus API while keeping its managed entries in a
gopass store. Follow its installation instructions; a typical current setup is:

```sh
go install github.com/nikicat/gopass-secret-service/cmd/gopass-secret@latest
gopass-secret service install
systemctl --user start gopass-secret-service
```

Use your desktop's Secret Service client or `secret-tool` to create entries
through the service. gopass-secret-service manages those entries under its own
configured prefix (normally `secret-service`). It does **not** automatically
export arbitrary existing gopass paths through Secret Service.

Existing paths remain available in forced legacy mode:

```sh
sshx ssh admin@example.com --credential-backend gopass
sshx ssh admin@example.com --gopass-prefix infrastructure/production
```

### KeePassXC

Enable Secret Service integration for the database and expose the group that
contains the SSH entries, then keep the database available to the desktop
session. See the
[KeePassXC Secret Service integration documentation](https://github.com/keepassxreboot/keepassxc/blob/develop/src/fdosecrets/README.md)
for configuration and attribute details.

Set an entry's URL to `ssh://host` and its username to the SSH login, or add a
custom `sshx.target` attribute. Verify what is exposed before connecting:

```sh
sshx credentials list --credential-backend secret-service
sshx credentials list admin --secret-collection '<collection>'
```

### GNOME Keyring

[GNOME Keyring](https://wiki.gnome.org/Projects/GnomeKeyring) normally provides
Secret Service in a logged-in GNOME session. A credential can be provisioned
interactively with `secret-tool`; it reads the password from the terminal and
does not place it in the command line:

```sh
secret-tool store \
  --label='admin@example.com' \
  service sshx \
  sshx.target admin@example.com
```

Confirm discovery without reading the secret:

```sh
sshx credentials list admin@example.com
```

Provider provisioning, migration, updates, and deletion are intentionally
outside sshx. The application is read-only with respect to credential stores.

## SSH usage

The original syntax remains supported:

```text
sshx <target|credential> [--credential-backend <backend>] [--secret-collection <collection>] [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]
```

The explicit subcommand is equivalent:

```text
sshx ssh <target|credential> [--credential-backend <backend>] [--secret-collection <collection>] [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]
```

Examples:

```sh
sshx admin@example.com
sshx ssh Login/Production --credential-backend secret-service
sshx ssh servers/admin@example.com --credential-backend gopass
sshx ssh admin@example.com -x "-p 2222 -L 8080:localhost:8080"
sshx ssh admin@example.com uptime
```

Options supplied through `-x` are inserted before the host in the `ssh`
invocation. All remaining arguments are appended after the host.

## SCP usage

```text
sshx scp <target|credential> [--credential-backend <backend>] [--secret-collection <collection>] [--gopass-prefix <path>] [--verbose] [-x '<scp opts>'] <source> <destination>
```

An operand beginning with `:` is expanded using the target resolved from the
credential:

```sh
# Upload
sshx scp admin@example.com file.txt :/tmp/

# Download
sshx scp admin@example.com :/var/log/app.log ./

# Explicit remote operand
sshx scp admin@example.com file.txt admin@example.com:/tmp/

# Recursive copy through another port
sshx scp admin@example.com -x "-r -P 2222" directory/ :/opt/app/
```

Local-to-remote and remote-to-local transfers are supported. Remote-to-remote
copies are rejected because they may require two independent credentials.
Remember that `scp` uses uppercase `-P`, while `ssh` uses lowercase `-p`.

## Direct gopass behavior and migration

Direct gopass lookup obtains canonical entries using `gopass list --flat`,
optionally scoped by `--gopass-prefix`. It prefers exact relative-path or
basename matches and then case-insensitive partial matches. One result is
selected automatically; multiple results are printed so an explicit path can
be chosen.

When the selected backend is gopass, a credential argument containing `/` is
treated as an exact path and skips lookup. A prefix is prepended when supplied:

```text
servers/admin@example.com --gopass-prefix infrastructure/production
-> infrastructure/production/servers/admin@example.com
```

To migrate incrementally, keep existing paths in legacy mode, provision new
items through the chosen Secret Service provider, and verify them with
`credentials list` before changing scripts to `auto` or `secret-service`.

## Diagnostics and security

`--verbose` identifies only the selected backend and credential identity on
stderr:

```text
sshx: using secret-service credential "Login/Production"
sshx: using gopass entry "infrastructure/production/servers/admin@example.com"
```

No diagnostic contains the password or a complete attribute map. The selected
secret stays in a byte buffer only for the connection and is cleared before
exit. SSH keys or an agent should still be preferred whenever the server
supports them.
