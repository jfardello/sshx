# Password authentication and file transfers

The password wrapper resolves one credential, starts OpenSSH in a controlling
pseudo-terminal, and supplies the password when its prompt is detected. The
password is not placed in command arguments or environment variables. Subsequent
input and output pass through to the interactive session.

## SSH connections

The shorthand and explicit forms are equivalent:

```sh
sshx alice@server.example
sshx ssh alice@server.example
sshx ssh Login/Production --credential-backend secret-service
sshx ssh servers/alice@server.example --credential-backend gopass
sshx ssh alice@server.example -x "-p 2222 -L 8080:localhost:8080"
sshx ssh alice@server.example uptime
```

Options in `-x`/`--options` are inserted before the destination. Remaining
arguments are appended after the destination. Option strings use whitespace
splitting, not shell evaluation; quoting inside an option string does not create
shell expansion. [Configuration](configuration.md) explains replacement of YAML
defaults and repeated `-x` options.

## Credential discovery

```sh
sshx credentials list
sshx credentials list production
sshx credentials list alice --secret-collection Login
sshx credentials list --credential-backend gopass
sshx credentials list --gopass-prefix infrastructure/production
```

Output has four tab-separated columns: `BACKEND`, `COLLECTION`, `LABEL`, `TARGET`.
Only safe metadata is printed; item IDs, full attribute maps and secrets are
omitted. An unsafe destination appears as `-`. Labels and targets may still be
sensitive operational metadata.

Secret Service matching uses the first level with results:

1. Exact `sshx.target` attribute.
2. Exact item label.
3. Exact `collection/label`.
4. Case-insensitive partial target or label match.

Discovery prints all matches at that level. A connection requires an unambiguous
selection; an explicit identity or collection narrows the result.

Direct gopass discovery uses `gopass list --flat`, optionally under a prefix.
Exact relative-path or basename matches take precedence over partial matches.
An argument containing `/` selects an exact path without discovery. A configured
prefix is prepended, so `servers/alice@server.example` under
`infrastructure/production` resolves to
`infrastructure/production/servers/alice@server.example`.

## SCP transfers

An operand beginning with `:` expands to the destination resolved from the
credential. Local-to-remote and remote-to-local copies are supported;
remote-to-remote copies are rejected because two credentials may be required.

```sh
# Upload
sshx scp alice@server.example file.txt :/tmp/
# Download
sshx scp alice@server.example :/var/log/app.log ./
# Explicit remote operand
sshx scp alice@server.example file.txt alice@server.example:/tmp/
# Recursive upload on another port
sshx scp alice@server.example -x "-r -P 2222" directory/ :/opt/app/
```

SCP uses uppercase `-P` for the port; SSH uses lowercase `-p`. Shared YAML
options must suit both clients; command-specific options belong in CLI overrides
or OpenSSH configuration.

## Diagnostics

`--verbose` writes the selected backend and credential identity to stderr.
Passwords and complete attribute maps are excluded. Agent diagnostics are a
separate flag scope, described in [troubleshooting](troubleshooting.md).
