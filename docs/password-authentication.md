# Password authentication and file transfers

sshx supplies a stored password to OpenSSH for interactive connections, remote
commands and file transfers. [Key authentication](agent/README.md) uses a separate
agent workflow.

## First password connection

After [installation](getting-started.md#installation), choose a provider and
[store the remote account password](providers.md). The server must accept
password authentication. No agent registration is needed.

For Secret Service, including GNOME Keyring or KWallet:

```sh
sshx credentials list alice@server.example --credential-backend secret-service
sshx ssh alice@server.example --credential-backend secret-service
```

For direct gopass:

```sh
sshx credentials list alice@server.example --credential-backend gopass
sshx ssh servers/alice@server.example --credential-backend gopass
```

Discovery should show the intended entry; the connection should open an
authenticated session. On a first connection, OpenSSH may ask to trust the server
host key; its fingerprint must match an independently trusted source. A discovery
row proves metadata lookup, not that the password is correct.

After the first connection, backend selection and other defaults can be saved
with [configuration commands](configuration.md#inspecting-and-editing-settings).
The remaining sections cover remote commands, discovery details and transfers.

## Redirected streams

Redirected stdout and stderr remain separate, and file or pipe input passes
directly to OpenSSH. Password prompts and terminal messages go to stderr, so
binary transfers can use normal shell redirection:

```sh
sshx alice@server.example tar czf - /tmp/foo > test.tar.gz
sshx alice@server.example 'cat > /tmp/input.bin' < input.bin
```

Terminal input still supports interactive prompts when output is redirected.
As with OpenSSH, explicitly requesting a remote terminal with `-t` or `-tt` can
change remote stream behavior; use a session without a remote terminal for
binary transfers.

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
