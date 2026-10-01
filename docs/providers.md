# Credential providers

sshx reads existing credentials. Provisioning, migration, updates and deletion
remain the responsibility of the selected provider and its management tools.

## Backend selection

| Selection | Behavior |
| --- | --- |
| `auto` on Linux | Secret Service; direct gopass only if the session bus or provider is unavailable |
| `auto` on other supported Unix platforms | Direct gopass |
| `secret-service` | Explicit Secret Service access |
| `gopass` | Explicit direct gopass access |

There is no fallback after a Secret Service provider has been reached. No match,
a locked store, canceled approval, access denial, malformed data and provider
errors remain errors. A nonempty `--gopass-prefix` makes `auto` select gopass.
`--secret-collection` cannot be combined with gopass selection. Defaults and
conflict handling are described in [configuration](configuration.md).

Agent backends are explicit per [registry record](agent/registration.md), with
no automatic fallback. Password discovery settings do not configure the agent.

## Password item format

A portable Secret Service item stores the password as its secret and includes
`sshx.target=alice@server.example` as a searchable attribute. Passwords must not
be stored in attributes.

`sshx.target` has priority. KeePassXC entries can alternatively provide
`URL=ssh://server.example` and `UserName=alice`; a username in the URL takes
precedence over `UserName`. Without either mapping, a nonempty item label without
whitespace is used as the OpenSSH destination.

## Direct gopass

Existing entries can be selected without a Secret Service bridge:

```sh
sshx ssh servers/alice@server.example --credential-backend gopass
sshx credentials list --gopass-prefix infrastructure/production
```

Password lookup and [private-key retrieval](agent/registration.md#backend-contracts)
have different contracts. Agent key reads are noninteractive and require the
entire key payload. GPG must already allow decryption; agent signing does not
open pinentry. The documented key-provider baseline is gopass 1.17.0 with GPG.

## gopass-secret-service

[gopass-secret-service](https://github.com/nikicat/gopass-secret-service) exposes
its managed entries over D-Bus. It does not automatically expose arbitrary
existing gopass paths. Installation and service management follow its upstream
documentation; credentials should be provisioned through a Secret Service client.
Existing direct paths remain accessible with `--credential-backend gopass`.

A migration can retain existing paths in direct mode while newly provisioned
Secret Service entries are checked with `sshx credentials list` before changing
backend defaults.

## KeePassXC

Secret Service integration must be enabled for the database and the relevant
group exposed. The database must be available in the desktop session.
[Upstream configuration](https://github.com/keepassxreboot/keepassxc/blob/develop/src/fdosecrets/README.md)
describes the integration and attributes.

An entry can contain an `ssh://` URL and SSH username, or an explicit `sshx.target`.
Exposure can be checked without reading its secret:

```sh
sshx credentials list --credential-backend secret-service
sshx credentials list alice --secret-collection '<collection>'
```

## KDE KWallet

For a Secret Service password to appear in the KWallet application, the
QtKeychain schema and associated attributes should be used when storing it.
KWallet's displayed entries are filtered by this schema:

```sh
secret-tool store \
  --label='sshx/alice@server.example' \
  service sshx \
  sshx.target 'alice@server.example' \
  xdg:schema org.qt.keychain \
  server sshx \
  type plaintext \
  user 'alice@server.example'
```

`alice@server.example` represents the SSH destination. The password is entered at the
interactive prompt, not supplied as an argument. This is a password-item schema;
agent key entries also require the [key attributes](agent/registration.md#backend-contracts).

## GNOME Keyring

GNOME Keyring normally provides Secret Service in a logged-in GNOME session.
A password can be provisioned interactively:

```sh
secret-tool store \
  --label='alice@server.example' \
  service sshx \
  sshx.target alice@server.example
sshx credentials list alice@server.example
```

Only one provider can own `org.freedesktop.secrets` in a session. An isolated bus
or separate desktop profile should be used for [provider smoke tests](development/secret-service-smoke-tests.md).
Password discovery success does not establish agent-key or signer-cache support.
