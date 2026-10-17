# Credential providers

This guide stores credentials with provider tools. After provisioning, continue
with the [password connection guide](password-authentication.md#first-password-connection)
or [key registration and connection](agent/README.md#register-an-existing-key).
sshx reads provider entries; it does not create or update their secret values.

| Provider | Passwords | Private keys |
| --- | --- | --- |
| Direct gopass | [Store a password](#gopass-passwords) | [Load a private key](#gopass-private-keys) |
| Secret Service / GNOME Keyring | [Store a password](#secret-service-passwords) | [Load a private key](#secret-service-private-keys) |
| KDE KWallet | [Password schema variant](#kwallet-passwords) | [Private-key schema variant](#kwallet-private-keys) |

Secret Service examples require `secret-tool` (from libsecret tools), an available
provider on the session bus, and an unlocked collection. Only one provider can
own `org.freedesktop.secrets` in a session. Additional setup for
[KeePassXC](#keepassxc) and [gopass-secret-service](#gopass-secret-service) appears below.

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
`--secret-collection` cannot be combined with gopass selection.
[Configuration](configuration.md#password-command-defaults) defines defaults and
conflict handling. Agent backends are explicit per registered key; password
discovery settings do not configure the agent.

## Password item format

A Secret Service password item stores the password as its secret and the
searchable attribute `sshx.target=alice@server.example`. Attributes and labels
are public metadata and must not contain passwords or private keys.

KeePassXC can alternatively supply an SSH URL and username. The complete lookup
order belongs to [credential discovery](password-authentication.md#credential-discovery).
Private-key items use a different schema, described below; password discovery
is not a way to list registered keys.

## Direct gopass

A working gopass/GPG store is required. For a new store only, run `gopass init`
and follow its GPG setup prompts. Existing stores do not need reinitialization.
The private-key workflow has been checked with gopass **1.17.4 and GPG**; it
requires support for `show --nofuzzysearch`. An older binary such as 1.15.16
lacks that flag. The selected executable and options can be checked without
reading a secret:

```sh
command -v gopass
CHECKPOINT_DISABLE=1 gopass version
gopass show --help
```

The same environment must select the same store during loading, unlocking and
registration. In particular, `XDG_CONFIG_HOME` affects both gopass and sshx;
changing it for an isolated sshx setup can also change the gopass configuration.
An explicit existing `GOPASS_CONFIG` can select the intended gopass configuration.

### gopass passwords

```sh
gopass insert servers/alice@server.example
```

Enter the remote account password at the prompt. Continue with the
[direct-gopass password connection](password-authentication.md#first-password-connection).
A password entry is separate from a private-key entry.

### gopass private keys

Store the complete existing private-key file, including its header and footer:

```sh
gopass insert --multiline ssh-keys/work-key < ~/.ssh/id_ed25519
```

Use a new entry path for a new key; an existing entry can prompt for replacement.
No extra password line, metadata, or base64 wrapping is needed. The reference
used at registration is exactly `ssh-keys/work-key`.

GPG must already permit noninteractive decryption. If its key is locked, perform
a normal read to allow pinentry, discard the output, then retry registration:

```sh
gopass show --noparsing --unsafe --alsoclip=false -- ssh-keys/work-key > /dev/null
```

The GPG agent's unlock lifetime is independent of sshx. A later expiry may require
another unlock. Registration reports a locked provider when GPG requires
pinentry; background agent reads do not launch it. A passphrase on the SSH key
itself is a separate layer, covered by the
[key guide](agent/README.md#store-the-private-key).

Continue with [registering the stored key](agent/README.md#register-an-existing-key).

## Secret Service

GNOME Keyring normally provides Secret Service in a logged-in GNOME session.
Other compatible providers use the same item attributes. The examples select
the `default` collection alias for both storage and registration. An alias is a
stable provider mapping, not the wallet's display name or a transient D-Bus path.
The provider must expose that alias to the intended collection.

Unlock the collection in the provider's management application before key
registration or signing. Provider unlocking is separate from an SSH private-key
passphrase. Provider-specific behavior should be checked with the
[smoke-test matrix](development/secret-service-smoke-tests.md).

### Secret Service passwords

```sh
secret-tool store --collection=default --label='alice@server.example' \
  service sshx sshx.target alice@server.example
```

Enter the password at the hidden prompt, then continue with the
[password connection guide](password-authentication.md#first-password-connection).

### Secret Service private keys

A key item needs these nonsecret string attributes:

| Attribute | Value | Purpose |
| --- | --- | --- |
| `service` | `sshx` | Identify sshx entries |
| `sshx.type` | `ssh-key` | Distinguish private-key items from passwords |
| `sshx.schema` | `1` | Key-item schema version |
| `sshx.id` | `work-key` | Stable ID used by registration's `--reference` |

Load the entire existing key through stdin:

```sh
secret-tool store --collection=default --label='sshx/work-key' \
  service sshx sshx.type ssh-key sshx.schema 1 sshx.id work-key \
  < ~/.ssh/id_ed25519
```

File redirection preserves multiline content and avoids putting the key in shell
arguments or history. `secret-tool` reads redirected input to EOF, as documented
by its [upstream implementation](https://github.com/GNOME/libsecret/blob/main/tool/secret-tool.c).
The label is for display; lookup uses the stable ID and collection alias.

Use this command **or** the KWallet variant below, depending on the provider.
Do not create separate items with the same `sshx.id` in one collection; ambiguous
IDs are rejected. Replacing an item's contents also requires updating its
[public registration](agent/registration.md#register-an-existing-provider-key)
if the key changes.

Continue with the [Secret Service registration command](agent/README.md#register-an-existing-key).

## KDE KWallet

KWallet uses the Secret Service backend in sshx. Its QtKeychain schema adds
application visibility metadata to the same sshx attributes.
[KDE's implementation](https://github.com/KDE/kwallet/blob/master/src/runtime/kwalletd/secretserviceclient.cpp)
maps `server` to the displayed folder and `user` to the entry key. Here
`server=sshx` groups entries under sshx; `user` identifies the password or key item.
`type=plaintext` means a text entry, including a PEM/OpenSSH private key; it does
not disable the wallet's encryption. Desktop version and provider integration
affect application visibility; the Secret Service collection must still be
available and unlocked.

### KWallet passwords

```sh
secret-tool store --collection=default --label='sshx/alice@server.example' \
  service sshx sshx.target alice@server.example \
  xdg:schema org.qt.keychain server sshx type plaintext user alice@server.example
```

Enter the password at the prompt. Continue with the
[Secret Service password connection](password-authentication.md#first-password-connection).

### KWallet private keys

This is an alternative to the generic Secret Service key-loading command:

```sh
secret-tool store --collection=default --label='sshx/work-key' \
  service sshx sshx.type ssh-key sshx.schema 1 sshx.id work-key \
  xdg:schema org.qt.keychain server sshx type plaintext user work-key \
  < ~/.ssh/id_ed25519
```

The [shared key attributes](#secret-service-private-keys) retain their meaning;
QtKeychain attributes only add the KWallet display mapping. Registration uses
`--backend secret-service --reference work-key --collection default`, exactly as
in the [key guide](agent/README.md#register-an-existing-key).

## gopass-secret-service

[gopass-secret-service](https://github.com/nikicat/gopass-secret-service) exposes
its managed entries over D-Bus. It does not automatically expose arbitrary
existing gopass paths. Installation and service management follow its upstream
documentation; provision entries with the Secret Service commands above and
check the provider's key-item behavior before use.

Direct paths remain accessible through the direct gopass backend. A bridge uses
the Secret Service contract instead, including stable key IDs and collection
aliases. [Backend selection](#backend-selection) explains how to choose explicitly.

## KeePassXC

Secret Service integration must be enabled for the database and the relevant
group exposed. The database must be available in the desktop session.
[Upstream configuration](https://github.com/keepassxreboot/keepassxc/blob/develop/src/fdosecrets/README.md)
describes integration and attributes.

Password entries can contain an SSH URL and username or an explicit `sshx.target`.
Private keys need the complete secret payload and the
[Secret Service key attributes](#secret-service-private-keys). Password discovery
alone does not establish key support. Collection aliases must resolve to the
exposed collection, and provider behavior needs the
[key-storage smoke checks](development/secret-service-smoke-tests.md#key-storage-and-cache-matrix).

## GNOME Keyring

Use the [Secret Service password](#secret-service-passwords) or
[private-key](#secret-service-private-keys) instructions above. No additional
KWallet display schema is needed. An unlocked desktop login keyring and an
available `default` alias are the usual prerequisites.
