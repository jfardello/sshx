# Secret Service smoke tests

Real-provider checks complement the isolated automated provider. A disposable
SSH account and isolated bus/profile are required; production credentials must
not be used. Only one provider can own `org.freedesktop.secrets` on a session bus.

## Password matrix

| Provider | Provisioning | Expected mapping |
| --- | --- | --- |
| gopass-secret-service | Managed item created through Secret Service | `sshx.target` |
| KeePassXC | Exposed test database/group | `sshx.target`, or SSH URL and username |
| GNOME Keyring | Interactive secret-tool entry | `sshx.target` |
| KWallet | QtKeychain attributes from the provider guide | `sshx.target` and application visibility |

[Provider setup](../providers.md) contains the schemas. A generic disposable entry
can be created interactively; the secret is entered only at the prompt:

```sh
test_target='sshx-smoke@127.0.0.1'
secret-tool store --label='sshx-smoke' \
  service sshx-smoke sshx.target "$test_target"
sshx credentials list sshx-smoke --credential-backend secret-service
sshx ssh sshx-smoke --credential-backend secret-service --verbose
```

The target represents a reachable disposable server. KWallet needs its additional
schema attributes. Expected discovery contains one metadata row, and SSH must
authenticate with the stored password. Passwords and complete attribute maps must
not appear in output, command arguments, environment, history or logs.

The same checks should cover collection scoping, ambiguous matches, locked
providers, cancellation and unavailable providers. Results should record provider
version and desktop/session type, never the secret. Direct-gopass lookup should
be tested separately with an isolated entry and optional prefix.

## Key-storage and cache matrix

Password checks alone do not validate agent keys. A synthetic multiline key item
requires the [key-item attributes](../providers.md#secret-service-private-keys)
and a matching public registration. Provision it with the provider guide's
generic Secret Service command or its KWallet alternative, then follow the
[CLI registration flow](../agent/README.md#register-an-existing-key).
Check that multiline content survives retrieval and registration prints the
matching public fingerprint. For KWallet, also verify folder/entry visibility
in the desktop application. Record provider and desktop versions separately;
an isolated generic provider does not establish KWallet UI compatibility.
Checks should cover successful retrieval,
locked refusal, duplicate IDs, mismatched keys, provider restart/path reuse and
cancellation. Cache-enabled providers additionally require monitoring and
revocation checks after lock, deletion, key modification and owner replacement.

## Cleanup

The exact generic fixture item can be removed with:

```sh
secret-tool clear service sshx-smoke sshx.target "$test_target"
```

Provider-specific entries and disposable databases should be removed through
their management tools. Repeated discovery must no longer show the test item.
[Automated checks](testing.md) should run on an isolated bus rather
than the active desktop session.
