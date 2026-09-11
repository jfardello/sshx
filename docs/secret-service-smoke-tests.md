# Secret Service smoke tests

Use this checklist before merging a Secret Service release candidate. It tests
real providers with disposable credentials and complements the isolated fake
provider used by the automated integration test.

Never use a production account or password. Use a disposable SSH account on a
test host, and remove the credential from the provider when finished. Only one
Secret Service provider can own `org.freedesktop.secrets` in a D-Bus session,
so stop or disable competing providers before each row of the matrix.

## Test values

Choose a reachable disposable SSH target and keep its password out of shell
history, environment variables, files, and command arguments:

```sh
test_target='sshx-smoke@127.0.0.1'
```

Replace `127.0.0.1` when the disposable SSH server is elsewhere. The examples
below use this metadata:

```text
label: sshx-smoke
sshx.target: sshx-smoke@127.0.0.1
secret: the disposable SSH account password
```

`secret-tool store` prompts for the secret interactively.

## Provider matrix

| Provider | Provisioning path | Expected discovery mapping | Cleanup |
| --- | --- | --- | --- |
| gopass-secret-service | Start the user service, then use `secret-tool store` | `sshx.target` resolves to the disposable target | `secret-tool clear`, then inspect the provider-managed gopass prefix |
| KeePassXC | Enable Secret Service for a test database/group and create a test entry | `URL=ssh://127.0.0.1` plus `UserName=sshx-smoke`, or custom `sshx.target` | Delete the test entry and empty the recycle bin if appropriate |
| GNOME Keyring | Use `secret-tool store` in a GNOME session | `sshx.target` resolves to the disposable target | `secret-tool clear` |

Record the provider version, desktop/session type, collection label, and result
for each row. Do not record the password.

## [gopass-secret-service](https://github.com/nikicat/gopass-secret-service)

Install and start the provider according to its upstream documentation. A
typical user-service installation is:

```sh
go install github.com/nikicat/gopass-secret-service/cmd/gopass-secret@latest
gopass-secret service install
systemctl --user start gopass-secret-service
```

Create the disposable credential through Secret Service:

```sh
secret-tool store \
  --label='sshx-smoke' \
  service sshx-smoke \
  sshx.target "${test_target}"
```

Do not create an arbitrary legacy gopass path for this test. The provider only
exposes entries it manages through Secret Service.

## [KeePassXC](https://github.com/keepassxreboot/keepassxc/blob/develop/src/fdosecrets/README.md)

Use a separate test database or group:

1. Enable Secret Service integration and expose the test group.
2. Create an entry titled `sshx-smoke`.
3. Set `URL` to `ssh://127.0.0.1` and `UserName` to `sshx-smoke`.
4. Alternatively, add the custom attribute
   `sshx.target=sshx-smoke@127.0.0.1`.
5. Set the entry password to the disposable SSH account password.
6. Unlock the database before running the common checks.

## [GNOME Keyring](https://gnome.pages.gitlab.gnome.org/libsecret/)

In a GNOME login session, create the disposable credential interactively:

```sh
secret-tool store \
  --label='sshx-smoke' \
  service sshx-smoke \
  sshx.target "${test_target}"
```

## Common checks

Run these commands for each provider:

```sh
sshx credentials list sshx-smoke --credential-backend secret-service
sshx ssh sshx-smoke --credential-backend secret-service --verbose
```

Expected discovery output contains one row equivalent to:

```text
secret-service  <collection>  sshx-smoke  sshx-smoke@127.0.0.1
```

The columns in real output are tab-separated. The SSH check must reach the
disposable server and authenticate with the stored password. Stderr may contain
only the backend and `collection/label` identity, for example:

```text
sshx: using secret-service credential "Login/sshx-smoke"
```

Confirm that stdout, stderr, shell history, process listings, and provider logs
do not contain the password or complete attribute maps.

Also verify collection scoping using the collection reported above:

```sh
sshx credentials list sshx-smoke \
  --credential-backend secret-service \
  --secret-collection '<collection>'
```

Test forced legacy access separately with a disposable gopass entry:

```sh
sshx credentials list sshx-smoke --credential-backend gopass
sshx credentials list sshx-smoke --gopass-prefix '<test-prefix>'
```

## Cleanup

For credentials created with `secret-tool`, remove the exact disposable item:

```sh
secret-tool clear service sshx-smoke sshx.target "${test_target}"
```

Delete the KeePassXC test entry through KeePassXC. Remove any direct-gopass
test entry through gopass. Finally, rerun discovery and confirm that
`sshx-smoke` is no longer listed.

## Automated and release validation

Run the isolated integration test without exposing the desktop session bus:

```sh
GOCACHE=/tmp/sshx-go-cache \
dbus-run-session --config-file testdata/dbus-session.conf -- \
env SSHX_SECRET_SERVICE_INTEGRATION=1 \
go test -race -run '^TestSecretServiceIntegration$' -count=1 ./...
```

Then run the remaining release gate:

```sh
GOCACHE=/tmp/sshx-go-cache go test -race ./...
GOCACHE=/tmp/sshx-go-cache go vet ./...
GOCACHE=/tmp/sshx-go-cache CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o /tmp/sshx-linux-amd64 .
GOCACHE=/tmp/sshx-go-cache CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -o /tmp/sshx-darwin-arm64 .
goreleaser check
GOCACHE=/tmp/sshx-go-cache \
  goreleaser release --snapshot --clean --skip=publish
```

Inspect `dist/metadata.json`, `dist/checksums.txt`, and both archive contents.
The snapshot version must end in `.dirty` when the working tree is uncommitted.
The archives must contain only the expected binary and documentation, and no
credential values, coverage profiles, test logs, or local configuration.
