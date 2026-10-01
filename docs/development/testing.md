# Development and testing

Commands below run from the repository root with the toolchain required by
`go.mod`. Fixtures use generated keys and disposable stores. Tests requiring Unix
sockets, loopback listeners, subprocesses or D-Bus need those local capabilities.

## Routine checks

```sh
go test -race ./...
go vet ./...
go build -o /tmp/sshx ./cmd/sshx
```

`GOCACHE=/tmp/sshx-go-cache` can select a writable cache in a restricted environment.
Normal tests cover configuration, terminal handling, provider errors, registry
trust, policy, bindings, locking, constraints, confirmation and revocation.

## OpenSSH interoperability

```sh
SSHX_AGENT_OPENSSH_INTEGRATION=1 go test -race ./...
```

The installed OpenSSH client authenticates against disposable Go SSH endpoints
using generated public identities. Tests include automatic agent-key discovery
without identity-selection flags for unrestricted and destination-constrained
keys, software algorithms, password-fallback exclusion, ssh-add, confirmation
and ProxyJump.

Forwarding has a separate checksum-pinned OpenSSH 10.5p1 build and three temporary
loopback-only sshd instances. It requires an unprivileged account, C compiler,
make, curl, tar, sha256sum, and OpenSSL/zlib development headers:

```sh
openssh_dir=$(sh testdata/build-forwarding-openssh.sh)
SSHX_AGENT_FORWARDING_OPENSSH_DIR="$openssh_dir" \
  go test -race -run '^TestAgentForwarding' -count=1 ./internal/agent
rm -rf "$openssh_dir"
```

Nothing is installed. Only generated keys are authorized, and a forced command
allowlist controls remote actions. Temporary fixture configurations disable
StrictModes checks for `/tmp` ancestors and source penalties for negative tests.
PR and release CI include the pinned harness. The fixtures verify both forwarding
depths, missing-edge and non-hostbound denial, and remote control rejection.

## Credential providers

```sh
dbus-run-session --config-file testdata/dbus-session.conf -- \
  env SSHX_SECRET_SERVICE_INTEGRATION=1 \
  go test -race -run '^TestSecretService(Integration|CacheIntegration|AgentCacheIntegration)$' -count=1 ./...
SSHX_GOPASS_KEY_INTEGRATION=1 \
  go test -race -run '^TestGopassKeyIntegration$' -count=1 ./...
```

The D-Bus fixture prevents desktop-provider activation and tests owner changes,
locks and cached-key revocation. The gopass fixture needs gopass, gpg and gpgconf
and isolates HOME, configuration, stores and GPG keys. Real desktop providers
require the [manual smoke matrix](secret-service-smoke-tests.md); passing a
fake-provider test does not establish compatibility with every desktop setup.

## Systemd activation

```sh
SSHX_SYSTEMD_INTEGRATION=1 \
  go test -race -v -run '^TestAgentSystemdIntegration$' -count=1 ./internal/cli
```

The standalone harness uses copied units, temporary configuration and
`systemd-socket-activate`. A real private user-manager fixture additionally needs
`SSHX_SYSTEMD_USER_MANAGER=1`, but must run only in a disposable VM/container with
isolated delegated cgroups. Private HOME/runtime/bus paths alone do not isolate a
user manager from an active desktop's cgroup hierarchy. Ordinary CI uses the
standalone activation fixture.

## Fuzzing and security checks

Fuzz targets run one at a time in their package:

```sh
go test ./internal/agent -run '^$' -fuzz '^FuzzAgentBinding$' -fuzztime=30s
go test ./internal/agent -run '^$' -fuzz '^FuzzAgentAddWire$' -fuzztime=30s
go test ./internal/agent -run '^$' -fuzz '^FuzzAgentDestinationConstraint$' -fuzztime=30s
govulncheck ./...
```

Reports should distinguish automated fixtures from manually checked provider,
desktop-helper or systemd environments. Historical local run counts are not a
substitute for current validation.

## Documentation

```sh
python3 scripts/check-docs.py
python3 -m http.server 8000 --directory docs
```

The local site is served at `http://localhost:8000`. Browser checks should cover
navigation, direct nested routes, search and mobile layout. Markdown files remain
readable through GitHub without JavaScript. Docsify assets are pinned locally.

The Pages workflow validates pull requests and deploys only `docs/` from `main` or
a manual run on `main`. Repository Pages settings must select GitHub Actions as
the publishing source. Deployment is separate from application releases.
