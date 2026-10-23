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
When an OpenSSH client is installed, normal PTY tests also verify password
authentication and binary archive upload/download against a disposable local
SSH endpoint, including decompression and checksum validation.

## SSH terminal selection

Parser tests cover optional queries, SSH/root parity, config precedence and
explicit resets, native option values, and remote-command/`--` boundaries. Existing
SCP/listing tests retain their original behavior. Selection tests verify scoped
metadata discovery, no-query prompting even for one candidate, direct connection
for one queried match, cancellation and failure before secret retrieval.

Real PTY fixtures test bounded numeric input, editing, cancel controls, invalid
input, pasted-ahead flushing, context and external-signal cancellation, terminal
restoration, and fresh input reaching the next reader. Subprocess fixtures bind
a controlling terminal while redirecting stdin/stdout, then verify the picker
leaves streams intact and restores the terminal before OpenSSH handoff.

## Desktop prompt helper

Normal tests inject dialogs to cover strict version-1 parsing, plain-text identity
rendering, denial, passphrase limits and mutable-buffer cleanup. Native-adapter
tests replace the Unix dialog executable in a subprocess and verify
`--default-cancel`, Allow once/Reject labels and `--hide-text`. Agent tests pass
actual generated requests through the helper and decode its responses with the
agent's version-1 decoder. Supervisor tests cover output bounds, environment
filtering and child cleanup on completion and timeout.

Selection tests exercise the separate version-2 schema, candidate/field/envelope
bounds, canonical display escaping, fresh request IDs/tokens and exact original
index binding. Duplicate labels, cross-request replies, extra fields, malformed
responses, helper failures and old Tk helpers fail closed. Oversized version-1
requests remain rejected even though the executable also accepts larger
version-2 selection requests. The selection caller never receives provider
references or retrieves secrets.

The Linux native smoke fixture requires Xvfb, Zenity, libX11, libXtst and Python 3.
It creates an isolated display and uses only a synthetic passphrase:

```sh
prompt_dir=$(mktemp -d /tmp/sshx-prompt.XXXXXX)
go build -o "$prompt_dir/sshx-prompt-zenity" ./cmd/sshx-prompt-zenity
python3 testdata/zenity-smoke.py "$prompt_dir/sshx-prompt-zenity"
rm -rf "$prompt_dir"
```

The fixture checks Enter defaults to rejection, explicit approval, passphrase
entry/base64, empty-input denial, selection cancellation and duplicate-label
selection of the second original token, and dialog removal after SIGTERM, SIGKILL and
the local 30-second deadline. `SSHX_ZENITY_SMOKE_SCREENSHOT=/tmp/sshx-masked.png` optionally
captures the synthetic masked entry for visual inspection; ImageMagick's `import`
is then required. Real macOS dialogs and other Unix dialog programs need separate
desktop smoke checks; cross-compilation alone does not validate their UI behavior.

The dialog dependency is pinned to
[`github.com/ncruces/zenity v0.10.15`](https://github.com/ncruces/zenity/tree/v0.10.15) (MIT,
commit `608cae244677a9a0f77097c3d07eea492475a76c`). The source review covers
`msg_unix.go`, `entry_unix.go`, `list_unix.go`, `list_darwin.go`, `util.go`,
`msg_darwin.go`, `entry_darwin.go` and
`internal/zenutil/zenutil_{unix,darwin}.go`. Linux questions disable markup and
default to cancellation; entry uses hidden text. macOS entry uses hiddenAnswer,
and button defaults are supplied through the library. No shell interpolation is
used. The helper escapes identity text before either platform receives it.
Selection uses the library's single-item list operation and checks its exact
returned row, including a unique ordinal; native display text cannot retarget a
credential. The Linux list does not disable markup itself, so canonical escaped
display fields are required. Native lists are not assumed to honor DefaultCancel;
explicit cancellation and empty results deny without a token.
The library uses `exec.CommandContext`/`Output`, which kills only its immediate
child and retains output/string copies. The helper's supervised process group,
lifetime pipe and local timeout provide cleanup around that behavior; these do
not contain processes that deliberately detach. Library-owned output buffers
and immutable strings cannot be cleared by sshx. Dependency changes require
review of those assumptions and repeat desktop checks.

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

Installation belongs in getting started; provider loading commands, schemas and
unlocking belong in the provider guide. Password and key quick starts own the
first-connection workflows. Registration, configuration and agent operation
pages own their detailed contracts. Keep landing pages short and link to those
sources instead of copying complete setup instructions or attribute definitions.

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
