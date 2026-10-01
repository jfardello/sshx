# Running the agent

An agent can serve a shared foreground socket, a command-scoped socket, or a
Linux systemd user socket. All modes use the [key registry](registration.md);
password-command backend flags and YAML defaults do not configure the agent.

## Foreground service

```sh
sshx agent start --foreground
```

In a second terminal, the environment can be selected with:

```sh
eval "$(sshx agent env)"
sshx agent status
ssh-add -l
ssh alice@server.example
```

`env` supports `sh` and `zsh`. It validates the endpoint and requests public
identities before printing a quoted `SSH_AUTH_SOCK` assignment and unsetting
`SSH_AGENT_PID`. It does not spawn an agent. Both `env` and `status` select their
configured socket, not an unrelated inherited `SSH_AUTH_SOCK`.

The standalone default is `$XDG_RUNTIME_DIR/sshx/agent.sock`. When that variable
is unset, the fallback is `/tmp/sshx-<uid>/agent.sock`, using canonical
`/private/tmp` on macOS. Runtime directories must be private, owner-controlled,
and reached through trusted non-symlink ancestors. sshx creates its own `0700`
subdirectory but does not repair existing permissions.

`--socket /absolute/private/agent.sock` selects another endpoint. Its parent must
already exist with mode `0700`; socket paths are limited to 100 bytes. Existing
endpoints, including stale sockets, are not replaced automatically. Shutdown by
Ctrl-C, SIGTERM or SIGHUP removes only the socket created by that agent.
`agent stop` without `--systemd` explains foreground shutdown; it does not kill
processes selected through PID files. Background daemonization is not provided.

## Command-scoped service

```sh
sshx agent run -- ssh alice@server.example
sshx agent run -- git clone git@github.com:org/repo.git
sshx agent run -- scp './file with spaces' alice@server.example:/tmp/
```

Arguments after `--` belong to the child. No shell or PTY is inserted; shell
syntax requires an explicit shell. Only the child receives the private socket.
Stale agent PID and systemd activation variables are removed from its environment.
Input, output and error streams remain connected to the foreground terminal.

Termination signals are forwarded to the child, followed by forced termination
if it has not exited within two seconds. Normal exit status is preserved; signal
termination returns `128 + signal`. Child exit or startup failure closes the
agent and removes its own socket and private directory. Descendants cannot retain
that agent after teardown.

Instances sharing an existing [state ledger](ssh-add.md#persistent-lock-and-removal-state)
are rejected. A separate `--state-file` is required for an independent mutation
and locking domain when another agent already owns the default ledger.

## Systemd user service

The source checkout contains templates at
[contrib/systemd](https://github.com/jfardello/sshx/tree/main/contrib/systemd).
They are installed explicitly; sshx does not enable units or lingering.

```sh
install -d -m 0700 "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
install -m 0600 contrib/systemd/sshx-agent.socket \
  contrib/systemd/sshx-agent.service \
  "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/"
```

The service defaults to `/usr/bin/sshx`. Its copied `ExecStart` must contain the
actual absolute executable path; systemd does not expand `~` or shell variables
there. Once that path and the registry are configured:

```sh
systemctl --user daemon-reload
systemctl --user enable --now sshx-agent.socket
sshx agent status --systemd
eval "$(sshx agent env --systemd)"
```

The managed socket is `$XDG_RUNTIME_DIR/sshx-agent/agent.sock`, distinct from the
standalone `sshx/` path. The first connection activates one shared foreground
service. `env --systemd` connects and may activate it; its two-second response
deadline can expire before slow activation completes. A later attempt can succeed.

`status --systemd` reads unit state without activation. A listening socket with an
inactive service is ready for activation. Status and listing do not verify
private-key retrieval or signing.

```sh
sshx agent stop --systemd
systemctl --user start sshx-agent.socket
```

Managed stop waits for the socket to stop before stopping the service, preventing
new socket activation. Failure to stop the socket prevents the second operation.
Stopping only the service leaves the socket able to reactivate it. Disabling
future login activation additionally requires `systemctl --user disable sshx-agent.socket`.
A process restart uses `systemctl --user restart sshx-agent.service`; registry
updates are read on requests and do not require restart.

The manager owns the socket. The service closes its descriptor and connections
without unlinking the managed endpoint. The templates set `UMask=0077`,
`NoNewPrivileges=yes`, and `LimitCORE=0`; there is no idle-exit or automatic restart
policy. Restart neither unlocks the agent nor clears persisted suppression.

## Environment and optional features

The user manager may have a different `PATH`, `XDG_CONFIG_HOME`, GPG configuration,
or desktop routing from the terminal. Only required nonsecret variables should
be configured or imported. A service restart is required after environment changes.
Secret Service needs the session bus; direct gopass needs its executable and a GPG
keyring ready for noninteractive decryption.

[Confirmation](confirmation.md), [caching](caching.md), [ssh-add](ssh-add.md), and
[forwarding](forwarding.md) flags belong before `--` on `agent run`, or in the
service's existing `ExecStart`. Existing flags must be retained when an override
replaces that command. [Troubleshooting](../troubleshooting.md) covers diagnostics.
