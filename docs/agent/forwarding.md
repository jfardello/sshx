# Constrained agent forwarding

Forwarding is disabled by default. It can be enabled explicitly on the agent process:

```sh
sshx agent start --foreground --allow-forwarding
# In another terminal:
eval "$(sshx agent env)"
ssh -A alice@bastion.example
# On the bastion:
ssh alice@server.example
```

A command-scoped agent can use:

```sh
sshx agent run --allow-forwarding -- ssh -A alice@bastion.example
```

For systemd, `--allow-forwarding` belongs in the existing service `ExecStart`,
alongside `--foreground --socket-activation` and any helper/cache/mutation flags.
A user-manager reload and service restart are required. This does not enable OpenSSH's
`ForwardAgent` option: forwarding must also be requested explicitly with `ssh -A`.

## Policy and visibility

Only `destination-constrained` identities may be listed or used on a connection
recognized as forwarded. Both registry identities and constrained `ssh-add -h`
imports use the same enforcement. `unrestricted-local` identities remain hidden
and cannot sign on these connections, even when their public blob is known.

For origin → bastion → destination, the key needs both origin → bastion and
bastion → destination edges. For origin → bastion → second hop → destination,
every adjacent edge is required. The following `destinations` object illustrates a version-2 registry entry.
All placeholders must be replaced with complete trusted public host keys:

```json
{
  "version": 1,
  "require_hostbound": true,
  "edges": [
    {
      "from": {},
      "to": {
        "hostname": "bastion.example",
        "username": "alice",
        "host_keys": ["ssh-ed25519 <BASTION_HOST_KEY_BASE64>"]
      }
    },
    {
      "from": {
        "hostname": "bastion.example",
        "host_keys": ["ssh-ed25519 <BASTION_HOST_KEY_BASE64>"]
      },
      "to": {
        "hostname": "server.example",
        "username": "alice",
        "host_keys": ["ssh-ed25519 <DESTINATION_HOST_KEY_BASE64>"]
      }
    }
  ]
}
```

Hostnames label pins; authorization compares verified raw host keys, not DNS.
Username restrictions apply to the final authentication destination. Session
bindings do not authenticate usernames of intermediate forwarding hosts. Shared
host keys cannot distinguish hosts: pins and delegation should reflect this limitation.

An initial forwarding-only binding may list a constrained identity only when its
recorded path is allowed and there is an allowed onward edge. A final
non-forwarding binding allows listing for authentication to that destination;
signing additionally checks the requested username and authentication payload.
Listing never retrieves private material. A destination without onward permission
will not expose the key for another forwarded session there.

## Signing and control boundaries

Every recorded hop must have a verified session-binding signature and a matching
policy edge. A final authentication binding and hostbound public-key request are
mandatory for forwarded signing, even when `require_hostbound` is false for direct
connections. The signed session ID, user, key, algorithm and final host key must
match. Clients/servers without the required extensions fail closed; there is no
fallback to unrestricted forwarded signing.

All remote Add, Remove, RemoveAll, Lock and Unlock requests are rejected, even
with `--allow-key-mutations`. Management operations require the local socket. Unsupported extensions, certificates, CA pins, smartcards and FIDO remain
unsupported. See [ssh-add compatibility](ssh-add.md).

Locking hides identities and denies signatures while valid binding proofs can
still be recorded. Unlocking cannot erase forwarded status, terminal bindings or
poisoning. Each socket connection owns its own chain, including simultaneous
connections on the same SSH session. Confirmation, cache revocation, registry
refresh and imported-key lifetime checks remain in effect. Changing the forwarding
setting invalidates pending signatures and signer caches; a connection already
rejected during disabled forwarding stays rejected and must be reopened.

## Delegation limits and ProxyJump

`ssh -J bastion destination` normally uses the origin's client for target
authentication. It needs independent origin → bastion and origin → destination
permissions; it does not imply a forwarded bastion → destination edge. By
contrast, `ssh -A bastion` followed by SSH on the bastion delegates agent use there.

A compromised permitted host can exercise the authority delegated through it.
Bindings prove host-key possession for recorded sessions, not a physical network
route or freshness. Noncooperating relays can hide hops, and replayed proofs can
make an apparent chain longer. A raw socket bridge can appear local; Unix peer
credentials identify that bridge, not its remote user. Hostbound verification
protects the final destination but does not detect every relay or same-user
misuse. These are protocol limits described in the
[OpenSSH restriction analysis](https://www.openssh.org/agent-restrict.html).
