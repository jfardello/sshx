# Desktop credential selection protocol

The optional `sshx-prompt-zenity` helper supports a separate version-2
`select-credential` operation. Agent confirmation and OpenSSH passphrase entry
continue to use [version 1](agent-protocol.md#prompt-helper-protocol), with their
existing limits. The Tk helper supports version 1 only; a selection caller must
reject its nonzero exit or incompatible response without retry or fallback.

The protocol, helper dialog and internal caller are implemented. Password SSH
now exposes [UI options and settings](../configuration.md#ssh-selection-defaults)
and a terminal picker. Desktop selection's SSH handoff remains pending: a request
that needs a desktop choice fails before password retrieval. SCP and credential
listing retain their existing behavior.

## Request

The parent invokes an explicitly configured trusted absolute executable without
arguments or a shell, sends one UTF-8 JSON object through a private stdin pipe,
and closes the pipe. Executable checks and process cleanup follow the
[helper trust rules](../agent/confirmation.md#enable-and-run).

```json
{
  "version": 2,
  "request_id": "<fresh random 64 lowercase hexadecimal characters>",
  "operation": "select-credential",
  "options": [
    {
      "token": "<fresh random 64 lowercase hexadecimal characters>",
      "display": {
        "label": "Production",
        "target": "alice@server.example",
        "backend": "secret-service",
        "collection": "Login"
      }
    }
  ]
}
```

All fields shown are required and have exact, case-sensitive names and types.
Label and target must be nonempty; backend is `gopass` or `secret-service`.
Collection may be an empty string. Display values are metadata, not proof of a
destination's identity or instructions for finding a credential. Provider IDs,
item/object paths, gopass references, attribute maps and secrets have no wire
fields and must remain in the parent. A gopass display label is a human label,
not its full storage reference.

The parent creates a random 256-bit request ID and independent, unique option
tokens for each invocation. It retains the exact credential references in the
same order. Token-to-reference associations exist only for that request; labels
and targets never serve as lookup keys when a choice is returned.

## Display and resource bounds

| Resource | Limit |
| --- | --- |
| Complete request, including JSON encoding | 256 KiB |
| Candidates | 1–256 |
| Each display field | 1024 UTF-8 bytes before and after display escaping |
| Complete response | 16 KiB |
| Picker operation | 30 seconds, or the caller's earlier deadline |

Oversized input fails with a narrowing-required error before invoking a helper.
Candidates and fields are never silently truncated. The JSON envelope limit can
be reached before the candidate-count or individual-field limits.

Display strings use a canonical visible ASCII representation. The parent applies
Go's `strconv.QuoteToASCII`, removes the enclosing quotes and replaces literal
`<`, `>`, `&` and apostrophe with `\u003c`, `\u003e`, `\u0026` and `\u0027`.
Controls, bidi characters, newlines, quotes, backslashes and non-ASCII characters
therefore remain visibly represented. Ordinary JSON encoding then escapes those
backslashes for transport. The helper validates this representation and displays
it without unescaping it into controls or markup.

The Zenity list prefixes each complete row with a unique ordinal. Identical
labels, targets and collection names remain distinct rows and resolve to their
own original tokens. It permits one choice, never multiple selections. Closing
or canceling the dialog denies; an empty native selection also denies.

## Response and validation

Successful selection returns exactly the envelope and the original chosen token:

```json
{"version":2,"request_id":"<exact request ID>","approved":true,"token":"<original option token>"}
```

Cancellation returns no token:

```json
{"version":2,"request_id":"<exact request ID>","approved":false}
```

Unknown, duplicate, missing, null or wrongly typed fields, trailing JSON,
unsupported versions/operations, mismatched request IDs, duplicate option tokens
and responses choosing a foreign token are invalid. A denial containing any token
field, including an empty token, is invalid. Responses cannot supply a target,
label, replacement credential or provider reference.

The internal caller returns only the validated original index, a cancellation,
or a fixed error. It neither searches providers nor retrieves passwords or starts
SSH. Its deadline ends before any subsequent SSH session. A missing or failed
helper never falls back to Tk, terminal input or another credential.

The helper shares the existing supervised worker, curated environment and
process-group cleanup. stdout contains one protocol response; diagnostics contain
no request content. Cancellation, supervisor death and the local deadline close
dialogs and descendants remaining in the worker's group. Deliberately detached
processes remain outside that mechanism. Owned mutable request/response buffers
are cleared best-effort; library and runtime copies cannot all be erased.
