package agent

import (
	"bytes"

	"golang.org/x/crypto/ssh"
)

const (
	sessionBindExtension          = "session-bind@openssh.com"
	maxAgentBindings              = 16
	maxAgentBindingAttempts       = 64
	maxAgentBindingKeyBytes       = 16 * 1024
	maxAgentSessionBytes          = 128
	maxAgentBindingSignatureBytes = 16 * 1024
)

// A proof of host-key possession, not host trust or destination authorization.
// These values are owned by the connection, never by the reusable frame buffer.
type agentSessionBinding struct {
	hostKey    ssh.PublicKey
	session    []byte
	forwarding bool
}

type agentBindingState struct {
	chain     []agentSessionBinding
	forwarded bool
	poisoned  bool
	attempts  int
}

// record verifies a session-binding proof and retains connection-local state.
// It enforces bounds, replay rules and terminal state, poisoning on any error.
// A verified binding proves key possession, not destination authorization.
func (b *agentBindingState) record(contents []byte) (err error) {
	defer func() {
		if err != nil {
			b.poisoned = true
		}
	}()
	if b.poisoned || b.attempts >= maxAgentBindingAttempts {
		return errAgentDenied
	}
	b.attempts++
	// Authentication is terminal, including exact replays of earlier hops.
	if len(b.chain) > 0 && !b.chain[len(b.chain)-1].forwarding {
		return errAgentDenied
	}
	host, rest, ok := agentWireString(contents)
	if !ok || len(host) == 0 || len(host) > maxAgentBindingKeyBytes {
		return errAgentDenied
	}
	session, rest, ok := agentWireString(rest)
	if !ok || len(session) == 0 || len(session) > maxAgentSessionBytes {
		return errAgentDenied
	}
	signature, rest, ok := agentWireString(rest)
	if !ok || len(signature) == 0 || len(signature) > maxAgentBindingSignatureBytes || len(rest) != 1 || rest[0] > 1 {
		return errAgentDenied
	}
	// Reject certificate/security-key/unknown types before invoking their
	// parsers. CA trust and hardware-key policy are separate work.
	kind, _, ok := agentWireString(host)
	if !ok {
		return errAgentDenied
	}
	switch string(kind) {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	default:
		return errAgentDenied
	}
	// Parse from an owned copy: upstream key types can retain byte slices.
	key, err := ssh.ParsePublicKey(bytes.Clone(host))
	if err != nil || !supportedAgentPublicKey(key) || !bytes.Equal(key.Marshal(), host) {
		return errAgentDenied
	}
	// Parse exactly two strings, excluding trailing/nested signature material.
	format, sigRest, ok := agentWireString(signature)
	if !ok || !agentAlgorithmAllowed(key.Type(), string(format)) {
		return errAgentDenied
	}
	blob, sigRest, ok := agentWireString(sigRest)
	if !ok || len(blob) == 0 || len(sigRest) != 0 {
		return errAgentDenied
	}
	if key.Verify(session, &ssh.Signature{Format: string(format), Blob: blob}) != nil {
		return errAgentDenied
	}
	for _, previous := range b.chain {
		if !bytes.Equal(previous.session, session) {
			continue
		}
		if !bytes.Equal(previous.hostKey.Marshal(), key.Marshal()) {
			return errAgentDenied
		}
		// All existing hops are forwarding at this point. A verified replay
		// is idempotent even if its requested flag differs: never change the
		// original flag or append a terminal hop for a repeated session ID.
		return nil
	}
	if len(b.chain) >= maxAgentBindings {
		return errAgentDenied
	}
	forwarding := rest[0] == 1
	b.chain = append(b.chain, agentSessionBinding{hostKey: key, session: bytes.Clone(session), forwarding: forwarding})
	b.forwarded = b.forwarded || forwarding
	return nil
}
