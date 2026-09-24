package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	maxAgentFrameBytes      = 256 * 1024
	agentFailureCode   byte = 5
	agentListCode      byte = 11
	agentSignCode      byte = 13
	agentExtensionCode byte = 27
)

// One adapter per socket; its state is never shared with another connection.
// Requests on a connection are processed serially by the outer frame loop.
type agentConnection struct {
	ctx      context.Context
	keys     *agentKeyService
	denied   bool
	bindings agentBindingState
}

var _ agent.ExtendedAgent = (*agentConnection)(nil)

func (a *agentConnection) List() ([]*agent.Key, error) {
	if a.denied || a.ctx.Err() != nil {
		return nil, errAgentDenied
	}
	return a.keys.list(a.ctx, &a.bindings)
}
func (a *agentConnection) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}
func (a *agentConnection) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if a.denied || key == nil {
		a.keys.debug("sign denied: connection rejected or key absent")
		return nil, errAgentDenied
	}
	blob := key.Marshal()
	if err := a.keys.refresh(); err != nil {
		return nil, errAgentDenied
	}
	registered, ok := a.keys.lookup(blob)
	if !ok {
		a.keys.debug("sign denied: identity not registered or disabled")
		return nil, errAgentDenied
	}
	algorithm := registered.publicKey.Type()
	if algorithm == ssh.KeyAlgoRSA {
		switch flags {
		case agent.SignatureFlagRsaSha256:
			algorithm = ssh.KeyAlgoRSASHA256
		case agent.SignatureFlagRsaSha512:
			algorithm = ssh.KeyAlgoRSASHA512
		default:
			return nil, errAgentDenied
		}
	} else if flags != 0 {
		return nil, errAgentDenied
	}
	return a.keys.signBound(a.ctx, blob, data, algorithm, &a.bindings)
}

// Mutations are handled exclusively by the raw frame gate, preserving every
// constraint and validating private fields before the upstream parser runs.
func (*agentConnection) Add(agent.AddedKey) error       { return errAgentDenied }
func (*agentConnection) Remove(ssh.PublicKey) error     { return errAgentDenied }
func (*agentConnection) RemoveAll() error               { return errAgentDenied }
func (*agentConnection) Lock([]byte) error              { return errAgentDenied }
func (*agentConnection) Unlock([]byte) error            { return errAgentDenied }
func (*agentConnection) Signers() ([]ssh.Signer, error) { return nil, errAgentDenied }
func (a *agentConnection) Extension(name string, contents []byte) ([]byte, error) {
	if name != sessionBindExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	// Binding provenance must be processed even while signing is locked or a
	// verified forwarding chain is denied by the current local-only policy.
	if a.ctx.Err() != nil || a.bindings.record(contents) != nil {
		a.denied = true
		a.bindings.poisoned = true
		a.keys.debug("binding denied: invalid proof, sequence or canceled connection")
		return nil, errAgentDenied
	}
	if a.bindings.forwarded {
		a.keys.debug("binding denied: forwarding disabled")
		a.denied = true
		return nil, errAgentDenied
	}
	a.keys.debug("direct session binding accepted")
	return []byte{6}, nil
}
func agentWireString(data []byte) (value, rest []byte, ok bool) {
	if len(data) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(data[:4])
	if uint64(n) > uint64(len(data)-4) {
		return nil, nil, false
	}
	return data[4 : 4+int(n)], data[4+int(n):], true
}
func agentPacket(payload []byte) []byte {
	packet := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(packet, uint32(len(payload)))
	copy(packet[4:], payload)
	return packet
}

// No blocked opcode ever reaches ServeAgent's ADD/private-key parser. Validate
// admitted bodies first, and expose only fixed errors to upstream. The server
// additionally disables upstream global logging once before serving.
func dispatchAgentFrame(a *agentConnection, body []byte) ([]byte, error) {
	failure := agentPacket([]byte{agentFailureCode})
	if len(body) == 0 || len(body) > maxAgentFrameBytes {
		return failure, errAgentProtocol
	}
	if a.denied && body[0] != agentExtensionCode {
		return failure, nil
	}
	switch body[0] {
	case 17, 18, 19, 22, 23, 25:
		return a.dispatchMutation(body)
	case agentListCode:
		if len(body) != 1 {
			return failure, errAgentProtocol
		}
	case agentSignCode:
		blob, rest, ok := agentWireString(body[1:])
		if !ok || len(blob) == 0 || len(blob) > 16384 {
			return failure, errAgentProtocol
		}
		_, rest, ok = agentWireString(rest)
		if !ok || len(rest) != 4 {
			return failure, errAgentProtocol
		}
		// Exact registered bytes, not attacker-supplied type strings, reach upstream.
		if err := a.keys.refresh(); err != nil {
			return failure, nil
		}
		if _, ok := a.keys.lookup(blob); !ok {
			a.keys.debug("sign denied: identity not registered or disabled")
			return failure, nil
		}
	case agentExtensionCode:
		name, contents, ok := agentWireString(body[1:])
		if !ok || len(name) == 0 || len(name) > 256 {
			a.denied = true
			a.bindings.poisoned = true
			a.keys.debug("binding denied: invalid proof, sequence or canceled connection")
			return failure, errAgentProtocol
		}
		reply, err := a.Extension(string(name), contents)
		if err == agent.ErrExtensionUnsupported {
			return failure, nil
		}
		if err != nil {
			return agentPacket([]byte{28}), nil
		}
		return agentPacket(reply), nil
	default:
		return failure, nil
	}
	// ServeAgent reads one request, writes exactly one response, then sees EOF.
	// There is no goroutine or pipe, and the connection adapter persists.
	packet := agentPacket(body)
	defer clearBytes(packet)
	rw := &agentFrameExchange{reader: bytes.NewReader(packet)}
	err := agent.ServeAgent(a, rw)
	if !errors.Is(err, io.EOF) || rw.output.Len() < 5 {
		return failure, errAgentProtocol
	}
	reply := rw.output.Bytes()
	if int(binary.BigEndian.Uint32(reply[:4])) != len(reply)-4 {
		return failure, errAgentProtocol
	}
	return reply, nil
}

type agentFrameExchange struct {
	reader *bytes.Reader
	output bytes.Buffer
}

func (r *agentFrameExchange) Read(p []byte) (int, error) { return r.reader.Read(p) }
func (r *agentFrameExchange) Write(p []byte) (int, error) {
	if len(p) > maxAgentFrameBytes+4-r.output.Len() {
		return 0, errAgentProtocol
	}
	return r.output.Write(p)
}
func writeAgentReply(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
