package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAgentUnsupportedMethods(t *testing.T) {
	s, _, pub := agentTestService(t)
	a := &agentConnection{ctx: context.Background(), keys: s}
	for _, err := range []error{a.Add(agent.AddedKey{}), a.Remove(pub), a.RemoveAll(), a.Lock([]byte("secret")), a.Unlock([]byte("secret"))} {
		if err == nil {
			t.Fatal("unsupported operation succeeded")
		}
	}
	if _, err := a.Signers(); err == nil {
		t.Fatal("exposed signer")
	}
}

func TestAgentFrameGateAndOneRequestDispatch(t *testing.T) {
	service, backend, pub := agentTestService(t)
	a := &agentConnection{ctx: context.Background(), keys: service}
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	for _, opcode := range []byte{1, 3, 7, 8, 9, 17, 18, 19, 20, 21, 22, 23, 25, 26, 255} {
		body := append([]byte{opcode}, []byte("synthetic-private-payload")...)
		reply, err := dispatchAgentFrame(a, body)
		if err != nil || !bytes.Equal(reply, agentPacket([]byte{5})) {
			t.Fatalf("opcode %d: %v", opcode, err)
		}
	}
	if backend.opens.Load() != 0 || logs.Len() != 0 {
		t.Fatal("blocked frame reached key parser")
	}
	for _, body := range [][]byte{nil, {11, 0}, {13}, {13, 0, 0, 0, 2, 1}, append(agentSignBody(pub, nil, 0), 0), bytes.Repeat([]byte{11}, maxAgentFrameBytes+1)} {
		reply, err := dispatchAgentFrame(a, body)
		if err == nil || !bytes.Equal(reply, agentPacket([]byte{5})) {
			t.Fatal("malformed frame accepted")
		}
	}
	for i := 0; i < 3; i++ {
		reply, err := dispatchAgentFrame(a, []byte{11})
		if err != nil || reply[4] != 12 || binary.BigEndian.Uint32(reply[5:9]) != 1 {
			t.Fatal("List dispatch", err)
		}
		reply, err = dispatchAgentFrame(a, agentSignBody(pub, []byte("challenge"), 0))
		if err != nil || reply[4] != 14 {
			t.Fatal("Sign dispatch", err)
		}
		blob, rest, ok := agentWireString(reply[5:])
		if !ok || len(rest) != 0 {
			t.Fatal("bad reply")
		}
		var sig ssh.Signature
		if ssh.Unmarshal(blob, &sig) != nil || pub.Verify([]byte("challenge"), &sig) != nil {
			t.Fatal("wire signature failed")
		}
	}
	if bytes.Contains(logs.Bytes(), []byte("synthetic-private")) {
		t.Fatal("private input logged")
	}
	backend.assertCleared(t)
}

type shortAgentWriter struct {
	bytes.Buffer
	n   int
	err error
}

func (w *shortAgentWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(p) > w.n {
		p = p[:w.n]
	}
	return w.Buffer.Write(p)
}

func TestAgentReplyBoundsAndShortWrites(t *testing.T) {
	w := &shortAgentWriter{n: 2}
	data := agentPacket([]byte{5})
	if err := writeAgentReply(w, data); err != nil || !bytes.Equal(w.Bytes(), data) {
		t.Fatal("short write handling", err)
	}
	if err := writeAgentReply(&shortAgentWriter{}, data); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := writeAgentReply(&shortAgentWriter{err: io.ErrClosedPipe}, data); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	rw := &agentFrameExchange{reader: bytes.NewReader(nil)}
	if _, err := rw.Write(make([]byte, maxAgentFrameBytes+5)); err == nil {
		t.Fatal("reply was unbounded")
	}
}

func FuzzAgentFrameGate(f *testing.F) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub, _ := ssh.NewPublicKey(private.Public())
	record := agentKeyRecord{ID: "fuzz-key", Reference: "fuzz-key", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), Backend: credentialBackendGopass, Policy: "unrestricted-local", Enabled: true}
	data, _ := json.Marshal(agentRegistryDocument{Version: 1, Keys: []agentKeyRecord{record}})
	registry, err := parseAgentRegistry(data)
	if err != nil {
		f.Fatal(err)
	}
	service, err := newAgentKeyService(registry, func(context.Context, credentialBackend) (credentialKeyStore, error) { return nil, errAgentDenied })
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{{11}, {11, 0}, {13}, {17}, agentSignBody(pub, []byte("data"), 0), {27, 0, 0, 0, 1, 'x'}, nil} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		reply, _ := dispatchAgentFrame(&agentConnection{ctx: context.Background(), keys: service}, body)
		if len(reply) < 5 || len(reply) > maxAgentFrameBytes+4 || int(binary.BigEndian.Uint32(reply[:4])) != len(reply)-4 {
			t.Fatal("invalid response frame")
		}
	})
}
