package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type agentTestBackend struct {
	data     map[string][]byte
	opens    atomic.Int32
	reads    atomic.Int32
	closes   atomic.Int32
	mutex    sync.Mutex
	buffers  [][]byte
	read     func(context.Context) error
	openErr  error
	closeErr error
}
type agentTestStore struct{ backend *agentTestBackend }

func denyAgentStore(context.Context, credentialBackend) (credentialKeyStore, error) {
	return nil, errAgentDenied
}

func (b *agentTestBackend) open(ctx context.Context, backend credentialBackend) (credentialKeyStore, error) {
	b.opens.Add(1)
	if backend != credentialBackendGopass {
		return nil, errAgentDenied
	}
	if b.openErr != nil {
		return nil, b.openErr
	}
	return &agentTestStore{b}, nil
}
func (s *agentTestStore) Search(context.Context, credentialQuery) ([]credentialRef, error) {
	panic("agent must not discover backend secrets")
}
func (s *agentTestStore) Secret(context.Context, credentialRef, credentialReadOptions) ([]byte, error) {
	panic("agent must not use password reads")
}
func (s *agentTestStore) Close() error { s.backend.closes.Add(1); return s.backend.closeErr }
func (s *agentTestStore) KeyMaterial(ctx context.Context, ref credentialRef) ([]byte, error) {
	b := s.backend
	b.reads.Add(1)
	if b.read != nil {
		if err := b.read(ctx); err != nil {
			return nil, err
		}
	}
	raw := append([]byte(nil), b.data[ref.ID]...)
	b.mutex.Lock()
	b.buffers = append(b.buffers, raw)
	b.mutex.Unlock()
	return raw, nil
}
func (b *agentTestBackend) assertCleared(t *testing.T) {
	t.Helper()
	b.mutex.Lock()
	defer b.mutex.Unlock()
	for _, buffer := range b.buffers {
		if !bytes.Equal(buffer, make([]byte, len(buffer))) {
			t.Fatal("private material retained")
		}
	}
}
func agentTestService(t *testing.T) (*agentKeyService, *agentTestBackend, ssh.PublicKey) {
	t.Helper()
	record, raw := testAgentKey(t)
	registry, err := parseAgentRegistry(registryJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
	service, err := newAgentKeyService(registry, backend.open)
	if err != nil {
		t.Fatal(err)
	}
	return service, backend, registry.keys[0].publicKey
}
func agentTestRecord(t *testing.T, private any, id string) (agentKeyRecord, []byte, ssh.PublicKey) {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	return agentKeyRecord{ID: id, PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), Enabled: true, Policy: "unrestricted-local", Backend: credentialBackendGopass, Reference: id}, pem.EncodeToMemory(block), signer.PublicKey()
}
func TestAgentSignaturesAndFlags(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := []any{ed, rsaKey}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	for _, private := range keys {
		record, raw, pub := agentTestRecord(t, private, "key")
		t.Run(pub.Type(), func(t *testing.T) {
			registry, err := parseAgentRegistry(registryJSON(t, record))
			if err != nil {
				t.Fatal(err)
			}
			backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
			service, err := newAgentKeyService(registry, backend.open)
			if err != nil {
				t.Fatal(err)
			}
			conn := &agentConnection{ctx: context.Background(), keys: service}
			listed, err := conn.List()
			if err != nil || len(listed) != 1 || backend.opens.Load() != 0 {
				t.Fatal("List touched backend", err)
			}
			flags := []agent.SignatureFlags{0}
			formats := []string{pub.Type()}
			if pub.Type() == ssh.KeyAlgoRSA {
				flags = []agent.SignatureFlags{2, 4}
				formats = []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
			}
			for i, flag := range flags {
				sig, err := conn.SignWithFlags(pub, []byte("independent challenge"), flag)
				if err != nil {
					t.Fatal(err)
				}
				if sig.Format != formats[i] || pub.Verify([]byte("independent challenge"), sig) != nil {
					t.Fatal("invalid signature or wrong algorithm")
				}
			}
			opens := backend.opens.Load()
			invalid := []agent.SignatureFlags{1, 3, 6, 8, 0xffffffff}
			if pub.Type() == ssh.KeyAlgoRSA {
				invalid = append(invalid, 0)
			} else {
				invalid = append(invalid, 2, 4)
			}
			for _, flag := range invalid {
				if sig, err := conn.SignWithFlags(pub, []byte("data"), flag); err == nil || sig != nil {
					t.Fatalf("accepted flags %d", flag)
				}
			}
			if backend.opens.Load() != opens || backend.closes.Load() != opens {
				t.Fatal("invalid flags fetched key or store not closed")
			}
			backend.assertCleared(t)
		})
	}
}
func TestAgentLazyReadsAndFailures(t *testing.T) {
	service, backend, pub := agentTestService(t)
	conn := &agentConnection{ctx: context.Background(), keys: service}
	for i := 0; i < 2; i++ {
		if _, err := conn.Sign(pub, []byte("data")); err != nil {
			t.Fatal(err)
		}
	}
	if backend.reads.Load() != 2 || backend.closes.Load() != 2 {
		t.Fatal("signer cached or connection retained")
	}
	_, unknownRaw := testAgentKey(t)
	backend.data["keys/test-key"] = unknownRaw
	if sig, err := conn.Sign(pub, []byte("data")); err == nil || sig != nil {
		t.Fatal("accepted replaced private key")
	}
	backend.assertCleared(t)
	for _, failure := range []string{"open", "read", "close"} {
		t.Run(failure, func(t *testing.T) {
			s, b, key := agentTestService(t)
			marker := errors.New("synthetic-private-error")
			switch failure {
			case "open":
				b.openErr = marker
			case "read":
				b.read = func(context.Context) error { return marker }
			case "close":
				b.closeErr = marker
			}
			sig, err := (&agentConnection{ctx: context.Background(), keys: s}).Sign(key, []byte("data"))
			if sig != nil || err == nil || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("unsafe failure")
			}
			b.assertCleared(t)
		})
	}
	other, _, unknown := agentTestService(t)
	_ = other
	before := backend.opens.Load()
	if _, err := conn.Sign(unknown, nil); err == nil {
		t.Fatal("accepted unknown key")
	}
	if _, err := conn.Sign(nil, nil); err == nil {
		t.Fatal("accepted nil key")
	}
	if _, err := service.sign(context.Background(), pub.Marshal(), nil, ssh.KeyAlgoRSASHA512); err == nil {
		t.Fatal("accepted wrong algorithm")
	}
	if backend.opens.Load() != before {
		t.Fatal("invalid request opened backend")
	}
}
func TestAgentSigningCapacityAndCancellation(t *testing.T) {
	s, b, pub := agentTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, maxAgentSigningJobs)
	b.read = func(ctx context.Context) error { entered <- struct{}{}; <-ctx.Done(); return ctx.Err() }
	done := make(chan error, maxAgentSigningJobs)
	for i := 0; i < maxAgentSigningJobs; i++ {
		go func() { _, err := (&agentConnection{ctx: ctx, keys: s}).Sign(pub, nil); done <- err }()
	}
	for i := 0; i < maxAgentSigningJobs; i++ {
		<-entered
	}
	if _, err := (&agentConnection{ctx: ctx, keys: s}).Sign(pub, nil); !errors.Is(err, errAgentBusy) {
		t.Fatal("capacity not bounded", err)
	}
	cancel()
	for i := 0; i < maxAgentSigningJobs; i++ {
		if err := <-done; err == nil {
			t.Fatal("cancelled signature succeeded")
		}
	}
	if len(s.jobs) != 0 || b.closes.Load() != maxAgentSigningJobs {
		t.Fatal("signing resources retained")
	}
	if _, err := s.sign(ctx, pub.Marshal(), nil, pub.Type()); err == nil {
		t.Fatal("ignored cancelled context")
	}
}
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
func agentSignBody(pub ssh.PublicKey, data []byte, flags uint32) []byte {
	return ssh.Marshal(struct {
		Key   []byte `sshtype:"13"`
		Data  []byte
		Flags uint32
	}{pub.Marshal(), data, flags})
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
func testAgentBind(t *testing.T, forward byte) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte("test session")
	sig, err := signer.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	contents := ssh.Marshal(struct {
		Host, Session, Signature []byte
		Forward                  byte
	}{signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), forward})
	return ssh.Marshal(struct {
		Name     string `sshtype:"27"`
		Contents []byte `ssh:"rest"`
	}{"session-bind@openssh.com", contents})
}
func TestAgentForwardingDenialIsConnectionLocal(t *testing.T) {
	s, b, pub := agentTestService(t)
	for _, body := range [][]byte{testAgentBind(t, 1), testAgentBind(t, 2), {27, 0, 0, 0, 99}, append(testAgentBind(t, 0), 0)} {
		a := &agentConnection{ctx: context.Background(), keys: s}
		if reply, _ := dispatchAgentFrame(a, body); reply[4] == 6 {
			t.Fatal("binding claimed success")
		}
		if !a.denied {
			t.Fatal("unsafe bind did not poison connection")
		}
		if reply, _ := dispatchAgentFrame(a, []byte{11}); reply[4] != 5 {
			t.Fatal("poisoned connection can List")
		}
		if _, err := a.Sign(pub, nil); err == nil {
			t.Fatal("poisoned connection can sign")
		}
		if _, err := a.Extension("other", nil); err == nil {
			t.Fatal("poisoned extension succeeded")
		}
	}
	clean := &agentConnection{ctx: context.Background(), keys: s}
	if reply, err := dispatchAgentFrame(clean, testAgentBind(t, 0)); err != nil || reply[4] != 5 || clean.denied {
		t.Fatal("direct unverified bind must remain unsupported", err)
	}
	if keys, err := clean.List(); err != nil || len(keys) != 1 {
		t.Fatal("one connection poisoned another")
	}
	if b.opens.Load() != 0 {
		t.Fatal("binding or List opened provider")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	clean.ctx = ctx
	if _, err := clean.List(); err == nil {
		t.Fatal("cancelled List succeeded")
	}
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
func TestAgentRegistryAdmission(t *testing.T) {
	if _, err := newAgentKeyService(nil, nil); err == nil {
		t.Fatal("nil registry")
	}
	record, _ := testAgentKey(t)
	registry, _ := parseAgentRegistry(registryJSON(t, record))
	registry.keys[0].record.Policy = "destination-constrained"
	if _, err := newAgentKeyService(registry, denyAgentStore); err == nil {
		t.Fatal("activated constrained policy")
	}
	registry, _ = parseAgentRegistry(registryJSON(t, record))
	s, err := newAgentKeyService(registry, denyAgentStore)
	if err != nil {
		t.Fatal(err)
	}
	registry.keys[0].record.Enabled = false
	if list, err := s.registry.List(context.Background()); err != nil || len(list) != 1 {
		t.Fatal("caller mutated registry snapshot")
	}
}

func TestAgentIdentityCountLimit(t *testing.T) {
	records := make([]agentKeyRecord, 0, maxAgentIdentities+1)
	for i := 0; i <= maxAgentIdentities; i++ {
		record, _ := testAgentKey(t)
		record.ID = fmt.Sprintf("key-%d", i)
		record.Reference = record.ID
		records = append(records, record)
	}
	registry, err := parseAgentRegistry(registryJSON(t, records...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAgentKeyService(registry, denyAgentStore); err == nil {
		t.Fatal("identity count not bounded")
	}
}
func TestAgentIdentityReplySizeLimit(t *testing.T) {
	records := make([]agentKeyRecord, 0, maxAgentIdentities)
	base := new(big.Int).Lsh(big.NewInt(1), 8191)
	for i := 0; i < maxAgentIdentities; i++ {
		n := new(big.Int).Add(base, big.NewInt(int64(2*i+1)))
		pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: 65537})
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("key-%d", i)
		records = append(records, agentKeyRecord{ID: id, Reference: id, PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), Comment: strings.Repeat("x", 128), Backend: credentialBackendGopass, Policy: "unrestricted-local", Enabled: true})
	}
	registry, err := parseAgentRegistry(registryJSON(t, records...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAgentKeyService(registry, denyAgentStore); err == nil {
		t.Fatal("identity reply size not bounded")
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
