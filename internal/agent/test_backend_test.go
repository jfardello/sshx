package agent

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

type fakeKeyMaterialStore struct {
	data  []byte
	err   error
	calls int
	ref   credentialRef
}

func (s *fakeKeyMaterialStore) KeyMaterial(ctx context.Context, ref credentialRef) ([]byte, error) {
	s.calls++
	s.ref = ref
	return s.data, s.err
}

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
