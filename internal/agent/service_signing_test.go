package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

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
