package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAgentRegistryDiscoveryAndExactRead(t *testing.T) {
	rec, raw := testAgentKey(t)
	reg, err := parseAgentRegistry(registryJSON(t, rec))
	if err != nil {
		t.Fatal(err)
	}
	identities, err := reg.List(context.Background())
	if err != nil || len(identities) != 1 {
		t.Fatalf("List: %v, %d", err, len(identities))
	}
	store := &fakeKeyMaterialStore{data: raw}
	if store.calls != 0 {
		t.Fatal("discovery fetched private material")
	}
	called := false
	err = reg.withKey(context.Background(), rec.ID, store, func(s ssh.Signer) error {
		called = true
		sig, err := s.Sign(rand.Reader, []byte("challenge"))
		if err != nil {
			return err
		}
		return identities[0].PublicKey.Verify([]byte("challenge"), sig)
	})
	if err != nil || !called || store.calls != 1 || store.ref.ID != rec.Reference || store.ref.Backend != rec.Backend {
		t.Fatalf("exact read: %v, %+v", err, store.ref)
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("owned material not cleared")
	}
	// The public key returned by discovery is not the trusted registry's object.
	exposed := identities[0].PublicKey.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	exposed[0] ^= 1
	again, _ := reg.List(context.Background())
	if bytes.Equal(again[0].PublicKey.Marshal(), identities[0].PublicKey.Marshal()) {
		t.Fatal("registry was mutated by caller")
	}
}

func TestAgentRegistryReadErrorsAreSanitized(t *testing.T) {
	rec, raw := testAgentKey(t)
	reg, _ := parseAgentRegistry(registryJSON(t, rec))
	for _, providerErr := range []error{errors.New("private fixture leaked by provider"), errCredentialLocked, errCredentialProviderChanged, context.Canceled, context.DeadlineExceeded, errCredentialReference, errCredentialTooLarge} {
		data := append([]byte(nil), raw...)
		store := &fakeKeyMaterialStore{data: data, err: providerErr}
		err := reg.withKey(context.Background(), rec.ID, store, func(ssh.Signer) error { t.Fatal("callback after failure"); return nil })
		if err == nil || strings.Contains(err.Error(), "fixture") || !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("unsafe failure")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reg.List(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := reg.withKey(ctx, rec.ID, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := reg.withKey(context.Background(), rec.ID, nil, nil); !errors.Is(err, errCredentialRead) {
		t.Fatal(err)
	}
	_, other := testAgentKey(t)
	if err := reg.withKey(context.Background(), rec.ID, &fakeKeyMaterialStore{data: other}, func(ssh.Signer) error { t.Fatal("wrong key used"); return nil }); !errors.Is(err, errKeyMismatch) {
		t.Fatal(err)
	}
}
