package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func assertKeyMaterialValidation(t *testing.T, data []byte, public ssh.PublicKey, passphrase []byte, want error) {
	t.Helper()
	beforeData, beforePassphrase := bytes.Clone(data), bytes.Clone(passphrase)
	var beforePublic []byte
	if public != nil {
		beforePublic = bytes.Clone(public.Marshal())
	}
	err := ValidateKeyMaterial(context.Background(), data, public, passphrase)
	if err != want {
		t.Fatalf("validation error = %v, want %v", err, want)
	}
	if !bytes.Equal(data, beforeData) || !bytes.Equal(passphrase, beforePassphrase) {
		t.Fatal("validation mutated borrowed buffers")
	}
	if public != nil && !bytes.Equal(public.Marshal(), beforePublic) {
		t.Fatal("validation mutated expected public key")
	}
	// Exact sentinel errors above also ensure parser details and secrets cannot
	// escape through wrapped errors.
	if err != nil && (strings.Contains(err.Error(), "secret-marker") || strings.Contains(err.Error(), "BEGIN")) {
		t.Fatal("validation exposed secret material")
	}
}

func TestValidateKeyMaterialFormats(t *testing.T) {
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
	for _, key := range keys {
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(key, "secret-marker")
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		blocks := []*pem.Block{block, {Type: "PRIVATE KEY", Bytes: der}}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			blocks = append(blocks, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				t.Fatal(err)
			}
			blocks = append(blocks, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		}
		for _, block := range blocks {
			t.Run(fmt.Sprintf("%s/%s", signer.PublicKey().Type(), block.Type), func(t *testing.T) {
				data := pem.EncodeToMemory(block)
				for _, passphrase := range [][]byte{nil, []byte("unused-secret-marker"), bytes.Repeat([]byte("x"), maxAgentPassphraseBytes+1)} {
					assertKeyMaterialValidation(t, data, signer.PublicKey(), passphrase, nil)
				}
				parsed, err := parseAgentKeyWithPassphrase(data, signer.PublicKey(), nil)
				if err != nil {
					t.Fatal(err)
				}
				challenge := []byte("validation challenge")
				signature, err := parsed.Sign(rand.Reader, challenge)
				if err != nil || signer.PublicKey().Verify(challenge, signature) != nil {
					t.Fatal("validated signer cannot sign", err)
				}
			})
		}
	}
}

func TestValidateKeyMaterialBoundsAndErrors(t *testing.T) {
	record, raw := testAgentKey(t)
	public := policyPublic(t, record)
	other, _ := testAgentKey(t)
	assertKeyMaterialValidation(t, raw, policyPublic(t, other), nil, errKeyMismatch)
	assertKeyMaterialValidation(t, raw, nil, nil, errKeyMismatch)
	atLimit := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), 64*1024-len(raw))...)
	assertKeyMaterialValidation(t, atLimit, public, nil, nil)
	assertKeyMaterialValidation(t, append(bytes.Clone(atLimit), ' '), public, nil, errCredentialTooLarge)
	for _, data := range [][]byte{
		nil, []byte("secret-marker"),
		append(bytes.Clone(raw), raw...), append(bytes.Clone(raw), []byte("secret-marker")...),
		[]byte("-----BEGIN PRIVATE KEY-----\nsecret-marker\n-----END PRIVATE KEY-----"),
		pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("secret-marker")}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte("secret-marker")}),
	} {
		assertKeyMaterialValidation(t, data, public, []byte("secret-marker"), errKeyUnsupported)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// An inconsistent Ed25519 seed must not pass merely because its embedded
	// public half matches the expected identity.
	pub, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	private[0] ^= 1
	block, err := ssh.MarshalPrivateKey(private, "secret-marker")
	if err != nil {
		t.Fatal(err)
	}
	assertKeyMaterialValidation(t, pem.EncodeToMemory(block), pub, nil, errKeyUnsupported)

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakSigner, err := ssh.NewSignerFromKey(weakRSA)
	if err != nil {
		t.Fatal(err)
	}
	assertKeyMaterialValidation(t, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weakRSA)}), weakSigner.PublicKey(), nil, errKeyUnsupported)
}

func validationEncryptedKey(t *testing.T) ([]byte, ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "secret-marker", []byte("secret-marker-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), public, private
}

func TestValidateKeyMaterialEncrypted(t *testing.T) {
	raw, public, private := validationEncryptedKey(t)
	passphrase := []byte("secret-marker-passphrase")
	assertKeyMaterialValidation(t, raw, public, passphrase, nil)
	for _, pass := range [][]byte{nil, {}, []byte("wrong-secret-marker"), bytes.Repeat([]byte("x"), maxAgentPassphraseBytes), bytes.Repeat([]byte("x"), maxAgentPassphraseBytes+1)} {
		assertKeyMaterialValidation(t, raw, public, pass, errAgentPassphrase)
	}
	assertKeyMaterialValidation(t, raw, nil, passphrase, errKeyMismatch)
	other, _ := testAgentKey(t)
	otherPublic := policyPublic(t, other)
	assertKeyMaterialValidation(t, raw, otherPublic, passphrase, errKeyMismatch)

	block, _ := pem.Decode(raw)
	defer clearBytes(block.Bytes)
	var envelope encryptedTestEnvelope
	if err := ssh.Unmarshal(block.Bytes[len("openssh-key-v1\x00"):], &envelope); err != nil {
		t.Fatal(err)
	}
	// Pin a different envelope identity while retaining the original encrypted
	// private key, forcing mismatch detection after decryption.
	envelope.Public = otherPublic.Marshal()
	changed := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)})
	assertKeyMaterialValidation(t, changed, otherPublic, passphrase, errKeyMismatch)

	// Excessive KDF work must be rejected by envelope inspection, not by the
	// passphrase check or upstream decryption (which returns errAgentPassphrase).
	envelope.Public = public.Marshal()
	binary.BigEndian.PutUint32(envelope.Options[len(envelope.Options)-4:], maxAgentBcryptRounds+1)
	changed = pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)})
	for _, pass := range [][]byte{nil, passphrase} {
		assertKeyMaterialValidation(t, changed, public, pass, errKeyUnsupported)
	}

	private[0] ^= 1
	inconsistent, err := ssh.MarshalPrivateKeyWithPassphrase(private, "secret-marker", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	assertKeyMaterialValidation(t, pem.EncodeToMemory(inconsistent), public, passphrase, errKeyUnsupported)
}

type validationCancelPublicKey struct {
	ssh.PublicKey
	cancel context.CancelFunc
}

func (p validationCancelPublicKey) Marshal() []byte {
	p.cancel()
	return p.PublicKey.Marshal()
}

func TestValidateKeyMaterialContext(t *testing.T) {
	record, raw := testAgentKey(t)
	public := policyPublic(t, record)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ValidateKeyMaterial(ctx, nil, nil, nil); err != context.Canceled {
		t.Fatal("cancellation did not precede parsing", err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := ValidateKeyMaterial(ctx, raw, public, nil); err != context.DeadlineExceeded {
		t.Fatal(err)
	}
	other, _ := testAgentKey(t)
	for _, expected := range []ssh.PublicKey{public, policyPublic(t, other)} {
		ctx, cancel := context.WithCancel(context.Background())
		before := bytes.Clone(raw)
		err := ValidateKeyMaterial(ctx, raw, validationCancelPublicKey{expected, cancel}, nil)
		cancel()
		if err != context.Canceled || !bytes.Equal(raw, before) {
			t.Fatal("post-validation cancellation or buffer ownership failed", err)
		}
	}
}

func TestAgentKeyPromptValidationCheckpoints(t *testing.T) {
	raw, public, _ := validationEncryptedKey(t)
	for _, tc := range []struct {
		name       string
		passphrase string
		failAt     int
		want       error
		sequence   string
	}{
		{"success", "secret-marker-passphrase", 0, nil, "check,prompt,check,check"},
		{"wrong", "wrong-secret-marker", 0, errAgentPassphrase, "check,prompt,check"},
		{"empty", "", 0, errAgentPassphrase, "check,prompt"},
		{"excess", strings.Repeat("x", maxAgentPassphraseBytes+1), 0, errAgentPassphrase, "check,prompt"},
		{"before prompt", "secret-marker-passphrase", 1, errCredentialLocked, "check"},
		{"before parse", "secret-marker-passphrase", 2, errCredentialLocked, "check,prompt,check"},
		{"after parse", "secret-marker-passphrase", 3, errCredentialLocked, "check,prompt,check,check"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sequence []string
			var owned []byte
			checks := 0
			prompt := &agentPrompter{ask: func(_ context.Context, request agentPromptRequest) ([]byte, error) {
				if request.Operation != "passphrase" {
					t.Fatal("unexpected prompt operation")
				}
				sequence = append(sequence, "prompt")
				owned = []byte(tc.passphrase)
				return owned, nil
			}}
			signer, err := parseAgentKeyWithPrompt(context.Background(), raw, public, prompt, agentPromptRequest{}, func() error {
				sequence = append(sequence, "check")
				checks++
				if checks == tc.failAt {
					return errCredentialLocked
				}
				return nil
			})
			if !errors.Is(err, tc.want) || (signer == nil) != (tc.want != nil) || strings.Join(sequence, ",") != tc.sequence {
				t.Fatalf("error = %v, sequence = %v", err, sequence)
			}
			if !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("prompt-owned passphrase not cleared")
			}
		})
	}

	block, _ := pem.Decode(raw)
	defer clearBytes(block.Bytes)
	var envelope encryptedTestEnvelope
	if err := ssh.Unmarshal(block.Bytes[len("openssh-key-v1\x00"):], &envelope); err != nil {
		t.Fatal(err)
	}
	other, unencrypted := testAgentKey(t)
	otherPublic := policyPublic(t, other)
	envelope.Public = otherPublic.Marshal()
	changed := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)})
	for _, denyAfter := range []bool{false, true} {
		checks := 0
		prompt := &agentPrompter{ask: func(context.Context, agentPromptRequest) ([]byte, error) {
			return []byte("secret-marker-passphrase"), nil
		}}
		signer, err := parseAgentKeyWithPrompt(context.Background(), changed, otherPublic, prompt, agentPromptRequest{}, func() error {
			checks++
			if denyAfter && checks == 3 {
				return errCredentialLocked
			}
			return nil
		})
		want := errKeyMismatch
		if denyAfter {
			want = errCredentialLocked
		}
		if signer != nil || err != want || checks != 3 {
			t.Fatalf("decrypted mismatch checkpoint: error = %v, checks = %d", err, checks)
		}
	}
	if _, err := parseAgentKeyWithPrompt(context.Background(), unencrypted, otherPublic, nil, agentPromptRequest{}, func() error {
		t.Fatal("unencrypted parsing added an authorization checkpoint")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
