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
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func assertRegistrationKey(t *testing.T, ctx context.Context, data []byte, prompt func(context.Context) ([]byte, error), expected ssh.PublicKey, want error) {
	t.Helper()
	before := bytes.Clone(data)
	public, err := RegistrationPublicKey(ctx, data, prompt)
	if err != want {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if want != nil {
		if public != nil {
			t.Fatal("returned a public identity on validation failure")
		}
	} else if public == nil || !bytes.Equal(public.Marshal(), expected.Marshal()) {
		t.Fatal("incorrect derived identity")
	}
	if !bytes.Equal(data, before) {
		t.Fatal("modified borrowed key data")
	}
}

func registrationNoPrompt(t *testing.T) func(context.Context) ([]byte, error) {
	t.Helper()
	return func(context.Context) ([]byte, error) {
		t.Fatal("rejected or unencrypted key prompted")
		return nil, nil
	}
}

func TestRegistrationPublicKeyFormats(t *testing.T) {
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
			t.Run(signer.PublicKey().Type()+"/"+block.Type, func(t *testing.T) {
				assertRegistrationKey(t, context.Background(), pem.EncodeToMemory(block), registrationNoPrompt(t), signer.PublicKey(), nil)
			})
		}
		t.Run(signer.PublicKey().Type()+"/encrypted", func(t *testing.T) {
			block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "secret-marker", []byte("secret-marker-passphrase"))
			if err != nil {
				t.Fatal(err)
			}
			owned := []byte("secret-marker-passphrase")
			assertRegistrationKey(t, context.Background(), pem.EncodeToMemory(block), func(context.Context) ([]byte, error) {
				return owned, nil
			}, signer.PublicKey(), nil)
			if !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("owned passphrase not cleared")
			}
		})
	}
}

func TestRegistrationPublicKeyBounds(t *testing.T) {
	record, raw := testAgentKey(t)
	public := policyPublic(t, record)
	atLimit := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), maxKeyMaterialBytes-len(raw))...)
	assertRegistrationKey(t, context.Background(), atLimit, registrationNoPrompt(t), public, nil)
	assertRegistrationKey(t, context.Background(), append(bytes.Clone(atLimit), ' '), registrationNoPrompt(t), nil, errCredentialTooLarge)
	for _, data := range [][]byte{
		nil, []byte("secret-marker"),
		append(bytes.Clone(raw), raw...), append(bytes.Clone(raw), []byte("secret-marker")...),
		append([]byte("secret-marker\n"), raw...),
		[]byte("-----BEGIN PRIVATE KEY-----\nsecret-marker\n-----END PRIVATE KEY-----"),
		pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("secret-marker")}),
		pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("secret-marker")}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte("secret-marker")}),
	} {
		assertRegistrationKey(t, context.Background(), data, registrationNoPrompt(t), nil, errKeyUnsupported)
	}
	// Reject ASN.1 integer and nesting excess before x509's arithmetic.
	integer, err := asn1.Marshal(new(big.Int).Lsh(big.NewInt(1), 1025*8))
	if err != nil {
		t.Fatal(err)
	}
	deep := []byte{2, 1, 1}
	for i := 0; i < 10; i++ {
		deep, err = asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: deep})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, der := range [][]byte{integer, deep} {
		for _, kind := range []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"} {
			material := der
			if kind == "PRIVATE KEY" {
				material, err = asn1.Marshal(struct {
					Version    int
					Algorithm  asn1.RawValue
					PrivateKey []byte
				}{0, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true}, der})
				if err != nil {
					t.Fatal(err)
				}
			}
			assertRegistrationKey(t, context.Background(), pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: material}), registrationNoPrompt(t), nil, errKeyUnsupported)
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(weak, "secret-marker")
	if err != nil {
		t.Fatal(err)
	}
	assertRegistrationKey(t, context.Background(), pem.EncodeToMemory(block), registrationNoPrompt(t), nil, errKeyUnsupported)
	assertRegistrationKey(t, context.Background(), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}), registrationNoPrompt(t), nil, errKeyUnsupported)
}

func registrationEnvelope(t *testing.T, raw []byte) encryptedTestEnvelope {
	t.Helper()
	block, _ := pem.Decode(raw)
	defer clearBytes(block.Bytes)
	var envelope encryptedTestEnvelope
	if err := ssh.Unmarshal(block.Bytes[len("openssh-key-v1\x00"):], &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Options = bytes.Clone(envelope.Options)
	envelope.Public = bytes.Clone(envelope.Public)
	envelope.Private = bytes.Clone(envelope.Private)
	return envelope
}

func registrationEncodeEnvelope(envelope encryptedTestEnvelope) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)})
}

func TestRegistrationPublicKeyEncryptedAdmission(t *testing.T) {
	raw, _, _ := validationEncryptedKey(t)
	original := registrationEnvelope(t, raw)
	for _, mode := range []string{"cipher", "kdf", "zero-rounds", "excess-rounds", "short-salt", "long-salt", "options-trailing", "options-truncated", "count", "public", "ciphertext", "trailing", "truncated", "magic"} {
		t.Run(mode, func(t *testing.T) {
			envelope := original
			envelope.Options = bytes.Clone(original.Options)
			switch mode {
			case "cipher":
				envelope.Cipher = "aes128-ctr"
			case "kdf":
				envelope.KDF = "unknown"
			case "zero-rounds":
				binary.BigEndian.PutUint32(envelope.Options[len(envelope.Options)-4:], 0)
			case "excess-rounds":
				binary.BigEndian.PutUint32(envelope.Options[len(envelope.Options)-4:], maxAgentBcryptRounds+1)
			case "short-salt", "long-salt":
				n := 15
				if mode == "long-salt" {
					n = 65
				}
				envelope.Options = ssh.Marshal(struct {
					Salt   []byte
					Rounds uint32
				}{make([]byte, n), 16})
			case "options-trailing":
				envelope.Options = append(envelope.Options, 0)
			case "options-truncated":
				envelope.Options = envelope.Options[:3]
			case "count":
				envelope.Count = 2
			case "public":
				envelope.Public = []byte("secret-marker")
			case "ciphertext":
				envelope.Private = make([]byte, 17)
			}
			data := append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)
			switch mode {
			case "trailing":
				data = append(data, 0)
			case "truncated":
				data = data[:len(data)-1]
			case "magic":
				data[0] ^= 1
			}
			assertRegistrationKey(t, context.Background(), pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: data}), registrationNoPrompt(t), nil, errKeyUnsupported)
		})
	}
}

func TestRegistrationPublicKeyEncryptedPrompt(t *testing.T) {
	raw, public, _ := validationEncryptedKey(t)
	assertRegistrationKey(t, context.Background(), raw, nil, nil, ErrKeyPassphrase)
	for _, tc := range []struct {
		name, pass        string
		callbackErr, want error
	}{
		{"success", "secret-marker-passphrase", nil, nil},
		{"wrong", "wrong-secret-marker", nil, ErrKeyPassphrase},
		{"empty", "", nil, ErrKeyPassphrase},
		{"excess", string(bytes.Repeat([]byte("x"), maxAgentPassphraseBytes+1)), nil, ErrKeyPassphrase},
		{"unknown", "secret-marker-passphrase", errors.New("secret-marker controlling terminal unavailable"), ErrKeyPassphrase},
		{"passphrase", "secret-marker-passphrase", fmt.Errorf("secret-marker: %w", ErrKeyPassphrase), ErrKeyPassphrase},
		{"cancel", "secret-marker-passphrase", fmt.Errorf("secret-marker: %w", context.Canceled), context.Canceled},
		{"deadline", "secret-marker-passphrase", fmt.Errorf("secret-marker: %w", context.DeadlineExceeded), context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owned := []byte(tc.pass)
			calls := 0
			assertRegistrationKey(t, context.Background(), raw, func(ctx context.Context) ([]byte, error) {
				calls++
				return owned, tc.callbackErr
			}, public, tc.want)
			if calls != 1 || !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("prompt count or owned buffer erasure failed")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	owned := []byte("secret-marker-passphrase")
	assertRegistrationKey(t, ctx, raw, func(got context.Context) ([]byte, error) {
		if got != ctx {
			t.Fatal("callback context changed")
		}
		cancel()
		return owned, errors.New("secret-marker")
	}, nil, context.Canceled)
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("cancelled buffer not cleared")
	}
}

func TestRegistrationPublicKeyConsistency(t *testing.T) {
	raw, public, private := validationEncryptedKey(t)
	other, unencrypted := testAgentKey(t)
	for _, data := range [][]byte{raw, unencrypted} {
		envelope := registrationEnvelope(t, data)
		replacement := public
		if bytes.Equal(envelope.Public, public.Marshal()) {
			replacement = policyPublic(t, other)
		}
		envelope.Public = replacement.Marshal()
		calls := 0
		assertRegistrationKey(t, context.Background(), registrationEncodeEnvelope(envelope), func(context.Context) ([]byte, error) {
			calls++
			return []byte("secret-marker-passphrase"), nil
		}, nil, errKeyMismatch)
		if (calls == 1) != (envelope.Cipher != "none") {
			t.Fatal("unexpected prompt count")
		}
	}
	private[0] ^= 1
	for _, encrypted := range []bool{false, true} {
		var block *pem.Block
		var err error
		if encrypted {
			block, err = ssh.MarshalPrivateKeyWithPassphrase(private, "secret-marker", []byte("secret-marker-passphrase"))
		} else {
			block, err = ssh.MarshalPrivateKey(private, "secret-marker")
		}
		if err != nil {
			t.Fatal(err)
		}
		assertRegistrationKey(t, context.Background(), pem.EncodeToMemory(block), func(context.Context) ([]byte, error) {
			if !encrypted {
				t.Fatal("unencrypted inconsistent key prompted")
			}
			return []byte("secret-marker-passphrase"), nil
		}, nil, errKeyUnsupported)
	}
	// A structurally accepted envelope with corrupt ciphertext must still decrypt
	// and validate; its public field must never be returned on its own.
	envelope := registrationEnvelope(t, raw)
	envelope.Private = bytes.Clone(envelope.Private)
	clearBytes(envelope.Private)
	assertRegistrationKey(t, context.Background(), registrationEncodeEnvelope(envelope), func(context.Context) ([]byte, error) {
		return []byte("secret-marker-passphrase"), nil
	}, nil, ErrKeyPassphrase)
}

// Deterministic cancellation at a checkpoint avoids timing-sensitive goroutines.
type registrationCheckpointContext struct {
	context.Context
	checks, cancelAt int
}

func (ctx *registrationCheckpointContext) Err() error {
	ctx.checks++
	if ctx.checks >= ctx.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestRegistrationPublicKeyPostValidationContext(t *testing.T) {
	_, plain := testAgentKey(t)
	encrypted, _, _ := validationEncryptedKey(t)
	for _, data := range [][]byte{plain, encrypted} {
		cancelAt := 2
		if bytes.Equal(data, encrypted) {
			cancelAt = 4 // initial, before prompt, after prompt, after validation
		}
		ctx := &registrationCheckpointContext{Context: context.Background(), cancelAt: cancelAt}
		owned := []byte("secret-marker-passphrase")
		assertRegistrationKey(t, ctx, data, func(context.Context) ([]byte, error) {
			return owned, nil
		}, nil, context.Canceled)
		if cancelAt == 4 && !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatal("post-validation cancellation did not clear passphrase")
		}
	}
}

func TestRegistrationPublicKeyContext(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := context.Canceled
		if deadline {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			cancel()
		}
		assertRegistrationKey(t, ctx, nil, registrationNoPrompt(t), nil, want)
		cancel()
	}
}

func TestRegistrationPublicKeyCBC(t *testing.T) {
	binary, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	record, raw := testAgentKey(t)
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-p", "-P", "", "-N", "secret-marker-passphrase", "-a", "1", "-Z", "aes256-cbc", "-f", path)
	if err := cmd.Run(); err != nil {
		t.Fatal("creating CBC fixture", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(data)
	assertRegistrationKey(t, ctx, data, func(context.Context) ([]byte, error) {
		return []byte("secret-marker-passphrase"), nil
	}, policyPublic(t, record), nil)
}
