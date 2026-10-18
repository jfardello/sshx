package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type encryptedTestEnvelope struct {
	Cipher, KDF     string
	Options         []byte
	Count           uint32
	Public, Private []byte
}

func TestAgentEncryptedEnvelopeBounds(t *testing.T) {
	a, b, pub, data := confirmationAgent(t, true)
	var raw []byte
	for _, v := range b.data {
		raw = v
	}
	block, _ := pem.Decode(raw)
	defer clearBytes(block.Bytes)
	var original encryptedTestEnvelope
	if err := ssh.Unmarshal(block.Bytes[len("openssh-key-v1\x00"):], &original); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"cipher", "kdf", "rounds-zero", "rounds-excessive", "salt", "multiple-keys", "public", "ciphertext", "trailing", "pkcs8"} {
		t.Run(mode, func(t *testing.T) {
			envelope := original
			envelope.Options = append([]byte(nil), original.Options...)
			switch mode {
			case "cipher":
				envelope.Cipher = "aes128-ctr"
			case "kdf":
				envelope.KDF = "unknown"
			case "rounds-zero":
				binary.BigEndian.PutUint32(envelope.Options[len(envelope.Options)-4:], 0)
			case "rounds-excessive":
				binary.BigEndian.PutUint32(envelope.Options[len(envelope.Options)-4:], maxAgentBcryptRounds+1)
			case "salt":
				envelope.Options = ssh.Marshal(struct {
					Salt   []byte
					Rounds uint32
				}{[]byte("short"), 16})
			case "multiple-keys":
				envelope.Count = 2
			case "public":
				envelope.Public = []byte("wrong-key")
			case "ciphertext":
				envelope.Private = []byte{1}
			}
			der := append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)
			if mode == "trailing" {
				der = append(der, 0)
			}
			kind := "OPENSSH PRIVATE KEY"
			if mode == "pkcs8" {
				kind = "ENCRYPTED PRIVATE KEY"
			}
			mutated := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
			for key := range b.data {
				b.data[key] = mutated
			}
			calls := 0
			a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
				calls++
				if r.Operation == "passphrase" {
					t.Error("invalid envelope prompted")
				}
				return nil, nil
			}}
			if sig, err := a.Sign(pub, data); err == nil || sig != nil {
				t.Fatal("invalid encryption accepted")
			}
			if calls != 1 {
				t.Fatal("expected only sign confirmation")
			}
		})
	}
	// The envelope public key cannot substitute for checking the decrypted key.
	other, _, _, _ := confirmationAgent(t, false)
	otherKey := other.keys.registry.keys[0].publicKey
	original.Public = otherKey.Marshal()
	changed := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte("openssh-key-v1\x00"), ssh.Marshal(original)...)})
	signer, err := parseAgentKeyWithPrompt(context.Background(), changed, otherKey, &agentPrompter{ask: func(context.Context, agentPromptRequest) ([]byte, error) { return []byte("fixture-passphrase"), nil }}, agentPromptRequest{}, func() error { return nil })
	if err == nil || signer != nil {
		t.Fatal("decrypted public key mismatch accepted")
	}
}

func FuzzAgentEncryptedEnvelope(f *testing.F) {
	pub, _ := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, 32)))
	envelope := encryptedTestEnvelope{Cipher: "aes256-ctr", KDF: "bcrypt", Options: ssh.Marshal(struct {
		Salt   []byte
		Rounds uint32
	}{make([]byte, 16), 16}), Count: 1, Public: pub.Marshal(), Private: make([]byte, 16)}
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)}))
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n-----END OPENSSH PRIVATE KEY-----\n"))
	f.Add([]byte("not a key"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxKeyMaterialBytes+1 {
			return
		}
		accepted, err := encryptedAgentEnvelope(data, pub)
		if accepted && err != nil {
			t.Fatal("inconsistent envelope admission")
		}
		withoutKey, _ := encryptedAgentEnvelope(data, nil)
		if withoutKey {
			t.Fatal("accepted encrypted key without expected public identity")
		}
	})
}

func TestAgentEncryptedCBCFixture(t *testing.T) {
	binary, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	record, raw := testAgentKey(t)
	pub := policyPublic(t, record)
	dir := agentTestDirectory(t)
	path := filepath.Join(dir, "identity")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	askpass := filepath.Join(dir, "askpass")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\nprintf '%s\\n' 'fixture-passphrase'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-p", "-Z", "aes256-cbc", "-f", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "DISPLAY=:0", "SSH_ASKPASS=" + askpass, "SSH_ASKPASS_REQUIRE=force"}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatal("creating CBC fixture", err)
	}
	encrypted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(encrypted)
	signer, err := parseAgentKeyWithPrompt(ctx, encrypted, pub, &agentPrompter{ask: func(context.Context, agentPromptRequest) ([]byte, error) { return []byte("fixture-passphrase"), nil }}, agentPromptRequest{}, func() error { return ctx.Err() })
	if err != nil {
		t.Fatal("CBC fixture rejected", err)
	}
	signature, err := signer.Sign(rand.Reader, []byte("fixture"))
	if err != nil || pub.Verify([]byte("fixture"), signature) != nil {
		t.Fatal("CBC signature failed", err)
	}
}
