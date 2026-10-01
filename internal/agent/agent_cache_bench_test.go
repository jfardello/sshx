package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"testing"
)

func BenchmarkAgentSignerReuse(b *testing.B) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "benchmark", []byte("fixture"))
	if err != nil {
		b.Fatal(err)
	}
	raw := pem.EncodeToMemory(block)
	signer, err := ssh.ParsePrivateKeyWithPassphrase(raw, []byte("fixture"))
	if err != nil {
		b.Fatal(err)
	}
	data := []byte("benchmark authentication payload")
	b.Run("decrypt-and-sign", func(b *testing.B) {
		for b.Loop() {
			s, err := ssh.ParsePrivateKeyWithPassphrase(raw, []byte("fixture"))
			if err != nil {
				b.Fatal(err)
			}
			if _, err = s.Sign(rand.Reader, data); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("reuse-and-sign", func(b *testing.B) {
		for b.Loop() {
			if _, err := signer.Sign(rand.Reader, data); err != nil {
				b.Fatal(err)
			}
		}
	})
}
