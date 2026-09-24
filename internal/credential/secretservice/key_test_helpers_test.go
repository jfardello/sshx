package secretservice

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testPrivateKeyBytes(t *testing.T) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}
