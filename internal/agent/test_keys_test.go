package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func bindingSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testAgentKey(t *testing.T) (agentKeyRecord, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return agentKeyRecord{ID: "test-key", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), Enabled: true, Policy: "unrestricted-local", Backend: credentialBackendGopass, Reference: "keys/test-key"}, pem.EncodeToMemory(block)
}

func registryJSON(t *testing.T, records ...agentKeyRecord) []byte {
	t.Helper()
	if records == nil {
		records = []agentKeyRecord{}
	}
	data, err := json.Marshal(agentRegistryDocument{Version: 1, Keys: records})
	if err != nil {
		t.Fatal(err)
	}
	return data
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
