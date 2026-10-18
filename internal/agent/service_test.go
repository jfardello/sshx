package agent

import (
	"context"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
