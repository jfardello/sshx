package agent

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jfardello/sshx/internal/keystore"
	"golang.org/x/crypto/ssh/agent"
)

// Called inside the disposable GPG fixture, after raw retrieval has been checked.
// The production opener must retrieve the enrolled key again through gopass.
func testGopassAgentRoundTrip(t *testing.T, ctx context.Context, record agentKeyRecord) {
	t.Helper()
	registry, err := parseAgentRegistry(registryJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(agentTestDirectory(t), "agent.sock")
	server, err := newAgentServer(socketPath, registry, keystore.Open)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.Serve(ctx)
	client := agent.NewClient(agentTestDial(t, socketPath))
	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatal("gopass-backed agent list", err)
	}
	data := []byte("disposable gopass agent challenge")
	signature, err := client.Sign(keys[0], data)
	if err != nil {
		t.Fatal("gopass-backed agent signing", err)
	}
	if err := registry.keys[0].publicKey.Verify(data, signature); err != nil {
		t.Fatal("invalid gopass-backed signature", err)
	}
}
