package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func agentTestDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sshx-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func agentTestServer(t *testing.T) (*agentServer, *agentTestBackend, string, context.CancelFunc, <-chan error) {
	t.Helper()
	service, backend, _ := agentTestService(t)
	name := filepath.Join(agentTestDirectory(t), "agent.sock")
	server, err := newAgentServer(name, service.registry, backend.open)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	return server, backend, name, cancel, done
}

func agentTestDial(t *testing.T, name string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("unix", name, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func waitAgentCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("agent condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func agentSignBody(pub ssh.PublicKey, data []byte, flags uint32) []byte {
	return ssh.Marshal(struct {
		Key   []byte `sshtype:"13"`
		Data  []byte
		Flags uint32
	}{pub.Marshal(), data, flags})
}
