package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
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
func TestAgentSocketLifecycle(t *testing.T) {
	server, backend, name, cancel, done := agentTestServer(t)
	info, err := os.Lstat(name)
	if err != nil || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("socket mode", err)
	}
	client := agent.NewClient(agentTestDial(t, name))
	for i := 0; i < 3; i++ {
		keys, err := client.List()
		if err != nil || len(keys) != 1 {
			t.Fatal("wire List", err)
		}
		if i == 0 && backend.opens.Load() != 0 {
			t.Fatal("List opened backend")
		}
		sig, err := client.Sign(keys[0], []byte("over socket"))
		if err != nil {
			t.Fatal(err)
		}
		trusted := server.keys.registry.keys[0].publicKey
		if err := trusted.Verify([]byte("over socket"), sig); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.RemoveAll(); err == nil {
		t.Fatal("wire mutation succeeded")
	}
	if err := client.Lock([]byte("synthetic-private-lock")); err == nil {
		t.Fatal("wire lock succeeded")
	}
	if err := client.Unlock([]byte("synthetic-private-lock")); err == nil {
		t.Fatal("wire unlock succeeded")
	}
	if _, err := client.List(); err != nil {
		t.Fatal("mutation failure broke connection", err)
	}
	if err := server.Serve(context.Background()); !errors.Is(err, errAgentDenied) {
		t.Fatal("server served twice")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown blocked")
	}
	if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned socket not removed")
	}
	if _, err := os.Stat(filepath.Dir(name)); err != nil {
		t.Fatal("removed caller directory")
	}
	if err := server.Close(); err != nil {
		t.Fatal("Close not idempotent", err)
	}
	backend.assertCleared(t)
}
func TestAgentSocketRejectsUnsafePaths(t *testing.T) {
	s, b, _ := agentTestService(t)
	dir := agentTestDirectory(t)
	name := filepath.Join(dir, "agent.sock")
	for _, path := range []string{"relative", "/agent.sock", name + strings.Repeat("x", 100), filepath.Join(dir, "missing", "agent.sock")} {
		if server, err := newAgentServer(path, s.registry, b.open); err == nil {
			server.Close()
			t.Fatal("accepted unsafe path")
		}
	}
	if err := os.WriteFile(name, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAgentServer(name, s.registry, b.open); err == nil {
		t.Fatal("replaced existing file")
	}
	os.Remove(name)
	os.Symlink(filepath.Join(dir, "missing"), name)
	if _, err := newAgentServer(name, s.registry, b.open); err == nil {
		t.Fatal("accepted dangling symlink")
	}
	os.Remove(name)
	os.Chmod(dir, 0755)
	if _, err := newAgentServer(name, s.registry, b.open); err == nil {
		t.Fatal("accepted public directory")
	}
	os.Chmod(dir, 0700)
	link := filepath.Join(agentTestDirectory(t), "link")
	os.Symlink(dir, link)
	if _, err := newAgentServer(filepath.Join(link, "agent.sock"), s.registry, b.open); err == nil {
		t.Fatal("accepted symlink parent")
	}
	server, err := newAgentServer(name, s.registry, b.open)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err := newAgentServer(name, s.registry, b.open); err == nil {
		t.Fatal("replaced live socket")
	}
	if b.opens.Load() != 0 {
		t.Fatal("socket startup opened provider")
	}
}
func TestAgentSocketCleanupPreservesReplacement(t *testing.T) {
	server, _, name, _, _ := agentTestServer(t)
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(name); err != nil || string(data) != "replacement" {
		t.Fatal("removed replacement endpoint", err)
	}
}
func TestAgentSocketCleanupAnchoredToDirectory(t *testing.T) {
	server, _, name, _, _ := agentTestServer(t)
	dir := filepath.Dir(name)
	moved := dir + "-moved"
	t.Cleanup(func() { os.RemoveAll(moved) })
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(name); err != nil {
		t.Fatal("unlinked replacement directory's file")
	}
	if _, err := os.Lstat(filepath.Join(moved, "agent.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned socket retained after directory rename")
	}
}
func TestAgentSocketFraming(t *testing.T) {
	_, backend, name, _, _ := agentTestServer(t)
	for _, size := range []uint32{0, maxAgentFrameBytes + 1, 0xffffffff} {
		conn := agentTestDial(t, name)
		conn.SetDeadline(time.Now().Add(time.Second))
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, size)
		if _, err := conn.Write(header); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("accepted invalid frame size")
		}
		conn.Close()
	}
	conn := agentTestDial(t, name)
	conn.SetDeadline(time.Now().Add(time.Second))
	if err := writeAgentReply(conn, agentPacket([]byte{11, 0})); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 5)
	if _, err := io.ReadFull(conn, response); err != nil || response[4] != 5 {
		t.Fatal("malformed List did not fail", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("malformed connection remained open")
	}
	raw := agentTestDial(t, name).(*net.UnixConn)
	raw.SetDeadline(time.Now().Add(time.Second))
	raw.Write([]byte{0, 0, 0, 10, 13})
	raw.CloseWrite()
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("truncated frame did not close")
	}
	if backend.opens.Load() != 0 {
		t.Fatal("malformed request opened backend")
	}
}
func TestAgentSocketConnectionLimit(t *testing.T) {
	server, _, name, _, _ := agentTestServer(t)
	count := func() int { server.mutex.Lock(); defer server.mutex.Unlock(); return len(server.connections) }
	clients := make([]net.Conn, 0, maxAgentConnections)
	for i := 0; i < maxAgentConnections; i++ {
		clients = append(clients, agentTestDial(t, name))
	}
	waitAgentCondition(t, func() bool { return count() == maxAgentConnections })
	extra := agentTestDial(t, name)
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("accepted connection beyond limit")
	}
	clients[0].Close()
	waitAgentCondition(t, func() bool { return count() == maxAgentConnections-1 })
	if _, err := agent.NewClient(agentTestDial(t, name)).List(); err != nil {
		t.Fatal("capacity did not recover", err)
	}
}
func TestAgentShutdownCancelsSigning(t *testing.T) {
	s, b, _ := agentTestService(t)
	entered := make(chan struct{})
	b.read = func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
	name := filepath.Join(agentTestDirectory(t), "agent.sock")
	server, err := newAgentServer(name, s.registry, b.open)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client := agent.NewClient(agentTestDial(t, name))
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	signed := make(chan error, 1)
	go func() { _, err := client.Sign(keys[0], nil); signed <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read not entered")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not cancel read")
	}
	select {
	case err := <-signed:
		if err == nil {
			t.Fatal("cancelled signature succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("client blocked")
	}
	if b.closes.Load() != 1 {
		t.Fatal("store not closed")
	}
}
func TestAgentReadDeadline(t *testing.T) {
	s, b, _ := agentTestService(t)
	name := filepath.Join(agentTestDirectory(t), "agent.sock")
	server, err := newAgentServer(name, s.registry, b.open)
	if err != nil {
		t.Fatal(err)
	}
	server.readTimeout = 30 * time.Millisecond
	defer server.Close()
	go server.Serve(context.Background())
	conn := agentTestDial(t, name)
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write([]byte{0})
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("partial frame ignored deadline")
	}
}
