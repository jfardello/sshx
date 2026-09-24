package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeDoesNotReadBackend(t *testing.T) {
	_, backend, socket, _, _ := agentTestServer(t)
	if err := Probe(context.Background(), socket); err != nil {
		t.Fatal(err)
	}
	if backend.opens.Load() != 0 || backend.reads.Load() != 0 {
		t.Fatal("probe activated backend")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Probe(ctx, socket); err == nil {
		t.Fatal("cancelled probe accepted")
	}
}

func TestProbeRejectsUnsafeAndMalformedEndpoints(t *testing.T) {
	dir := agentTestDirectory(t)
	for _, path := range []string{"relative", filepath.Join(dir, "missing")} {
		if err := Probe(context.Background(), path); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
	if err := ValidateDirectory("relative"); err == nil {
		t.Fatal("relative directory accepted")
	}
	for _, body := range [][]byte{{}, {12, 0, 0, 0, 1}, {12, 0, 0, 0, 0, 1}, {5}, {12, 255, 255, 255, 255}} {
		socket := filepath.Join(dir, "fake.sock")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(socket, 0600); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var request [5]byte
			_, _ = conn.Read(request[:])
			_, _ = conn.Write(agentPacket(body))
		}()
		if err := Probe(context.Background(), socket); err == nil {
			t.Fatal("malformed response accepted")
		}
		listener.Close()
		<-done
	}
}
