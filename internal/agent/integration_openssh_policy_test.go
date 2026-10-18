package agent

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Capture a real ssh-add generated constraint without enabling ADD on sshx.
// The fixture receiver rejects the import after copying only its public policy.
func testOpenSSHDestinationWire(t *testing.T) {
	t.Helper()
	tool, err := exec.LookPath("ssh-add")
	if err != nil {
		t.Fatal(err)
	}
	dir := agentTestDirectory(t)
	record, raw := testAgentKey(t)
	_ = record
	private := filepath.Join(dir, "private")
	if err := os.WriteFile(private, raw, 0600); err != nil {
		t.Fatal(err)
	}
	host := bindingSigner(t).PublicKey()
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, append([]byte("destination.example "), ssh.MarshalAuthorizedKey(host)...), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "capture.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- nil
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		for {
			frame, err := readBindingProxyFrame(conn)
			if err != nil {
				result <- nil
				return
			}
			if frame[0] == 25 {
				rest := frame[1:]
				valid := true
				// Ed25519 ADD: type, public key, private key, comment, constraints.
				for i := 0; i < 4; i++ {
					var field []byte
					var ok bool
					field, rest, ok = agentWireString(rest)
					if !ok || (i == 0 && string(field) != ssh.KeyAlgoED25519) {
						valid = false
						break
					}
				}
				var policy []byte
				if valid {
					policy = bytes.Clone(rest)
				}
				clearBytes(frame)
				writeAgentReply(conn, agentPacket([]byte{5}))
				result <- policy
				return
			}
			clearBytes(frame)
			if writeAgentReply(conn, agentPacket([]byte{5})) != nil {
				result <- nil
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, "-H", known, "-h", "alice@destination.example", private)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "SSH_AUTH_SOCK=" + socket}
	err = cmd.Run()
	listener.Close()
	if err == nil {
		t.Fatal("capture unexpectedly imported a key")
	}
	wire := <-result
	p, err := parseAgentDestinationConstraint(wire)
	if err != nil || len(p.Edges) != 1 || p.Edges[0].To.Username != "alice" || p.Edges[0].To.HostKeys[0] != policyPin(host) {
		t.Fatal("real ssh-add constraint decode", err)
	}
}

func TestAgentDestinationOpenSSHIntegration(t *testing.T) {
	if os.Getenv("SSHX_AGENT_OPENSSH_INTEGRATION") != "1" {
		t.Skip("set SSHX_AGENT_OPENSSH_INTEGRATION=1 for disposable OpenSSH destination tests")
	}
	t.Run("ssh-add-wire", testOpenSSHDestinationWire)
	t.Run("ProxyJump", func(t *testing.T) {
		record, raw := testAgentKey(t)
		pub := policyPublic(t, record)
		destination, dKey, stop := startAgentSSHFixture(t, pub, pub.Type())
		defer stop()
		bastion, bKey, stop := startAgentSSHFixture(t, pub, pub.Type(), destination)
		defer stop()
		record.Policy = "destination-constrained"
		record.Destinations = &agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{policyEdge(nil, bKey, "sshx-fixture"), policyEdge(nil, dKey, "sshx-fixture")}}
		dir := agentTestDirectory(t)
		name := filepath.Join(dir, "agent.json")
		writePolicyFile(t, name, policyJSON(t, record))
		registry, err := readAgentRegistry(name)
		if err != nil {
			t.Fatal(err)
		}
		backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
		socket := filepath.Join(dir, "agent.sock")
		server, err := newAgentServer(socket, registry, backend.open)
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		go server.Serve(context.Background())
		identity := filepath.Join(dir, "identity.pub")
		os.WriteFile(identity, ssh.MarshalAuthorizedKey(pub), 0600)
		known := filepath.Join(dir, "known_hosts")
		bHost, bPort, _ := net.SplitHostPort(bastion)
		dHost, dPort, _ := net.SplitHostPort(destination)
		os.WriteFile(known, []byte("["+bHost+"]:"+bPort+" "+policyPin(bKey)+"\n["+dHost+"]:"+dPort+" "+policyPin(dKey)+"\n"), 0600)
		config := filepath.Join(dir, "ssh_config")
		text := "Host *\n User sshx-fixture\n BatchMode yes\n IdentitiesOnly yes\n IdentityAgent " + socket + "\n IdentityFile " + identity + "\n UserKnownHostsFile " + known + "\n GlobalKnownHostsFile /dev/null\n StrictHostKeyChecking yes\n PreferredAuthentications publickey\n PasswordAuthentication no\n KbdInteractiveAuthentication no\n ForwardAgent no\n ControlMaster no\n ControlPath none\nHost bastion\n HostName " + bHost + "\n Port " + bPort + "\nHost destination\n HostName " + dHost + "\n Port " + dPort + "\n"
		os.WriteFile(config, []byte(text), 0600)
		run := func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "ssh", "-F", config, "-J", "bastion", "destination", "fixture-command")
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "SSH_AUTH_SOCK=" + socket}
			cmd.Stderr = io.Discard
			output, err := cmd.Output()
			return string(output), err
		}
		if output, err := run(); err != nil || output != "agent-authenticated\n" {
			t.Fatal("ProxyJump with independent origin edges", err)
		}
		if backend.reads.Load() != 2 {
			t.Fatal("expected separate bastion/destination signatures")
		}
		// A bastion -> destination edge does not grant origin -> destination use.
		record.Destinations.Edges[1] = policyEdge(bKey, dKey, "sshx-fixture")
		writePolicyFile(t, name, policyJSON(t, record))
		before := backend.reads.Load()
		if _, err := run(); err == nil {
			t.Fatal("ProxyJump manufactured a forwarding edge")
		}
		if backend.reads.Load() != before+1 {
			t.Fatal("denied destination fetched key or bastion failed")
		}
		backend.assertCleared(t)
	})
}
