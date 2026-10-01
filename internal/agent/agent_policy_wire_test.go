package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func constraintString(data []byte) []byte { return ssh.Marshal(struct{ Value []byte }{data}) }
func constraintHop(user, host string, keys ...ssh.PublicKey) []byte {
	data := ssh.Marshal(struct{ User, Host, Reserved string }{user, host, ""})
	for _, key := range keys {
		data = append(data, constraintString(key.Marshal())...)
		data = append(data, 0)
	}
	return data
}
func constraintEnvelope(from, to, reserved []byte) []byte {
	edge := append(constraintString(from), constraintString(to)...)
	edge = append(edge, constraintString(reserved)...)
	return append(append([]byte{255}, constraintString([]byte(agentDestinationExtension))...), constraintString(constraintString(edge))...)
}
func TestAgentDestinationConstraintWire(t *testing.T) {
	host := bindingSigner(t).PublicKey()
	from := constraintHop("", "")
	to := constraintHop("alice", "host", host)
	good := constraintEnvelope(from, to, nil)
	p, err := parseAgentDestinationConstraint(good)
	if err != nil || p.Edges[0].To.Username != "alice" || p.Edges[0].To.HostKeys[0] != policyPin(host) {
		t.Fatal("valid nested constraint", err)
	}
	inputs := [][]byte{nil, {255}, append(bytes.Clone(good), 0), constraintEnvelope(from, to, []byte{1}), constraintEnvelope(constraintHop("root", ""), to, nil), constraintEnvelope(from, constraintHop("", "host"), nil), constraintEnvelope(constraintHop("", "source"), to, nil), constraintEnvelope(constraintHop("", "", host), to, nil)}
	ca := bytes.Clone(to)
	ca[len(ca)-1] = 1
	inputs = append(inputs, constraintEnvelope(from, ca, nil))
	nonempty := ssh.Marshal(struct{ User, Host, Reserved string }{"", "host", "reserved"})
	inputs = append(inputs, constraintEnvelope(from, nonempty, nil))
	certificate := ssh.Marshal(struct{ Type string }{ssh.CertAlgoED25519v01})
	badHop := append(ssh.Marshal(struct{ User, Host, Reserved string }{"", "host", ""}), constraintString(certificate)...)
	badHop = append(badHop, 0)
	inputs = append(inputs, constraintEnvelope(from, badHop, nil))
	for i := 0; i < len(good); i++ {
		inputs = append(inputs, good[:i])
	}
	for _, data := range inputs {
		if _, err := parseAgentDestinationConstraint(data); err == nil {
			t.Fatal("malformed/unsupported nested constraint accepted")
		}
	}
}

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

func FuzzAgentDestinationConstraint(f *testing.F) {
	signer, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	f.Add(constraintEnvelope(constraintHop("", ""), constraintHop("alice", "host", signer.PublicKey()), nil))
	f.Add([]byte{255})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parseAgentDestinationConstraint(data)
		if err == nil {
			if _, err := compileAgentPolicy(p); err != nil {
				t.Fatal("decoder returned invalid policy")
			}
		}
	})
}
func FuzzAgentUserauth(f *testing.F) {
	signer, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	pub := signer.PublicKey()
	sig, _ := signer.Sign(rand.Reader, []byte("session"))
	var b agentBindingState
	b.record(bindingPayload(pub.Marshal(), []byte("session"), ssh.Marshal(sig), 0))
	p, _ := compileAgentPolicy(&agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{policyEdge(nil, pub, "alice")}})
	f.Add(authData(pub, pub, pub.Type()))
	f.Add(authData(pub, nil, pub.Type()))
	f.Add([]byte("SSHSIG"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if p.authorize(&b, pub.Marshal(), data, pub.Type()) {
			r, ok := parseAgentUserauth(data)
			if !ok || r.username != "alice" || !bytes.Equal(r.session, []byte("session")) || !bytes.Equal(r.key, pub.Marshal()) {
				t.Fatal("invalid userauth authorized")
			}
		}
	})
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
