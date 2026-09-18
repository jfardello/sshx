package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Actual OpenSSH clients use the native agent against a disposable Go SSH
// endpoint accepting only the fixture public key. No real accounts or stores.
func TestAgentOpenSSHIntegration(t *testing.T) {
	if os.Getenv("SSHX_AGENT_OPENSSH_INTEGRATION") != "1" {
		t.Skip("set SSHX_AGENT_OPENSSH_INTEGRATION=1 to test installed OpenSSH clients")
	}
	for _, tool := range []string{"ssh", "ssh-add"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal("required OpenSSH client unavailable", tool)
		}
	}
	version, err := exec.Command("ssh", "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(strings.TrimSpace(string(version)))
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		private   any
		algorithm string
	}{{ed, ssh.KeyAlgoED25519}, {rsaKey, ssh.KeyAlgoRSASHA256}, {rsaKey, ssh.KeyAlgoRSASHA512}}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, struct {
			private   any
			algorithm string
		}{key, pub.Type()})
	}
	for _, fixture := range fixtures {
		t.Run(fixture.algorithm, func(t *testing.T) {
			record, raw, pub := agentTestRecord(t, fixture.private, "openssh-key")
			registry, err := parseAgentRegistry(registryJSON(t, record))
			if err != nil {
				t.Fatal(err)
			}
			backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
			dir := agentTestDirectory(t)
			socketPath := filepath.Join(dir, "agent.sock")
			server, err := newAgentServer(socketPath, registry, backend.open)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go server.Serve(context.Background())
			proxy := startBindingProxy(t, socketPath)
			socketPath = proxy.path
			publicPath := filepath.Join(dir, "identity.pub")
			if err := os.WriteFile(publicPath, ssh.MarshalAuthorizedKey(pub), 0600); err != nil {
				t.Fatal(err)
			}
			env := []string{}
			for _, value := range os.Environ() {
				name, _, _ := strings.Cut(value, "=")
				if name == "HOME" || strings.HasPrefix(name, "SSH_") {
					continue
				}
				env = append(env, value)
			}
			env = append(env, "HOME="+dir, "SSH_AUTH_SOCK="+socketPath)
			run := func(program string, args ...string) ([]byte, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, program, args...)
				cmd.Env = env
				var output bytes.Buffer
				stderr := &bytes.Buffer{}
				cmd.Stdout = &output
				cmd.Stderr = stderr
				err := cmd.Run()
				if err != nil {
					t.Logf("%s failed: %v; %s", program, err, stderr.Bytes())
				}
				return output.Bytes(), err
			}
			if data, err := run("ssh-add", "-L"); err != nil || !bytes.Contains(data, []byte(record.PublicKey)) {
				t.Fatal("OpenSSH public identity list", err)
			}
			if _, err := run("ssh-add", "-l"); err != nil {
				t.Fatal("OpenSSH fingerprint list", err)
			}
			if backend.opens.Load() != 0 {
				t.Fatal("OpenSSH listing read private key")
			}
			address, hostKey, stop := startAgentSSHFixture(t, pub, fixture.algorithm)
			defer stop()
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			knownPath := filepath.Join(dir, "known_hosts")
			if err := os.WriteFile(knownPath, append([]byte("["+host+"]:"+port+" "), ssh.MarshalAuthorizedKey(hostKey)...), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=" + socketPath, "-o", "IdentityFile=" + publicPath, "-o", "UserKnownHostsFile=" + knownPath, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "ForwardAgent=no", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "PubkeyAcceptedAlgorithms=" + fixture.algorithm, "-p", port, "sshx-fixture@" + host, "fixture-command"}
			output, err := run("ssh", args...)
			if err != nil || string(output) != "agent-authenticated\n" {
				t.Fatal("OpenSSH agent authentication", err)
			}
			if backend.reads.Load() != 1 {
				t.Fatalf("private reads = %d; expected agent-only authentication", backend.reads.Load())
			}
			proxy.mutex.Lock()
			verified := proxy.verified > 0 && proxy.host != nil && bytes.Equal(proxy.host.Marshal(), hostKey.Marshal()) && proxy.signedSession
			proxy.mutex.Unlock()
			if !verified {
				t.Fatal("real OpenSSH authentication did not use a verified binding for the fixture host/session")
			}
			for _, negative := range []string{"corrupt", "forwarding"} {
				proxy.corrupt.Store(negative == "corrupt")
				proxy.forward.Store(negative == "forwarding")
				before := backend.reads.Load()
				if _, err := run("ssh", args...); err == nil {
					t.Fatal("invalid/forwarded proof authenticated", negative)
				}
				if backend.reads.Load() != before {
					t.Fatal("denied binding accessed backend", negative)
				}
			}
			proxy.corrupt.Store(false)
			proxy.forward.Store(false)
			proxy.mutex.Lock()
			failed := proxy.failures
			proxy.mutex.Unlock()
			if failed < 2 {
				t.Fatal("negative OpenSSH cases did not receive extension failure")
			}
			if fixture.algorithm == ssh.KeyAlgoED25519 {
				if _, err := run("ssh-add", "-T", publicPath); err != nil {
					t.Fatal("OpenSSH signature test", err)
				}
			}
			before := backend.reads.Load()
			if _, err := run("ssh-add", "-d", publicPath); err == nil {
				t.Fatal("OpenSSH removal succeeded")
			}
			if _, err := run("ssh-add", "-D"); err == nil {
				t.Fatal("OpenSSH remove-all succeeded")
			}
			privatePath := filepath.Join(dir, "private-key")
			if err := os.WriteFile(privatePath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := run("ssh-add", privatePath); err == nil {
				t.Fatal("OpenSSH ADD succeeded")
			}
			if backend.reads.Load() != before {
				t.Fatal("mutation fetched a backend key")
			}
			// Repeat real authentication with a pinned destination policy for
			// every advertised credential algorithm, including both RSA flags.
			record.Policy = "destination-constrained"
			record.Destinations = &agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{policyEdge(nil, hostKey, "sshx-fixture")}}
			constrained, err := parseAgentRegistry(policyJSON(t, record))
			if err != nil {
				t.Fatal(err)
			}
			if err := server.keys.replaceRegistry(constrained); err != nil {
				t.Fatal(err)
			}
			before = backend.reads.Load()
			if output, err := run("ssh", args...); err != nil || string(output) != "agent-authenticated\n" {
				t.Fatal("constrained OpenSSH authentication", err)
			}
			if backend.reads.Load() != before+1 {
				t.Fatal("constrained connection did not use exactly one backend signature")
			}
			record.Destinations.Edges[0].To.Username = "different-user"
			constrained, err = parseAgentRegistry(policyJSON(t, record))
			if err != nil {
				t.Fatal(err)
			}
			if err := server.keys.replaceRegistry(constrained); err != nil {
				t.Fatal(err)
			}
			before = backend.reads.Load()
			if _, err := run("ssh", args...); err == nil {
				t.Fatal("wrong destination user authenticated")
			}
			if backend.reads.Load() != before {
				t.Fatal("denied destination user fetched a key")
			}
			backend.assertCleared(t)
		})
	}
}

func startAgentSSHFixture(t *testing.T, allowed ssh.PublicKey, algorithm string, forwardTo ...string) (string, ssh.PublicKey, func()) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyAuthAlgorithms: []string{algorithm}, PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "sshx-fixture" || !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, fmt.Errorf("fixture key required")
		}
		return nil, nil
	}}
	config.AddHostKey(hostKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	connections := map[net.Conn]bool{}
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mutex.Lock()
			connections[conn] = true
			mutex.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mutex.Lock(); delete(connections, conn); mutex.Unlock() }()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() == "direct-tcpip" && len(forwardTo) == 1 {
						var request struct {
							Host       string
							Port       uint32
							Origin     string
							OriginPort uint32
						}
						if ssh.Unmarshal(channel.ExtraData(), &request) != nil || net.JoinHostPort(request.Host, strconv.Itoa(int(request.Port))) != forwardTo[0] {
							channel.Reject(ssh.Prohibited, "fixture target required")
							continue
						}
						target, err := net.DialTimeout("tcp", forwardTo[0], time.Second)
						if err != nil {
							channel.Reject(ssh.ConnectionFailed, "fixture unavailable")
							continue
						}
						stream, requests, err := channel.Accept()
						if err != nil {
							target.Close()
							return
						}
						go ssh.DiscardRequests(requests)
						copied := make(chan struct{}, 2)
						go func() { io.Copy(target, stream); target.(*net.TCPConn).CloseWrite(); copied <- struct{}{} }()
						go func() { io.Copy(stream, target); stream.CloseWrite(); copied <- struct{}{} }()
						<-copied
						target.Close()
						stream.Close()
						<-copied
						continue
					}
					if channel.ChannelType() != "session" {
						channel.Reject(ssh.UnknownChannelType, "session required")
						continue
					}
					session, requests, err := channel.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						if request.Type != "exec" {
							request.Reply(false, nil)
							continue
						}
						request.Reply(true, nil)
						io.WriteString(session, "agent-authenticated\n")
						var status [4]byte
						binary.BigEndian.PutUint32(status[:], 0)
						session.SendRequest("exit-status", false, status[:])
						session.Close()
						break
					}
				}
			}()
		}
	}()
	stop := func() {
		listener.Close()
		<-accepted
		mutex.Lock()
		for conn := range connections {
			conn.Close()
		}
		mutex.Unlock()
		workers.Wait()
	}
	return listener.Addr().String(), hostKey.PublicKey(), stop
}
