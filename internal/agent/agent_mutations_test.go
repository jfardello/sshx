package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func mutationServer(t *testing.T, state string, enabled bool) (*agentServer, agent.ExtendedAgent) {
	t.Helper()
	service, backend, _ := agentTestService(t)
	name := filepath.Join(agentTestDirectory(t), "agent.sock")
	server, err := newAgentServer(name, service.registry, backend.open)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	if err := server.ConfigureMutations(state, enabled); err != nil {
		t.Fatal(err)
	}
	go server.Serve(context.Background())
	return server, agent.NewClient(agentTestDial(t, name))
}
func mutationPrivate(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func TestAgentMutationSoftwareKeys(t *testing.T) {
	server, client := mutationServer(t, filepath.Join(agentTestDirectory(t), "state"), true)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := []any{mutationPrivate(t), rsaKey}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	for _, key := range keys {
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Add(agent.AddedKey{PrivateKey: key, Comment: "temporary"}); err != nil {
			t.Fatal(err)
		}
		if err := client.Add(agent.AddedKey{PrivateKey: key}); err == nil {
			t.Fatal("replacement accepted")
		}
		flags := []agent.SignatureFlags{0}
		if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
			flags = []agent.SignatureFlags{agent.SignatureFlagRsaSha256, agent.SignatureFlagRsaSha512}
		}
		for _, flag := range flags {
			sig, err := client.SignWithFlags(signer.PublicKey(), []byte("software key"), flag)
			if err != nil {
				t.Fatal(err)
			}
			if err := signer.PublicKey().Verify([]byte("software key"), sig); err != nil {
				t.Fatal(err)
			}
		}
		if err := client.Remove(signer.PublicKey()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Sign(signer.PublicKey(), []byte("removed")); err == nil {
			t.Fatal("removed key signed")
		}
	}
	server.keys.stateMutex.RLock()
	n := len(server.keys.mutations.overlay)
	server.keys.stateMutex.RUnlock()
	if n != 0 {
		t.Fatal("overlay not empty")
	}
}
func TestAgentMutationLifetimeAndAtomicity(t *testing.T) {
	_, client := mutationServer(t, filepath.Join(agentTestDirectory(t), "state"), true)
	key := mutationPrivate(t)
	signer, _ := ssh.NewSignerFromKey(key)
	for _, added := range []agent.AddedKey{
		{PrivateKey: key, ConfirmBeforeUse: true},
		{PrivateKey: key, ConstraintExtensions: []agent.ConstraintExtension{{ExtensionName: "unsupported", ExtensionDetails: []byte("no")}}},
	} {
		if err := client.Add(added); err == nil {
			t.Fatal("unsupported constraint accepted")
		}
		list, err := client.List()
		if err != nil || len(list) != 1 {
			t.Fatal("failed import changed identities", err)
		}
	}
	if err := client.Add(agent.AddedKey{PrivateKey: key, LifetimeSecs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(signer.PublicKey(), []byte("before expiry")); err != nil {
		t.Fatal(err)
	}
	waitAgentCondition(t, func() bool { list, err := client.List(); return err == nil && len(list) == 1 })
	if _, err := client.Sign(signer.PublicKey(), []byte("expired")); err == nil {
		t.Fatal("expired key signed")
	}
}
func TestAgentMutationRestartAndLock(t *testing.T) {
	path := filepath.Join(agentTestDirectory(t), "state")
	server, client := mutationServer(t, path, true)
	enrolled := server.keys.registry.keys[0].publicKey
	if err := client.Remove(enrolled); err != nil {
		t.Fatal(err)
	}
	if err := client.Add(agent.AddedKey{PrivateKey: mutationPrivate(t)}); err != nil {
		t.Fatal(err)
	}
	if err := client.Lock([]byte("test password")); err != nil {
		t.Fatal(err)
	}
	if list, err := client.List(); err != nil || len(list) != 0 {
		t.Fatal("locked identities exposed", err)
	}
	if err := ResetMutationState(path); err == nil {
		t.Fatal("reset while running succeeded")
	}
	if err := client.Unlock([]byte("wrong")); err == nil {
		t.Fatal("incorrect unlock accepted")
	}
	server.Close()
	file, doc, err := openAgentState(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Lock == nil || doc.Lock.Failures != 1 || len(doc.Suppressed) != 1 {
		t.Fatal("lock/removal not durable")
	}
	file.close()
	// Reuse the same enrolled public key to check suppression across a restart.
	name := filepath.Join(agentTestDirectory(t), "agent.sock")
	restarted, err := newAgentServer(name, server.keys.registry, server.keys.open)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Close() })
	if err := restarted.ConfigureMutations(path, true); err != nil {
		t.Fatal(err)
	}
	go restarted.Serve(context.Background())
	next := agent.NewClient(agentTestDial(t, name))
	if err := next.Unlock([]byte("test password")); err == nil {
		t.Fatal("restart bypassed cooldown")
	}
	time.Sleep(time.Until(time.Unix(0, doc.Lock.NextAttempt)) + time.Millisecond)
	if err := next.Unlock([]byte("test password")); err != nil {
		t.Fatal(err)
	}
	if list, err := next.List(); err != nil || len(list) != 0 {
		t.Fatal("restart restored removed or volatile identities", err)
	}
	if _, err := next.Sign(enrolled, []byte("suppressed")); err == nil {
		t.Fatal("suppressed enrollment signed")
	}
	restarted.Close()
	if err := ResetMutationState(path); err != nil {
		t.Fatal(err)
	}
	file, doc, err = openAgentState(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer file.close()
	if doc.Lock != nil || len(doc.Suppressed) != 0 || doc.SuppressAll {
		t.Fatal("reset did not restore state")
	}
}
func TestAgentMutationWireConstraints(t *testing.T) {
	key := mutationPrivate(t)
	body := append([]byte{25}, ssh.Marshal(struct {
		Kind            string
		Public, Private []byte
		Comment         string
	}{ssh.KeyAlgoED25519, key[32:], key, "test"})...)
	host := bindingSigner(t).PublicKey()
	good := constraintEnvelope(constraintHop("", ""), constraintHop("alice", "host", host), nil)
	entry, err := parseAgentAdd(append(bytes.Clone(body), good...))
	if err != nil || entry.key.policy == nil {
		t.Fatal("destination constraint", err)
	}
	entry.destroy()
	for _, tail := range [][]byte{{3, 0, 0, 0, 1}, {2, 2}, {1, 0, 0, 0, 0}, {1, 0}, {255}, append(bytes.Clone(good), good...)} {
		if entry, err := parseAgentAdd(append(bytes.Clone(body), tail...)); err == nil {
			entry.destroy()
			t.Fatal("invalid constraints accepted")
		}
	}
	for i := 0; i < len(body)-4; i++ {
		if entry, err := parseAgentAdd(body[:i]); err == nil {
			entry.destroy()
			t.Fatal("truncated key accepted")
		}
	}
}
func FuzzAgentAddWire(f *testing.F) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	body := append([]byte{25}, ssh.Marshal(struct {
		Kind            string
		Public, Private []byte
		Comment         string
	}{ssh.KeyAlgoED25519, key[32:], key, "test"})...)
	f.Add(body)
	f.Add(append(bytes.Clone(body), 2))
	f.Add([]byte{17})
	f.Fuzz(func(t *testing.T, body []byte) {
		entry, err := parseAgentAdd(body)
		if err == nil {
			entry.destroy()
		}
	})
}
func TestAgentSSHAddIntegration(t *testing.T) {
	if os.Getenv("SSHX_AGENT_OPENSSH_INTEGRATION") != "1" {
		t.Skip("set SSHX_AGENT_OPENSSH_INTEGRATION=1")
	}
	path := filepath.Join(agentTestDirectory(t), "state")
	server, _ := mutationServer(t, path, true)
	key := mutationPrivate(t)
	block, err := ssh.MarshalPrivateKey(key, "integration")
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(agentTestDirectory(t), "key")
	if err := os.WriteFile(private, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("ssh-add", args...)
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+server.listener.Addr().String())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssh-add %v: %v: %s", args, err, out)
		}
	}
	run(private)
	pub, _ := ssh.NewPublicKey(key.Public())
	address, hostKey, stop := startAgentSSHFixture(t, pub, ssh.KeyAlgoED25519)
	defer stop()
	hostName, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := private + ".pub"
	if err := os.WriteFile(publicPath, ssh.MarshalAuthorizedKey(pub), 0600); err != nil {
		t.Fatal(err)
	}
	knownPath := private + ".known"
	if err := os.WriteFile(knownPath, append([]byte("["+hostName+"]:"+port+" "), ssh.MarshalAuthorizedKey(hostKey)...), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent="+server.listener.Addr().String(), "-i", publicPath, "-o", "UserKnownHostsFile="+knownPath, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-p", port, "sshx-fixture@"+hostName, "fixture-command")
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "agent-authenticated\n" {
		t.Fatalf("imported-key SSH authentication: %v: %s", err, out)
	}
	run("-l")
	run("-L")
	run("-d", private)
	run("-t", "1", private)
	run("-D")
	server.keys.stateMutex.Lock()
	server.keys.prompt = &agentPrompter{ask: func(context.Context, agentPromptRequest) ([]byte, error) { return nil, nil }}
	server.keys.stateMutex.Unlock()
	run("-c", private)
	run("-d", private)
	host := bindingSigner(t).PublicKey()
	known := filepath.Join(agentTestDirectory(t), "known_hosts")
	if err := os.WriteFile(known, append([]byte("destination.example "), ssh.MarshalAuthorizedKey(host)...), 0600); err != nil {
		t.Fatal(err)
	}
	run("-H", known, "-h", "alice@destination.example", private)
	run("-d", private)
	helper := filepath.Join(agentTestDirectory(t), "askpass")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' fixture-password\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{"-x", "-X"} {
		cmd := exec.Command("ssh-add", arg)
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+server.listener.Addr().String(), "SSH_ASKPASS="+helper, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=:fixture")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssh-add %s: %v: %s", arg, err, out)
		}
	}
}

func TestAgentMutationConfirmationBindingAndExpiry(t *testing.T) {
	server, _ := mutationServer(t, filepath.Join(agentTestDirectory(t), "state"), true)
	a := &agentConnection{ctx: context.Background(), keys: server.keys}
	key := mutationPrivate(t)
	pub, _ := ssh.NewPublicKey(key.Public())
	host := bindingSigner(t)
	base := append([]byte{25}, ssh.Marshal(struct {
		Kind            string
		Public, Private []byte
		Comment         string
	}{ssh.KeyAlgoED25519, key[32:], key, "restricted"})...)
	body := append(base, constraintEnvelope(constraintHop("", ""), constraintHop("alice", "host", host.PublicKey()), nil)...)
	body = append(body, 2)
	calls := 0
	server.keys.stateMutex.Lock()
	server.keys.prompt = &agentPrompter{ask: func(context.Context, agentPromptRequest) ([]byte, error) { calls++; return nil, nil }}
	server.keys.stateMutex.Unlock()
	reply, err := a.dispatchMutation(body)
	if err != nil || !bytes.Equal(reply, agentPacket([]byte{6})) {
		t.Fatal("import denied", err)
	}
	data := authData(pub, nil, pub.Type())
	if _, err := a.Sign(pub, data); err == nil || calls != 0 {
		t.Fatal("unbound constrained signing allowed")
	}
	bindingReply(t, a, signedBinding(t, host, []byte("session"), 0), 6)
	for i := 0; i < 2; i++ {
		if _, err := a.Sign(pub, data); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal("confirmation not fresh")
	}
	if err := server.keys.changeLock(context.Background(), []byte("password"), false); err != nil {
		t.Fatal(err)
	}
	if err := server.keys.changeLock(context.Background(), []byte("password"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sign(pub, data); err != nil {
		t.Fatal("binding lost through lock cycle", err)
	}
	bindingReply(t, a, signedBinding(t, host, []byte("conflicting session"), 0), 28)
	if _, err := a.Sign(pub, data); err == nil {
		t.Fatal("poisoned binding signed")
	}
	if reply, _ := a.dispatchMutation([]byte{19}); !bytes.Equal(reply, agentPacket([]byte{5})) {
		t.Fatal("poisoned mutation accepted")
	}
	// Expiry during an outstanding confirmation must discard approval and signature.
	b := &agentConnection{ctx: context.Background(), keys: server.keys}
	bindingReply(t, b, signedBinding(t, host, []byte("session"), 0), 6)
	server.keys.stateMutex.Lock()
	server.keys.prompt = &agentPrompter{ask: func(context.Context, agentPromptRequest) ([]byte, error) {
		server.keys.stateMutex.Lock()
		server.keys.mutations.overlay[string(pub.Marshal())].expires = time.Now().Add(-time.Second)
		server.keys.stateMutex.Unlock()
		return nil, nil
	}}
	server.keys.stateMutex.Unlock()
	if _, err := b.Sign(pub, data); err == nil {
		t.Fatal("late confirmation bypassed expiry")
	}
}
func TestAgentMutationStateTrust(t *testing.T) {
	path := filepath.Join(agentTestDirectory(t), "state")
	file, _, err := openAgentState(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if other, _, err := openAgentState(path, true); err == nil {
		other.close()
		t.Fatal("competing state owner accepted")
	}
	file.close()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if file, _, err := openAgentState(path, false); err == nil {
		file.close()
		t.Fatal("public state accepted")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, []byte(`{"version":1,"version":1,"suppressed":[],"suppress_all":false}`), 0600)
	if file, _, err := openAgentState(path, false); err == nil {
		file.close()
		t.Fatal("ambiguous state accepted")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(agentTestDirectory(t), "target"), path)
	if file, _, err := openAgentState(path, true); err == nil {
		file.close()
		t.Fatal("symlink state accepted")
	}
}
func TestAgentMutationRemoveAllAndDisabledRestart(t *testing.T) {
	path := filepath.Join(agentTestDirectory(t), "state")
	server, client := mutationServer(t, path, true)
	if err := client.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if err := client.Lock([]byte("password")); err != nil {
		t.Fatal(err)
	}
	server.Close()
	next, readonly := mutationServer(t, path, false)
	if !next.keys.locked {
		t.Fatal("disabled mutations unlocked persisted lock")
	}
	if err := readonly.Unlock([]byte("password")); err == nil {
		t.Fatal("disabled mutations accepted unlock")
	}
	if list, err := readonly.List(); err != nil || len(list) != 0 {
		t.Fatal("disabled mode restored identities", err)
	}
	next.keys.stateMutex.Lock()
	next.keys.locked = false
	next.keys.stateMutex.Unlock()
	if list, err := readonly.List(); err != nil || len(list) != 0 {
		t.Fatal("remove-all not durable", err)
	}
}

func TestAgentMutationEnrollmentAndRegistryChange(t *testing.T) {
	server, client := mutationServer(t, filepath.Join(agentTestDirectory(t), "state"), true)
	enrolled := mutationPrivate(t)
	record, _, pub := agentTestRecord(t, enrolled, "collision")
	registry, err := parseAgentRegistry(registryJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.keys.replaceRegistry(registry); err != nil {
		t.Fatal(err)
	}
	if err := client.Remove(pub); err != nil {
		t.Fatal(err)
	}
	if err := client.Add(agent.AddedKey{PrivateKey: enrolled}); err == nil {
		t.Fatal("suppressed enrollment replaced")
	}
	other := mutationPrivate(t)
	otherPub, _ := ssh.NewPublicKey(other.Public())
	if err := client.Add(agent.AddedKey{PrivateKey: other}); err != nil {
		t.Fatal(err)
	}
	record.Comment = "changed policy snapshot"
	registry, err = parseAgentRegistry(registryJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.keys.replaceRegistry(registry); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(otherPub, []byte("after registry change")); err == nil {
		t.Fatal("registry reload retained overlay")
	}
}
func TestAgentMutationPersistentFailureClosesAccess(t *testing.T) {
	directory := agentTestDirectory(t)
	server, client := mutationServer(t, filepath.Join(directory, "state"), true)
	key := mutationPrivate(t)
	pub, _ := ssh.NewPublicKey(key.Public())
	if err := client.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	// An unlinked parent cannot receive new state files, even for root test users.
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}
	if err := client.Lock([]byte("password")); err == nil {
		t.Fatal("unpersisted lock succeeded")
	}
	if _, err := client.Sign(pub, []byte("after state failure")); err == nil {
		t.Fatal("signing after persistence failure")
	}
	if err := server.keys.replaceRegistry(server.keys.registry); err != nil {
		t.Fatal(err)
	}
	if err := client.Add(agent.AddedKey{PrivateKey: mutationPrivate(t)}); err == nil {
		t.Fatal("registry refresh cleared durable-state fault")
	}
}
