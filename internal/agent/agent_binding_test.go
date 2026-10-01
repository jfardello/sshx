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
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
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
func bindingPayload(host, session, signature []byte, forward byte) []byte {
	return ssh.Marshal(struct {
		Host, Session, Signature []byte
		Forward                  byte
	}{host, session, signature, forward})
}
func signedBinding(t *testing.T, signer ssh.Signer, session []byte, forward byte) []byte {
	t.Helper()
	algorithm := signer.PublicKey().Type()
	if algorithm == ssh.KeyAlgoRSA {
		algorithm = ssh.KeyAlgoRSASHA512
	}
	sig, err := signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, session, algorithm)
	if err != nil {
		t.Fatal(err)
	}
	return bindingPayload(signer.PublicKey().Marshal(), session, ssh.Marshal(sig), forward)
}
func bindingFrame(payload []byte) []byte {
	return ssh.Marshal(struct {
		Name     string `sshtype:"27"`
		Contents []byte `ssh:"rest"`
	}{sessionBindExtension, payload})
}
func bindingReply(t *testing.T, a *agentConnection, payload []byte, want byte) {
	t.Helper()
	reply, err := dispatchAgentFrame(a, bindingFrame(payload))
	if err != nil || !bytes.Equal(reply, agentPacket([]byte{want})) {
		t.Fatalf("binding reply=%x error=%v want=%d", reply, err, want)
	}
}

func TestAgentBindingHostAlgorithms(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		key       any
		algorithm string
	}{{ed, ssh.KeyAlgoED25519}, {rsaKey, ssh.KeyAlgoRSASHA256}, {rsaKey, ssh.KeyAlgoRSASHA512}}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, struct {
			key       any
			algorithm string
		}{key, pub.Type()})
	}
	for _, fixture := range fixtures {
		t.Run(fixture.algorithm, func(t *testing.T) {
			signer, err := ssh.NewSignerFromKey(fixture.key)
			if err != nil {
				t.Fatal(err)
			}
			sid := []byte("initial exchange hash")
			sig, err := signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, sid, fixture.algorithm)
			if err != nil {
				t.Fatal(err)
			}
			s, b, pub := agentTestService(t)
			a := &agentConnection{ctx: context.Background(), keys: s}
			payload := bindingPayload(signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), 0)
			bindingReply(t, a, payload, 6)
			clearBytes(payload) // The server clears its frame after every dispatch.
			if len(a.bindings.chain) != 1 || !bytes.Equal(a.bindings.chain[0].session, sid) || !bytes.Equal(a.bindings.chain[0].hostKey.Marshal(), signer.PublicKey().Marshal()) {
				t.Fatal("binding retained borrowed frame bytes")
			}
			if b.opens.Load() != 0 {
				t.Fatal("binding read a credential")
			}
			if _, err := a.Sign(pub, []byte("still unrestricted-local")); err != nil {
				t.Fatal(err)
			}
			bindingReply(t, a, signedBinding(t, signer, sid, 0), 28)
			if _, err := a.Sign(pub, nil); err == nil {
				t.Fatal("terminal replay did not poison connection")
			}
		})
	}
	// SHA-1 and undersized RSA host keys are intentionally unsupported.
	for _, bits := range []int{1024, 2048} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		algorithm := ssh.KeyAlgoRSA
		if bits == 1024 {
			algorithm = ssh.KeyAlgoRSASHA256
		}
		sig, err := signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, []byte("sid"), algorithm)
		if err != nil {
			t.Fatal(err)
		}
		var state agentBindingState
		if state.record(bindingPayload(signer.PublicKey().Marshal(), []byte("sid"), ssh.Marshal(sig), 0)) == nil {
			t.Fatal("unsupported RSA host proof accepted")
		}
	}
}

func TestAgentBindingMalformedProofs(t *testing.T) {
	signer := bindingSigner(t)
	other := bindingSigner(t)
	sid := []byte("session")
	signature, err := signer.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	rawSig := ssh.Marshal(signature)
	host := signer.PublicKey().Marshal()
	badSig := bytes.Clone(rawSig)
	badSig[len(badSig)-1] ^= 1
	cases := map[string][]byte{
		"empty": nil, "truncated": {0, 0, 0, 10, 1},
		"host-missing":          bindingPayload(nil, sid, rawSig, 0),
		"host-oversized":        bindingPayload(make([]byte, maxAgentBindingKeyBytes+1), sid, rawSig, 0),
		"host-malformed":        bindingPayload([]byte{1, 2, 3}, sid, rawSig, 0),
		"host-invalid-encoding": bindingPayload(append(host, 0), sid, rawSig, 0),
		"host-unknown":          bindingPayload(ssh.Marshal(struct{ Type string }{"unknown-host-type"}), sid, rawSig, 0),
		"session-empty":         bindingPayload(host, nil, rawSig, 0),
		"session-oversized":     bindingPayload(host, make([]byte, maxAgentSessionBytes+1), rawSig, 0),
		"wrong-session":         bindingPayload(host, []byte("different"), rawSig, 0),
		"wrong-host":            bindingPayload(other.PublicKey().Marshal(), sid, rawSig, 0),
		"signature-corrupt":     bindingPayload(host, sid, badSig, 0),
		"signature-missing":     bindingPayload(host, sid, nil, 0),
		"signature-oversized":   bindingPayload(host, sid, make([]byte, maxAgentBindingSignatureBytes+1), 0),
		"signature-malformed":   bindingPayload(host, sid, []byte{1}, 0),
		"signature-trailing":    bindingPayload(host, sid, append(bytes.Clone(rawSig), 0), 0),
		"signature-empty-blob":  bindingPayload(host, sid, ssh.Marshal(&ssh.Signature{Format: ssh.KeyAlgoED25519}), 0),
		"signature-algorithm":   bindingPayload(host, sid, ssh.Marshal(&ssh.Signature{Format: ssh.KeyAlgoRSASHA512, Blob: signature.Blob}), 0),
		"flag":                  bindingPayload(host, sid, rawSig, 2),
		"trailing":              append(bindingPayload(host, sid, rawSig, 0), 0),
	}
	s, b, pub := agentTestService(t)
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			a := &agentConnection{ctx: context.Background(), keys: s}
			bindingReply(t, a, payload, 28)
			if !a.denied || !a.bindings.poisoned || len(a.bindings.chain) != 0 {
				t.Fatal("failed proof did not poison without enrollment")
			}
			bindingReply(t, a, signedBinding(t, signer, sid, 0), 28)
			if _, err := a.Sign(pub, nil); err == nil {
				t.Fatal("failed proof regained signing")
			}
			if _, err := a.List(); err == nil {
				t.Fatal("failed proof regained identities")
			}
		})
	}
	if b.opens.Load() != 0 {
		t.Fatal("invalid bindings accessed backend")
	}
}

func TestAgentBindingForwardingSequence(t *testing.T) {
	s, b, pub := agentTestService(t)
	signer := bindingSigner(t)
	a := &agentConnection{ctx: context.Background(), keys: s}
	first := signedBinding(t, signer, []byte("hop-one"), 1)
	bindingReply(t, a, first, 28) // proof retained, forwarding admission still denied
	for _, flag := range []byte{1, 0} {
		bindingReply(t, a, signedBinding(t, signer, []byte("hop-one"), flag), 28)
		if len(a.bindings.chain) != 1 || !a.bindings.chain[0].forwarding || a.bindings.poisoned {
			t.Fatal("forwarding replay changed state")
		}
	}
	bindingReply(t, a, signedBinding(t, signer, []byte("hop-two"), 1), 28)
	bindingReply(t, a, signedBinding(t, bindingSigner(t), []byte("destination"), 0), 28)
	if a.bindings.poisoned || len(a.bindings.chain) != 3 || a.bindings.chain[2].forwarding {
		t.Fatal("ordered chain not retained")
	}
	if _, err := a.Sign(pub, nil); err == nil {
		t.Fatal("forwarding enabled prematurely")
	}
	bindingReply(t, a, first, 28)
	if !a.bindings.poisoned {
		t.Fatal("earlier-hop replay bypassed terminal state")
	}
	if b.opens.Load() != 0 {
		t.Fatal("forwarded request opened backend")
	}
	conflict := &agentConnection{ctx: context.Background(), keys: s}
	bindingReply(t, conflict, first, 28)
	bindingReply(t, conflict, signedBinding(t, bindingSigner(t), []byte("hop-one"), 1), 28)
	if !conflict.bindings.poisoned || len(conflict.bindings.chain) != 1 {
		t.Fatal("conflicting host for same session accepted")
	}
}

func TestAgentBindingBounds(t *testing.T) {
	signer := bindingSigner(t)
	var state agentBindingState
	for i := 0; i < maxAgentBindings; i++ {
		if err := state.record(signedBinding(t, signer, []byte(fmt.Sprint(i)), 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.record(signedBinding(t, signer, []byte("0"), 0)); err != nil || len(state.chain) != maxAgentBindings {
		t.Fatal("bounded replay appended or failed")
	}
	if state.record(signedBinding(t, signer, []byte("overflow"), 1)) == nil || !state.poisoned {
		t.Fatal("unbounded chain")
	}
	state = agentBindingState{}
	payload := signedBinding(t, signer, []byte("replay"), 1)
	for i := 0; i < maxAgentBindingAttempts; i++ {
		if err := state.record(payload); err != nil {
			t.Fatal(err)
		}
	}
	if state.record(payload) == nil || !state.poisoned || len(state.chain) != 1 {
		t.Fatal("unbounded verification work")
	}
}

func TestAgentBindingsSurviveSigningLock(t *testing.T) {
	for _, mode := range []string{"direct", "forwarding", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			s, b, pub := agentTestService(t)
			a := &agentConnection{ctx: context.Background(), keys: s}
			s.setLocked(true)
			// Repeating a state transition must not alter its generation.
			generation, _ := s.signingState()
			s.setLocked(true)
			if current, _ := s.signingState(); current != generation {
				t.Fatal("redundant lock invalidated generation")
			}
			payload := signedBinding(t, bindingSigner(t), []byte("bound while locked"), 0)
			want := byte(6)
			if mode == "forwarding" {
				payload[len(payload)-1] = 1
				want = 28
			}
			if mode == "invalid" {
				payload[len(payload)-2] ^= 1
				want = 28
			}
			bindingReply(t, a, payload, want)
			if _, err := a.Sign(pub, nil); err == nil {
				t.Fatal("signing while locked")
			}
			if keys, _ := a.List(); len(keys) != 0 {
				t.Fatal("identities visible while locked")
			}
			if b.opens.Load() != 0 {
				t.Fatal("binding or locked sign accessed backend")
			}
			s.setLocked(false)
			if mode == "direct" {
				if len(a.bindings.chain) != 1 {
					t.Fatal("unlock lost direct binding")
				}
				if _, err := a.Sign(pub, nil); err != nil {
					t.Fatal(err)
				}
				s.setLocked(true)
				s.setLocked(false)
				bindingReply(t, a, payload, 28) // terminal state survived another lock cycle
			} else {
				if _, err := a.Sign(pub, nil); err == nil {
					t.Fatal("unlock restored local privileges")
				}
				if mode == "forwarding" && (len(a.bindings.chain) != 1 || !a.bindings.forwarded) {
					t.Fatal("unlock lost forwarding provenance")
				}
			}
			// Unrelated connections retain their own clean admission state.
			clean := &agentConnection{ctx: context.Background(), keys: s}
			if _, err := clean.Sign(pub, nil); err != nil {
				t.Fatal("one connection poisoned another", err)
			}
		})
	}
}

func TestAgentLockInvalidatesInFlightSignature(t *testing.T) {
	s, b, pub := agentTestService(t)
	entered, release := make(chan struct{}), make(chan struct{})
	b.read = func(context.Context) error { close(entered); <-release; return nil }
	done := make(chan error, 1)
	go func() {
		sig, err := s.sign(context.Background(), pub.Marshal(), []byte("before lock"), pub.Type())
		if sig != nil || err == nil {
			done <- fmt.Errorf("stale signature released")
			return
		}
		done <- nil
	}()
	<-entered
	s.setLocked(true)
	s.setLocked(false)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	b.assertCleared(t)
}

func bindingSocketReply(t *testing.T, conn net.Conn, payload []byte, want byte) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeAgentReply(conn, agentPacket(bindingFrame(payload))); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, agentPacket([]byte{want})) {
		t.Fatalf("socket binding=%x: %v", reply, err)
	}
}
func TestAgentBindingSocketLifetime(t *testing.T) {
	_, backend, path, _, _ := agentTestServer(t)
	conn := agentTestDial(t, path)
	payload := testAgentBind(t, 0)
	_, contents, ok := agentWireString(payload[1:])
	if !ok {
		t.Fatal("fixture encoding")
	}
	bindingSocketReply(t, conn, contents, 6)
	bindingSocketReply(t, conn, contents, 28)
	if _, err := sshagent.NewClient(conn).List(); err == nil {
		t.Fatal("poisoned live socket listed keys")
	}
	conn.Close()
	fresh := agentTestDial(t, path)
	bindingSocketReply(t, fresh, contents, 6)
	if keys, err := sshagent.NewClient(fresh).List(); err != nil || len(keys) != 1 {
		t.Fatal("new connection inherited stale binding")
	}
	if backend.opens.Load() != 0 {
		t.Fatal("binding lifecycle accessed backend")
	}
}

func FuzzAgentBinding(f *testing.F) {
	signer, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	sid := []byte("fuzz session")
	sig, _ := signer.Sign(rand.Reader, sid)
	for _, flag := range []byte{0, 1, 2} {
		f.Add(bindingPayload(signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), flag), []byte{})
	}
	forward := bindingPayload(signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), 1)
	direct := bindingPayload(signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), 0)
	f.Add(forward, forward)
	f.Add(forward, direct)
	f.Add(direct, forward)
	f.Add([]byte{}, []byte{0, 0, 0, 255})
	f.Fuzz(func(t *testing.T, first, second []byte) {
		var state agentBindingState
		for _, payload := range [][]byte{first, second, first} {
			poisoned := state.poisoned
			if err := state.record(payload); err != nil && !state.poisoned {
				t.Fatal("failure not sticky")
			}
			if poisoned && !state.poisoned {
				t.Fatal("poisoned state reset")
			}
			if len(state.chain) > maxAgentBindings || state.attempts > maxAgentBindingAttempts {
				t.Fatal("unbounded state")
			}
			for _, binding := range state.chain {
				if len(binding.session) > maxAgentSessionBytes {
					t.Fatal("unbounded session")
				}
			}
		}
		for _, service := range []*agentKeyService{nil, {forwardingEnabled: true}} {
			a := &agentConnection{ctx: context.Background(), keys: service}
			for _, payload := range [][]byte{first, second, first} {
				reply, _ := dispatchAgentFrame(a, bindingFrame(payload))
				if len(reply) != 5 || binary.BigEndian.Uint32(reply[:4]) != 1 {
					t.Fatal("bad binding response")
				}
			}
		}
	})
}

func TestAgentBindingResponseCodes(t *testing.T) {
	s, b, pub := agentTestService(t)
	a := &agentConnection{ctx: context.Background(), keys: s}
	unknown := ssh.Marshal(struct {
		Name string `sshtype:"27"`
	}{"unknown-extension"})
	for _, locked := range []bool{false, true} {
		s.setLocked(locked)
		reply, err := dispatchAgentFrame(a, unknown)
		if err != nil || !bytes.Equal(reply, agentPacket([]byte{5})) || a.denied {
			t.Fatal("unknown extension did not remain unsupported")
		}
	}
	payload := signedBinding(t, bindingSigner(t), []byte("locked response"), 0)
	bindingReply(t, a, payload, 6)
	if reply, err := dispatchAgentFrame(a, []byte{agentListCode}); err != nil || len(reply) != 9 || reply[4] != 12 || binary.BigEndian.Uint32(reply[5:]) != 0 {
		t.Fatal("locked wire listing not empty")
	}
	if reply, err := dispatchAgentFrame(a, agentSignBody(pub, nil, 0)); err != nil || reply[4] != 5 {
		t.Fatal("locked wire signing accepted")
	}
	for _, opcode := range []byte{22, 23} { // public lock/unlock remain unsupported
		if reply, err := dispatchAgentFrame(a, []byte{opcode}); err != nil || reply[4] != 5 {
			t.Fatal("premature public lock command")
		}
	}
	s.setLocked(false)
	bindingReply(t, a, payload, 28)
	if reply, err := dispatchAgentFrame(a, unknown); err != nil || reply[4] != 5 {
		t.Fatal("unsupported and known failure codes conflated")
	}
	if b.opens.Load() != 0 {
		t.Fatal("locked requests accessed backend")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	a = &agentConnection{ctx: cancelled, keys: s}
	bindingReply(t, a, payload, 28)
	if !a.bindings.poisoned {
		t.Fatal("cancellation restored unbound state")
	}
}
