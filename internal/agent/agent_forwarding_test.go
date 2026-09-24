package agent

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func forwardingFixture(t *testing.T, hosts []ssh.Signer, enabled bool) (*agentConnection, *agentTestBackend, ssh.PublicKey, *agentServer) {
	t.Helper()
	record, raw := policyRecord(t, hosts[len(hosts)-1].PublicKey())
	record.Destinations.Edges = nil
	var previous ssh.PublicKey
	for _, host := range hosts {
		record.Destinations.Edges = append(record.Destinations.Edges, policyEdge(previous, host.PublicKey(), "alice"))
		previous = host.PublicKey()
	}
	a, backend := policyConnection(t, record, raw, nil)
	server := &agentServer{keys: a.keys}
	server.SetForwardingEnabled(enabled)
	t.Cleanup(func() { a.keys.cache.close(); a.keys.closeMutations() })
	return a, backend, policyPublic(t, record), server
}
func bindForwardingPath(t *testing.T, a *agentConnection, hosts []ssh.Signer) {
	t.Helper()
	for i, host := range hosts {
		sid := []byte(fmt.Sprintf("hop-%d", i))
		flag := byte(1)
		if i == len(hosts)-1 {
			sid = []byte("session")
			flag = 0
		}
		bindingReply(t, a, signedBinding(t, host, sid, flag), 6)
	}
}
func TestAgentForwardingPaths(t *testing.T) {
	for _, hops := range []int{2, 3} {
		t.Run(fmt.Sprint(hops), func(t *testing.T) {
			hosts := make([]ssh.Signer, hops)
			for i := range hosts {
				hosts[i] = bindingSigner(t)
			}
			a, b, pub, _ := forwardingFixture(t, hosts, true)
			// A forwarding-only connection exposes only keys with an onward grant.
			bindingReply(t, a, signedBinding(t, hosts[0], []byte("hop-0"), 1), 6)
			if list, err := a.List(); err != nil || len(list) != 1 || b.opens.Load() != 0 {
				t.Fatal("forwarding visibility", err)
			}
			if _, err := a.Sign(pub, authData(pub, hosts[0].PublicKey(), pub.Type())); err == nil {
				t.Fatal("forwarding-only signing succeeded")
			}
			for i := 1; i < hops; i++ {
				flag := byte(1)
				sid := []byte(fmt.Sprintf("hop-%d", i))
				if i == hops-1 {
					flag = 0
					sid = []byte("session")
				}
				bindingReply(t, a, signedBinding(t, hosts[i], sid, flag), 6)
			}
			data := authData(pub, hosts[hops-1].PublicKey(), pub.Type())
			sig, err := a.Sign(pub, data)
			if err != nil || pub.Verify(data, sig) != nil {
				t.Fatal("allowed chain", err)
			}
			before := b.reads.Load()
			if _, err := a.Sign(pub, authData(pub, nil, pub.Type())); err == nil || b.reads.Load() != before {
				t.Fatal("legacy forwarded auth accessed key")
			}
			if _, err := a.Sign(pub, authData(pub, hosts[0].PublicKey(), pub.Type())); err == nil || b.reads.Load() != before {
				t.Fatal("substituted host accessed key")
			}
			b.assertCleared(t)
		})
	}
}
func TestAgentForwardingDeniedPaths(t *testing.T) {
	hosts := []ssh.Signer{bindingSigner(t), bindingSigner(t), bindingSigner(t)}
	for _, scenario := range []string{"missing-origin", "missing-middle", "missing-final", "reordered", "wrong-host", "wrong-user", "resigned-session", "unbound", "default-off"} {
		t.Run(scenario, func(t *testing.T) {
			a, b, pub, s := forwardingFixture(t, hosts, scenario != "default-off")
			data := authData(pub, hosts[2].PublicKey(), pub.Type())
			if scenario == "default-off" {
				bindingReply(t, a, signedBinding(t, hosts[0], []byte("hop-0"), 1), 28)
			} else if scenario != "unbound" {
				chain := append([]ssh.Signer(nil), hosts...)
				if scenario == "reordered" {
					chain[0], chain[1] = chain[1], chain[0]
				}
				if scenario == "wrong-host" {
					chain[1] = bindingSigner(t)
				}
				if scenario == "resigned-session" {
					chain[2] = hosts[1]
				}
				bindForwardingPath(t, a, chain)
			}
			record := s.keys.registry.keys[0].record
			switch scenario {
			case "missing-origin":
				record.Destinations.Edges = record.Destinations.Edges[1:]
			case "missing-middle":
				record.Destinations.Edges = append(record.Destinations.Edges[:1], record.Destinations.Edges[2:]...)
			case "missing-final":
				record.Destinations.Edges = record.Destinations.Edges[:2]
			case "wrong-user":
				record.Destinations.Edges[2].To.Username = "somebody-else"
			case "resigned-session":
				record.Destinations.Edges = append(record.Destinations.Edges, policyEdge(hosts[1].PublicKey(), hosts[1].PublicKey(), "alice"))
			}
			reg, err := parseAgentRegistry(policyJSON(t, record))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.keys.replaceRegistry(reg); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Sign(pub, data); err == nil || b.opens.Load() != 0 {
				t.Fatal("denied path fetched private key")
			}
		})
	}
}
func TestAgentForwardingVisibilityAndControl(t *testing.T) {
	hosts := []ssh.Signer{bindingSigner(t), bindingSigner(t)}
	a, b, pub, s := forwardingFixture(t, hosts, true)
	if err := s.ConfigureMutations(filepath.Join(agentTestDirectory(t), "state"), true); err != nil {
		t.Fatal(err)
	}
	restricted := s.keys.registry.keys[0].record
	unrestricted, raw := testAgentKey(t)
	unrestricted.ID = "local"
	unrestricted.Reference = "local"
	unrestricted.Policy = "unrestricted-local"
	b.data[unrestricted.Reference] = raw
	reg, err := parseAgentRegistry(policyJSON(t, restricted, unrestricted))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.keys.replaceRegistry(reg); err != nil {
		t.Fatal(err)
	}
	bindingReply(t, a, signedBinding(t, hosts[0], []byte("bastion"), 1), 6)
	if list, err := a.List(); err != nil || len(list) != 1 || !bytes.Equal(list[0].Blob, pub.Marshal()) {
		t.Fatal("unrestricted identity exposed", err)
	}
	localPub := policyPublic(t, unrestricted)
	if _, err := a.Sign(localPub, []byte("arbitrary")); err == nil || b.opens.Load() != 0 {
		t.Fatal("unrestricted forwarded sign")
	}
	before := s.keys.generation
	private := mutationPrivate(t)
	addBody := ssh.Marshal(struct {
		Kind            string
		Public, Private []byte
		Comment         string
	}{ssh.KeyAlgoED25519, private[32:], private, "remote import"})
	for _, op := range []byte{17, 18, 19, 22, 23, 25} {
		body := []byte{op}
		switch op {
		case 17, 25:
			body = append(body, addBody...)
		case 18:
			body = append(body, constraintString(pub.Marshal())...)
		case 22, 23:
			body = append(body, constraintString([]byte("password"))...)
		}
		reply, err := dispatchAgentFrame(a, body)
		if err != nil || !bytes.Equal(reply, agentPacket([]byte{5})) {
			t.Fatal("remote control admitted", op, err)
		}
	}
	if s.keys.generation != before || s.keys.locked || s.keys.mutations.suppressAll {
		t.Fatal("remote control changed state")
	}
	// No onward edge after the final forwarding hop: no identities visible.
	bindingReply(t, a, signedBinding(t, hosts[1], []byte("destination"), 1), 6)
	if list, err := a.List(); err != nil || len(list) != 0 {
		t.Fatal("dead-end identities exposed", err)
	}
}
func TestAgentForwardingLockAndGeneration(t *testing.T) {
	hosts := []ssh.Signer{bindingSigner(t), bindingSigner(t)}
	a, b, pub, s := forwardingFixture(t, hosts, true)
	if err := s.ConfigureMutations(filepath.Join(agentTestDirectory(t), "state"), true); err != nil {
		t.Fatal(err)
	}
	if err := s.keys.changeLock(context.Background(), []byte("password"), false); err != nil {
		t.Fatal(err)
	}
	bindForwardingPath(t, a, hosts)
	if list, err := a.List(); err != nil || len(list) != 0 {
		t.Fatal("locked listing", err)
	}
	if err := s.keys.changeLock(context.Background(), []byte("password"), true); err != nil {
		t.Fatal(err)
	}
	data := authData(pub, hosts[1].PublicKey(), pub.Type())
	if _, err := a.Sign(pub, data); err != nil {
		t.Fatal("bindings lost through lock", err)
	}
	if _, err := a.Sign(pub, authData(pub, nil, pub.Type())); err == nil {
		t.Fatal("unlock restored local-only privilege")
	}
	b.read = func(context.Context) error { s.SetForwardingEnabled(false); return nil }
	if _, err := a.Sign(pub, data); err == nil {
		t.Fatal("late signature survived disabling forwarding")
	}
	s.SetForwardingEnabled(true)
	b.read = nil
	bindingReply(t, a, signedBinding(t, hosts[1], []byte("another terminal"), 0), 28)
	s.keys.setLocked(true)
	s.keys.setLocked(false)
	if _, err := a.Sign(pub, data); err == nil {
		t.Fatal("lock cleared poisoning")
	}
}
func TestAgentForwardingConnectionIsolation(t *testing.T) {
	hosts := []ssh.Signer{bindingSigner(t), bindingSigner(t)}
	a, b, pub, _ := forwardingFixture(t, hosts, true)
	bindForwardingPath(t, a, hosts)
	other := &agentConnection{ctx: context.Background(), keys: a.keys}
	bindForwardingPath(t, other, []ssh.Signer{bindingSigner(t), hosts[1]})
	data := authData(pub, hosts[1].PublicKey(), pub.Type())
	var workers sync.WaitGroup
	for _, conn := range []*agentConnection{a, other} {
		workers.Add(1)
		go func(c *agentConnection) {
			defer workers.Done()
			for i := 0; i < 10; i++ {
				list, err := c.List()
				if err != nil {
					t.Error(err)
					return
				}
				want := 0
				if c == a {
					want = 1
				}
				if len(list) != want {
					t.Error("cross-connection listing")
				}
				_, err = c.Sign(pub, data)
				if (err == nil) != (c == a) {
					t.Error("cross-connection signing")
				}
			}
		}(conn)
	}
	workers.Wait()
	if b.reads.Load() != 10 {
		t.Fatal("denied connection fetched material")
	}
}

func TestAgentForwardingImportedIdentities(t *testing.T) {
	hosts := []ssh.Signer{bindingSigner(t), bindingSigner(t)}
	a, _, _, s := forwardingFixture(t, hosts, true)
	if err := s.ConfigureMutations(filepath.Join(agentTestDirectory(t), "state"), true); err != nil {
		t.Fatal(err)
	}
	local := &agentConnection{ctx: context.Background(), keys: a.keys}
	var restrictedPub, localPub ssh.PublicKey
	for _, restricted := range []bool{true, false} {
		private := mutationPrivate(t)
		pub, _ := ssh.NewPublicKey(private.Public())
		body := append([]byte{25}, ssh.Marshal(struct {
			Kind            string
			Public, Private []byte
			Comment         string
		}{ssh.KeyAlgoED25519, private[32:], private, "import"})...)
		if restricted {
			origin := constraintEnvelope(constraintHop("", ""), constraintHop("alice", "b", hosts[0].PublicKey()), nil)
			onward := constraintEnvelope(constraintHop("", "b", hosts[0].PublicKey()), constraintHop("alice", "d", hosts[1].PublicKey()), nil)
			_, rest, _ := agentWireString(origin[1:])
			first, _, _ := agentWireString(rest)
			_, rest, _ = agentWireString(onward[1:])
			second, _, _ := agentWireString(rest)
			body = append(body, 255)
			body = append(body, constraintString([]byte(agentDestinationExtension))...)
			body = append(body, constraintString(append(first, second...))...)
			restrictedPub = pub
		} else {
			localPub = pub
		}
		reply, err := dispatchAgentFrame(local, body)
		if err != nil || !bytes.Equal(reply, agentPacket([]byte{6})) {
			t.Fatal("local import", err)
		}
	}
	bindForwardingPath(t, a, hosts)
	list, err := a.List()
	if err != nil || len(list) != 2 {
		t.Fatal("imported visibility", err)
	}
	for _, key := range list {
		if bytes.Equal(key.Blob, localPub.Marshal()) {
			t.Fatal("local import leaked")
		}
	}
	if _, err := a.Sign(localPub, []byte("arbitrary")); err == nil {
		t.Fatal("local import signed remotely")
	}
	data := authData(restrictedPub, hosts[1].PublicKey(), restrictedPub.Type())
	sig, err := a.Sign(restrictedPub, data)
	if err != nil || restrictedPub.Verify(data, sig) != nil {
		t.Fatal("constrained import failed", err)
	}
}

func TestAgentForwardingInvalidBindingWhileLocked(t *testing.T) {
	hosts := []ssh.Signer{bindingSigner(t), bindingSigner(t)}
	a, b, pub, s := forwardingFixture(t, hosts, true)
	if err := s.ConfigureMutations(filepath.Join(agentTestDirectory(t), "state"), true); err != nil {
		t.Fatal(err)
	}
	if err := s.keys.changeLock(context.Background(), []byte("password"), false); err != nil {
		t.Fatal(err)
	}
	bindingReply(t, a, signedBinding(t, hosts[0], []byte("bastion"), 1), 6)
	// A well-formed remote unlock must not exercise local password verification.
	body := append([]byte{23}, constraintString([]byte("password"))...)
	if reply, _ := dispatchAgentFrame(a, body); !bytes.Equal(reply, agentPacket([]byte{5})) || !s.keys.locked {
		t.Fatal("remote unlock succeeded")
	}
	bad := signedBinding(t, hosts[1], []byte("session"), 0)
	bad[len(bad)-2] ^= 1
	bindingReply(t, a, bad, 28)
	if err := s.keys.changeLock(context.Background(), []byte("password"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sign(pub, authData(pub, hosts[1].PublicKey(), pub.Type())); err == nil || b.opens.Load() != 0 {
		t.Fatal("unlock cleared invalid binding")
	}
}
