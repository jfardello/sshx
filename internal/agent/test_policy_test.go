package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
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

func policyPin(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func policyEdge(from, to ssh.PublicKey, user string) agentDestinationEdge {
	e := agentDestinationEdge{To: agentDestinationHop{Hostname: "destination.example", Username: user, HostKeys: []string{policyPin(to)}}}
	if from != nil {
		e.From = agentDestinationHop{Hostname: "source.example", HostKeys: []string{policyPin(from)}}
	}
	return e
}

func policyRecord(t *testing.T, host ssh.PublicKey) (agentKeyRecord, []byte) {
	t.Helper()
	record, raw := testAgentKey(t)
	record.Policy = "destination-constrained"
	record.Destinations = &agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{policyEdge(nil, host, "alice")}}
	return record, raw
}

func policyJSON(t *testing.T, records ...agentKeyRecord) []byte {
	t.Helper()
	data, err := json.Marshal(agentRegistryDocument{Version: 2, Keys: records})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func policyConnection(t *testing.T, record agentKeyRecord, raw []byte, host ssh.Signer) (*agentConnection, *agentTestBackend) {
	t.Helper()
	reg, err := parseAgentRegistry(policyJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
	service, err := newAgentKeyService(reg, backend.open)
	if err != nil {
		t.Fatal(err)
	}
	a := &agentConnection{ctx: context.Background(), keys: service}
	if host != nil {
		bindingReply(t, a, signedBinding(t, host, []byte("session"), 0), 6)
	}
	return a, backend
}

type policyAuth struct {
	Session               []byte
	Message               byte
	User, Service, Method string
	Follows               bool
	Algorithm             string
	Key                   []byte
}

func authData(key ssh.PublicKey, host ssh.PublicKey, algorithm string) []byte {
	r := policyAuth{[]byte("session"), 50, "alice", "ssh-connection", "publickey", true, algorithm, key.Marshal()}
	if host != nil {
		r.Method = agentHostboundMethod
	}
	data := ssh.Marshal(r)
	if host != nil {
		data = append(data, ssh.Marshal(struct{ Host []byte }{host.Marshal()})...)
	}
	return data
}

func policyPublic(t *testing.T, record agentKeyRecord) ssh.PublicKey {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(record.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writePolicyFile(t *testing.T, name string, data []byte) {
	t.Helper()
	tmp := name + ".new"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, name); err != nil {
		t.Fatal(err)
	}
}

func testAgentBind(t *testing.T, forward byte) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte("test session")
	sig, err := signer.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	contents := ssh.Marshal(struct {
		Host, Session, Signature []byte
		Forward                  byte
	}{signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), forward})
	return ssh.Marshal(struct {
		Name     string `sshtype:"27"`
		Contents []byte `ssh:"rest"`
	}{"session-bind@openssh.com", contents})
}
