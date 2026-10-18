package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
