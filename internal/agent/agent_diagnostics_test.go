package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAgentMutationDisabledDiagnostics(t *testing.T) {
	const event = "sshx agent: mutation denied: key mutations are disabled; restart with --allow-key-mutations\n"
	for _, tc := range []struct {
		name         string
		mutations    *agentMutationState
		invalid      bool
		wantDisabled bool
	}{
		{"not-configured", nil, false, true},
		{"disabled", &agentMutationState{}, false, true},
		{"enabled-but-failed", &agentMutationState{enabled: true, failed: true}, false, false},
		{"enabled-but-invalid", &agentMutationState{enabled: true}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, verbose := range []bool{false, true} {
				keys := &agentKeyService{mutations: tc.mutations, invalid: tc.invalid}
				server := &agentServer{keys: keys}
				var out bytes.Buffer
				if verbose {
					server.SetDiagnostics(&out)
					out.Reset()
				}
				connection := &agentConnection{ctx: context.Background(), keys: keys}
				// Include sensitive-looking wire data: rejection must happen before
				// parsing it, and diagnostics must contain only the fixed event.
				for _, operation := range []byte{17, 25, 18, 19, 22, 23} {
					out.Reset()
					body := append([]byte{operation}, []byte("SECRET-KEY-OR-PASSPHRASE")...)
					reply, err := connection.dispatchMutation(body)
					if err != nil || !bytes.Equal(reply, agentPacket([]byte{agentFailureCode})) {
						t.Fatalf("operation %d: reply %v, error %v", operation, reply, err)
					}
					want := ""
					if verbose && tc.wantDisabled {
						want = event
					}
					if out.String() != want {
						t.Fatalf("operation %d, verbose %t: diagnostics %q, want %q", operation, verbose, out.String(), want)
					}
				}
			}
		})
	}
}

func TestAgentDiagnosticsStagesAndRedaction(t *testing.T) {
	host := bindingSigner(t)
	record, raw := policyRecord(t, host.PublicKey())
	record.Comment = "PRIVATE-COMMENT"
	a, backend := policyConnection(t, record, raw, nil)
	pub := policyPublic(t, record)
	data := authData(pub, nil, pub.Type())
	server := &agentServer{keys: a.keys}
	var out bytes.Buffer
	// Disabled by default, including normal failures.
	a.Sign(pub, data)
	if a.keys.diagnostics.Load() != nil {
		t.Fatal("diagnostics enabled by default")
	}
	server.SetDiagnostics(&out)
	if _, err := a.Sign(pub, data); err == nil {
		t.Fatal("missing binding accepted")
	}
	if !strings.Contains(out.String(), "destination policy") || backend.reads.Load() != 0 {
		t.Fatal("missing policy diagnostic")
	}
	bindingReply(t, a, signedBinding(t, host, []byte("session"), 0), 6)
	backend.read = func(context.Context) error { return errors.New("SECRET-PROVIDER-ERROR") }
	if _, err := a.Sign(pub, data); err == nil {
		t.Fatal("backend failure ignored")
	}
	if !strings.Contains(out.String(), "credential read or cryptographic operation failed") {
		t.Fatal("missing read diagnostic")
	}
	backend.read = nil
	if _, err := a.Sign(pub, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "sign succeeded") || !strings.Contains(out.String(), "direct session binding accepted") {
		t.Fatal("missing success diagnostics")
	}
	for _, secret := range []string{"SECRET-PROVIDER-ERROR", record.Comment, record.Reference, record.PublicKey, string(raw), string(data)} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("sensitive data in diagnostics")
		}
	}
	n := out.Len()
	server.SetDiagnostics(nil)
	if _, err := a.Sign(pub, data); err != nil {
		t.Fatal(err)
	}
	if out.Len() != n {
		t.Fatal("diagnostics not disabled")
	}
	backend.assertCleared(t)
}
