package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

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
