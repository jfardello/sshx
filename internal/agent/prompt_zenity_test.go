package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/jfardello/sshx/internal/promptprotocol"
	"github.com/jfardello/sshx/internal/promptzenity"
)

type wireDialogs struct {
	approve  bool
	password []byte
}

func (d wireDialogs) Confirm(context.Context, string) (bool, error) { return d.approve, nil }

func (d wireDialogs) Password(context.Context, string) ([]byte, error) {
	return append([]byte(nil), d.password...), nil
}

func TestAgentZenityVersionOneWire(t *testing.T) {
	a, _, pub, data := confirmationAgent(t, false)
	key, _ := a.keys.lookup(pub.Marshal())
	for _, known := range []bool{false, true} {
		request, err := newAgentPromptRequest(context.Background(), key, data, pub.Type(), 0, &a.bindings)
		if err != nil {
			t.Fatal(err)
		}
		if !known {
			request.Destination = agentPromptDestination{Status: "unknown"}
		}
		for _, operation := range []string{"confirm", "passphrase"} {
			request.Operation = operation
			input, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := promptprotocol.DecodeRequest(input); err != nil {
				t.Fatal("agent request incompatible", err)
			}
			for _, approve := range []bool{false, true} {
				dialog := wireDialogs{approve: approve}
				if approve && operation == "passphrase" {
					dialog.password = []byte("test-passphrase")
				}
				var out bytes.Buffer
				if err := promptzenity.Serve(context.Background(), bytes.NewReader(input), &out, dialog); err != nil {
					t.Fatal(err)
				}
				password, err := decodeAgentPrompt(out.Bytes(), request)
				if approve && (err != nil || !bytes.Equal(password, dialog.password)) {
					t.Fatal("approved response incompatible", err)
				}
				if !approve && err != errAgentPromptDenied {
					t.Fatal("denial accepted")
				}
				clearBytes(password)
			}
		}
	}
}
