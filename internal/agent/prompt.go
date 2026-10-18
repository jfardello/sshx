package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/jfardello/sshx/internal/helperexec"
	"golang.org/x/crypto/ssh"
)

const maxAgentPromptBytes = 16 * 1024

const maxAgentPassphraseBytes = 4096

var (
	errAgentPromptUnavailable = errors.New("local agent prompt unavailable")
	errAgentPromptDenied      = errors.New("local agent prompt denied or invalid")
	errAgentPassphrase        = errors.New("encrypted OpenSSH key could not be decrypted")
)

type agentPromptRequest struct {
	Version        int                    `json:"version"`
	RequestID      string                 `json:"request_id"`
	Operation      string                 `json:"operation"`
	KeyFingerprint string                 `json:"key_fingerprint"`
	DataDigest     string                 `json:"data_digest"`
	Algorithm      string                 `json:"algorithm"`
	Destination    agentPromptDestination `json:"destination"`
}

type agentPromptDestination struct {
	Status          string `json:"status"`
	HostFingerprint string `json:"host_fingerprint,omitempty"`
	Username        string `json:"username,omitempty"`
}

type agentPromptResponse struct {
	Version    int    `json:"version"`
	RequestID  string `json:"request_id"`
	Approved   bool   `json:"approved"`
	Passphrase []byte `json:"passphrase,omitempty"` // JSON base64, private stdout pipe only.
}

type agentPrompter struct {
	ask func(context.Context, agentPromptRequest) ([]byte, error)
}

type agentConnectionIdentity struct{}

// SetPromptHelper configures an explicitly trusted executable, never a shell
// command. Changing it invalidates pending requests. Empty disables prompting.
func (s *agentServer) SetPromptHelper(path string) error {
	var prompt *agentPrompter
	if path != "" {
		if !helperexec.Trusted(path) {
			return errAgentPromptUnavailable
		}
		prompt = &agentPrompter{ask: func(ctx context.Context, request agentPromptRequest) ([]byte, error) {
			return runAgentPrompt(ctx, path, request)
		}}
	}
	s.keys.stateMutex.Lock()
	defer s.keys.stateMutex.Unlock()
	s.keys.prompt = prompt
	s.keys.advanceGeneration()
	return nil
}

func runAgentPrompt(ctx context.Context, path string, request agentPromptRequest) ([]byte, error) {
	input, err := json.Marshal(request)
	if err != nil {
		return nil, errAgentPromptDenied
	}
	defer clearBytes(input)
	output, err := helperexec.Run(ctx, path, input, helperexec.Limits{
		RequestBytes: maxAgentPromptBytes, ResponseBytes: maxAgentPromptBytes,
	})
	defer clearBytes(output)
	if errors.Is(err, helperexec.ErrUnavailable) {
		return nil, errAgentPromptUnavailable
	}
	if err != nil {
		return nil, errAgentPromptDenied
	}
	return decodeAgentPrompt(output, request)
}

func decodeAgentPrompt(data []byte, request agentPromptRequest) ([]byte, error) {
	if len(data) > maxAgentPromptBytes {
		return nil, errAgentPromptDenied
	}
	// Token check avoids duplicate fields and encoding/json's case-folded names.
	check := json.NewDecoder(bytes.NewReader(data))
	token, err := check.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errAgentPromptDenied
	}
	seen := map[string]bool{}
	for check.More() {
		token, err = check.Token()
		if err != nil {
			return nil, errAgentPromptDenied
		}
		name, ok := token.(string)
		if !ok || seen[name] || (name != "version" && name != "request_id" && name != "approved" && name != "passphrase") {
			return nil, errAgentPromptDenied
		}
		seen[name] = true
		var value json.RawMessage
		if check.Decode(&value) != nil {
			return nil, errAgentPromptDenied
		}
		null := bytes.Equal(value, []byte("null"))
		clearBytes(value)
		if null {
			return nil, errAgentPromptDenied
		}
	}
	if _, err = check.Token(); err != nil {
		return nil, errAgentPromptDenied
	}
	if _, err = check.Token(); err != io.EOF {
		return nil, errAgentPromptDenied
	}
	var response agentPromptResponse
	defer func() { clearBytes(response.Passphrase) }()
	if json.Unmarshal(data, &response) != nil || response.Version != 1 || response.RequestID != request.RequestID || !response.Approved {
		return nil, errAgentPromptDenied
	}
	switch request.Operation {
	case "confirm":
		if len(response.Passphrase) != 0 {
			return nil, errAgentPromptDenied
		}
		return nil, nil
	case "passphrase":
		if len(response.Passphrase) == 0 || len(response.Passphrase) > maxAgentPassphraseBytes {
			return nil, errAgentPromptDenied
		}
		return append([]byte(nil), response.Passphrase...), nil
	default:
		return nil, errAgentPromptDenied
	}
}

func newAgentPromptRequest(ctx context.Context, key registeredAgentKey, data []byte, algorithm string, generation uint64, bindings *agentBindingState) (agentPromptRequest, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return agentPromptRequest{}, errAgentPromptUnavailable
	}
	connection, _ := ctx.Value(agentConnectionIdentity{}).([32]byte)
	digest := sha256.Sum256(data)
	// Random nonce makes identical concurrent requests and retries distinct. The
	// transcript binds the exact payload, key, algorithm, connection and generation.
	transcript := ssh.Marshal(struct {
		Nonce, Connection, Key, Data []byte
		Algorithm                    string
		Generation                   uint64
	}{nonce[:], connection[:], key.publicKey.Marshal(), digest[:], algorithm, generation})
	id := sha256.Sum256(transcript)
	request := agentPromptRequest{Version: 1, RequestID: hex.EncodeToString(id[:]), KeyFingerprint: ssh.FingerprintSHA256(key.publicKey), DataDigest: hex.EncodeToString(digest[:]), Algorithm: algorithm, Destination: agentPromptDestination{Status: "unknown"}}
	if key.policy != nil && key.policy.authorize(bindings, key.publicKey.Marshal(), data, algorithm) {
		auth, _ := parseAgentUserauth(data)
		request.Destination = agentPromptDestination{Status: "verified-session-and-policy", HostFingerprint: ssh.FingerprintSHA256(bindings.chain[len(bindings.chain)-1].hostKey), Username: auth.username}
	}
	return request, nil
}

func askAgentPrompt(ctx context.Context, prompt *agentPrompter, request agentPromptRequest, operation string) ([]byte, error) {
	if prompt == nil || ctx.Err() != nil {
		return nil, errAgentPromptUnavailable
	}
	// Separate response namespaces prevent treating passphrase entry as consent.
	id := sha256.Sum256([]byte(request.RequestID + ":" + operation))
	request.RequestID = hex.EncodeToString(id[:])
	request.Operation = operation
	return prompt.ask(ctx, request)
}
