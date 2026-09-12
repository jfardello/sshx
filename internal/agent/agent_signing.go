package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/jfardello/sshx/internal/credential"
	"golang.org/x/crypto/ssh"
)

const (
	maxAgentIdentities  = 256
	maxAgentSigningJobs = 4
)

var (
	errAgentDenied   = errors.New("SSH agent request denied")
	errAgentBusy     = errors.New("SSH agent signing capacity exhausted")
	errAgentProtocol = errors.New("invalid SSH agent message")
)

// Each signing operation owns its store connection. Opening is lazy, so neither
// agent startup nor identity listing activates a provider. No automatic fallback.
type agentStoreOpener func(context.Context, credentialBackend) (credential.KeyStore, error)

type agentKeyService struct {
	registry *agentRegistry
	byBlob   map[string]registeredAgentKey
	open     agentStoreOpener
	jobs     chan struct{}
}

func newAgentKeyService(registry *agentRegistry, opener agentStoreOpener) (*agentKeyService, error) {
	if registry == nil {
		return nil, errAgentRegistry
	}
	// Validate and detach the registry snapshot from its caller. Policy changes
	// require stopping and recreating the service in this phase.
	records := make([]agentKeyRecord, 0, len(registry.keys))
	for _, key := range registry.keys {
		records = append(records, key.record)
	}
	data, err := json.Marshal(agentRegistryDocument{Version: 1, Keys: records})
	if err != nil {
		return nil, errAgentRegistry
	}
	snapshot, err := parseAgentRegistry(data)
	if err != nil {
		return nil, err
	}
	service := &agentKeyService{registry: snapshot, byBlob: make(map[string]registeredAgentKey), open: opener, jobs: make(chan struct{}, maxAgentSigningJobs)}
	replySize := 5
	for _, key := range snapshot.keys {
		if key.record.Enabled {
			blob := key.publicKey.Marshal()
			service.byBlob[string(blob)] = key
			replySize += 8 + len(blob) + len(key.record.Comment)
		}
	}
	if len(service.byBlob) > maxAgentIdentities || replySize > maxAgentFrameBytes {
		return nil, errAgentRegistry
	}
	if opener == nil {
		return nil, errAgentDenied
	}
	return service, nil
}
func (s *agentKeyService) sign(ctx context.Context, blob, data []byte, algorithm string) (signature *ssh.Signature, returnErr error) {
	key, ok := s.byBlob[string(blob)]
	if !ok || len(data) > maxAgentFrameBytes || !agentAlgorithmAllowed(key.publicKey.Type(), algorithm) {
		return nil, errAgentDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, errAgentDenied
	}
	select {
	case s.jobs <- struct{}{}:
		defer func() { <-s.jobs }()
	default:
		return nil, errAgentBusy
	}
	ctx, cancel := context.WithTimeout(ctx, credentialOperationTimeout)
	defer cancel()
	// Only fixed error messages cross into upstream protocol logging.
	defer func() {
		if returnErr != nil || ctx.Err() != nil {
			if signature != nil {
				clearBytes(signature.Blob)
			}
			signature = nil
			returnErr = errAgentDenied
		}
	}()
	store, err := s.open(ctx, key.record.Backend)
	if store != nil {
		defer func() {
			if err := store.Close(); err != nil {
				returnErr = errAgentDenied
			}
		}()
	}
	if err != nil || store == nil {
		return nil, errAgentDenied
	}
	err = s.registry.withKey(ctx, key.record.ID, store, func(signer ssh.Signer) error {
		algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return errAgentDenied
		}
		var err error
		signature, err = algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
		if err != nil || signature == nil || signature.Format != algorithm {
			return errAgentDenied
		}
		// Also catch inconsistent provider private-key encodings before releasing a
		// result. Verification uses the trusted registered public key.
		return key.publicKey.Verify(data, signature)
	})
	return signature, err
}
func agentAlgorithmAllowed(keyType, algorithm string) bool {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return algorithm == ssh.KeyAlgoRSASHA256 || algorithm == ssh.KeyAlgoRSASHA512
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return algorithm == keyType
	default:
		return false
	}
}
