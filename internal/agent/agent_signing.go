package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"sync/atomic"

	"github.com/jfardello/sshx/internal/credential"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
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
	diagnostics atomic.Pointer[log.Logger]
	registry    *agentRegistry
	byBlob      map[string]registeredAgentKey
	open        agentStoreOpener
	jobs        chan struct{}
	stateMutex  sync.RWMutex
	locked      bool
	generation  uint64
	reloadMutex sync.Mutex
	source      string
	fingerprint [32]byte
	invalid     bool
	prompt      *agentPrompter
	changed     chan struct{}
}

// The lifecycle lock gate is separate from connection provenance. Public lock
// commands/password handling remain deferred; future management must use this
// transition rather than replacing connection adapters or their bindings.
func (s *agentKeyService) setLocked(locked bool) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	if s.locked != locked {
		s.locked = locked
		s.advanceGeneration()
	}
}

// advanceGeneration is called with stateMutex held.
func (s *agentKeyService) advanceGeneration() {
	s.generation++
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}

func (s *agentKeyService) signingState() (uint64, bool) {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return s.generation, s.locked
}

func agentRegistrySnapshot(registry *agentRegistry) (*agentRegistry, map[string]registeredAgentKey, [32]byte, error) {
	var fingerprint [32]byte
	if registry == nil {
		return nil, nil, fingerprint, errAgentRegistry
	}
	records := make([]agentKeyRecord, 0, len(registry.keys))
	for _, key := range registry.keys {
		records = append(records, key.record)
	}
	data, err := json.Marshal(agentRegistryDocument{Version: 2, Keys: records})
	if err != nil {
		return nil, nil, fingerprint, errAgentRegistry
	}
	snapshot, err := parseAgentRegistry(data)
	if err != nil {
		return nil, nil, fingerprint, err
	}
	byBlob := make(map[string]registeredAgentKey)
	replySize := 5
	for _, key := range snapshot.keys {
		if key.record.Enabled {
			blob := key.publicKey.Marshal()
			byBlob[string(blob)] = key
			replySize += 8 + len(blob) + len(key.record.Comment)
		}
	}
	if len(byBlob) > maxAgentIdentities || replySize > maxAgentFrameBytes {
		return nil, nil, fingerprint, errAgentRegistry
	}
	return snapshot, byBlob, sha256.Sum256(data), nil
}

func newAgentKeyService(registry *agentRegistry, opener agentStoreOpener) (*agentKeyService, error) {
	snapshot, byBlob, fingerprint, err := agentRegistrySnapshot(registry)
	if err != nil {
		return nil, err
	}
	if opener == nil {
		return nil, errAgentDenied
	}
	return &agentKeyService{registry: snapshot, byBlob: byBlob, fingerprint: fingerprint,
		source: registry.source, open: opener, changed: make(chan struct{}), jobs: make(chan struct{}, maxAgentSigningJobs)}, nil
}

// refresh reads only owner-controlled public configuration. Changed, removed or
// invalid policy invalidates requests admitted under the previous generation.
func (s *agentKeyService) refresh() error {
	if s.source == "" {
		return nil
	}
	s.reloadMutex.Lock()
	defer s.reloadMutex.Unlock()
	registry, err := readAgentRegistry(s.source)
	if err != nil {
		s.debug("registry refresh denied: unreadable, invalid or untrusted registry")
		s.invalidateRegistry()
		return errAgentRegistry
	}
	return s.replaceRegistry(registry)
}
func (s *agentKeyService) invalidateRegistry() {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	if !s.invalid {
		s.advanceGeneration()
	}
	s.invalid = true
}
func (s *agentKeyService) replaceRegistry(registry *agentRegistry) error {
	snapshot, byBlob, fingerprint, err := agentRegistrySnapshot(registry)
	if err != nil {
		s.invalidateRegistry()
		return err
	}
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	if s.invalid || fingerprint != s.fingerprint {
		s.advanceGeneration()
		s.registry, s.byBlob, s.fingerprint = snapshot, byBlob, fingerprint
	}
	s.invalid = false
	return nil
}
func (s *agentKeyService) lookup(blob []byte) (registeredAgentKey, bool) {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	key, ok := s.byBlob[string(blob)]
	return key, ok && !s.invalid
}
func (s *agentKeyService) list(ctx context.Context, bindings *agentBindingState) ([]*sshagent.Key, error) {
	if bindings != nil && (bindings.poisoned || bindings.forwarded) {
		s.debug("request denied: poisoned or forwarded connection")
		return nil, errAgentDenied
	}
	if err := s.refresh(); err != nil {
		return nil, errAgentDenied
	}
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	if ctx.Err() != nil || s.invalid {
		return nil, errAgentDenied
	}
	result := []*sshagent.Key{}
	if s.locked {
		return result, nil
	}
	for _, key := range s.registry.keys {
		if key.record.Enabled && (key.policy == nil || key.policy.visible(bindings)) {
			result = append(result, &sshagent.Key{Format: key.publicKey.Type(), Blob: key.publicKey.Marshal(), Comment: key.record.Comment})
		}
	}
	return result, nil
}

func (s *agentKeyService) sign(ctx context.Context, blob, data []byte, algorithm string) (*ssh.Signature, error) {
	return s.signBound(ctx, blob, data, algorithm, nil)
}
func (s *agentKeyService) signBound(ctx context.Context, blob, data []byte, algorithm string, bindings *agentBindingState) (signature *ssh.Signature, returnErr error) {
	if err := s.refresh(); err != nil {
		return nil, errAgentDenied
	}
	s.stateMutex.RLock()
	generation, locked, invalid := s.generation, s.locked, s.invalid
	registry := s.registry
	prompt, changed := s.prompt, s.changed
	key, ok := s.byBlob[string(blob)]
	s.stateMutex.RUnlock()
	s.debug("sign request received")
	if locked || invalid || !ok || len(data) > maxAgentFrameBytes || !agentAlgorithmAllowed(key.publicKey.Type(), algorithm) {
		s.debug("sign denied: locked, unavailable identity or invalid algorithm/payload size")
		return nil, errAgentDenied
	}
	if bindings != nil && (bindings.poisoned || bindings.forwarded) {
		s.debug("request denied: poisoned or forwarded connection")
		return nil, errAgentDenied
	}
	if key.policy != nil && !key.policy.authorize(bindings, blob, data, algorithm) {
		s.debug("sign denied: destination policy or authentication payload mismatch (including missing binding)")
		return nil, errAgentDenied
	}

	if err := ctx.Err(); err != nil {
		return nil, errAgentDenied
	}
	select {
	case s.jobs <- struct{}{}:
		defer func() { <-s.jobs }()
	default:
		s.debug("sign denied: signing capacity exhausted")
		return nil, errAgentBusy
	}
	ctx, cancel := context.WithTimeout(ctx, credentialOperationTimeout)
	defer cancel()
	// An observed policy/helper/lock transition cancels an outstanding helper.
	go func() {
		select {
		case <-changed:
			cancel()
		case <-ctx.Done():
		}
	}()
	revalidate := func() error {
		if ctx.Err() != nil {
			return errAgentDenied
		}
		if s.refresh() != nil {
			return errAgentDenied
		}
		current, locked := s.signingState()
		if locked || current != generation {
			return errAgentDenied
		}
		return nil
	}
	request, err := newAgentPromptRequest(ctx, key, data, algorithm, generation, bindings)
	if err != nil {
		return nil, errAgentDenied
	}
	if key.record.Confirm {
		s.debug("requesting local signing confirmation")
		response, err := askAgentPrompt(ctx, prompt, request, "confirm")
		clearBytes(response)
		if err != nil {
			s.debug("sign denied: local confirmation unavailable, denied or canceled")
			return nil, errAgentDenied
		}
		if revalidate() != nil {
			return nil, errAgentDenied
		}
	}
	// Only fixed error messages cross into upstream protocol logging.
	defer func() {
		refreshErr := s.refresh()
		current, locked := s.signingState()
		if refreshErr != nil || returnErr != nil || ctx.Err() != nil || locked || current != generation {
			if refreshErr != nil || locked || current != generation {
				s.debug("signature discarded: registry or lock generation changed")
			}
			if signature != nil {
				clearBytes(signature.Blob)
			}
			signature = nil
			returnErr = errAgentDenied
		} else {
			s.debug("sign succeeded")
		}
	}()
	s.debug("sign authorized; opening credential backend")
	store, err := s.open(ctx, key.record.Backend)
	if store != nil {
		defer func() {
			if err := store.Close(); err != nil {
				s.debug("sign denied: credential backend cleanup failed")
				returnErr = errAgentDenied
			}
		}()
	}
	if err != nil || store == nil {
		s.debug("sign denied: credential backend open failed")
		return nil, errAgentDenied
	}
	s.debug("credential backend opened; reading registered key")
	err = registry.withKey(ctx, key.record.ID, store, func(signer ssh.Signer) error {
		if err := revalidate(); err != nil {
			return err
		}
		s.debug("credential read and private-key validation succeeded")
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
	}, func(data []byte, public ssh.PublicKey) (ssh.Signer, error) {
		if err := revalidate(); err != nil {
			return nil, err
		}
		return parseAgentKeyWithPrompt(ctx, data, public, prompt, request, revalidate)
	})
	if err != nil {
		s.debug(diagnosticKeyError(err))
	}
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
