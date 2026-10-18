package agent

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfardello/sshx/internal/credential"
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

// Cold signing operations own their store connection; cache entries own separate
// revocation monitors. Startup and listing never activate a provider. No fallback.
type agentStoreOpener func(context.Context, credentialBackend) (credential.KeyStore, error)

type agentKeyService struct {
	diagnostics       atomic.Pointer[log.Logger]
	registry          *agentRegistry
	byBlob            map[string]registeredAgentKey
	open              agentStoreOpener
	jobs              chan struct{}
	stateMutex        sync.RWMutex
	locked            bool
	generation        uint64
	reloadMutex       sync.Mutex
	source            string
	fingerprint       [32]byte
	invalid           bool
	prompt            *agentPrompter
	changed           chan struct{}
	cache             *agentSignerCache
	mutations         *agentMutationState
	forwardingEnabled bool
}

// The internal lifecycle gate is separate from connection provenance. Wire lock
// operations additionally persist their verifier before publishing the transition.
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
	s.cache.invalidate()
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

func newAgentKeyService(registry *agentRegistry, opener agentStoreOpener) (*agentKeyService, error) {
	snapshot, byBlob, fingerprint, err := agentRegistrySnapshot(registry)
	if err != nil {
		return nil, err
	}
	if opener == nil {
		return nil, errAgentDenied
	}
	return &agentKeyService{registry: snapshot, byBlob: byBlob, fingerprint: fingerprint,
		cache: newAgentSignerCache(), source: registry.source, open: opener, changed: make(chan struct{}), jobs: make(chan struct{}, maxAgentSigningJobs)}, nil
}

func (s *agentKeyService) list(ctx context.Context, bindings *agentBindingState) ([]*sshagent.Key, error) {
	if err := s.refresh(); err != nil {
		return nil, errAgentDenied
	}
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	if ctx.Err() != nil || s.invalid || s.mutationFaultLocked() || (bindings != nil && (bindings.poisoned || (bindings.forwarded && !s.forwardingEnabled))) {
		return nil, errAgentDenied
	}
	result := []*sshagent.Key{}
	if s.locked {
		return result, nil
	}
	for _, key := range s.registry.keys {
		if key.record.Enabled && !s.suppressedLocked(string(key.publicKey.Marshal())) && agentIdentityVisible(key, bindings) {
			result = append(result, &sshagent.Key{Format: key.publicKey.Type(), Blob: key.publicKey.Marshal(), Comment: key.record.Comment})
		}
	}
	if s.mutations != nil {
		for _, entry := range s.mutations.overlay {
			if !entry.retired && (entry.expires.IsZero() || time.Now().Before(entry.expires)) && agentIdentityVisible(entry.key, bindings) {
				result = append(result, &sshagent.Key{Format: entry.key.publicKey.Type(), Blob: entry.key.publicKey.Marshal(), Comment: entry.key.record.Comment})
			}
		}
	}
	return result, nil
}
