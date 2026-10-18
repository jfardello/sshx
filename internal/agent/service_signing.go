package agent

import (
	"context"
	"crypto/rand"

	"github.com/jfardello/sshx/internal/credential"
	"golang.org/x/crypto/ssh"
)

func (s *agentKeyService) sign(ctx context.Context, blob, data []byte, algorithm string) (*ssh.Signature, error) {
	return s.signBound(ctx, blob, data, algorithm, nil)
}

func (s *agentKeyService) signBound(ctx context.Context, blob, data []byte, algorithm string, bindings *agentBindingState) (signature *ssh.Signature, returnErr error) {
	if err := s.refresh(); err != nil {
		return nil, errAgentDenied
	}
	s.stateMutex.Lock()
	generation, locked, invalid := s.generation, s.locked, s.invalid || s.mutationFaultLocked()
	registry := s.registry
	prompt, changed := s.prompt, s.changed
	forwardingEnabled := s.forwardingEnabled
	key, imported, ok := s.identityLocked(string(blob))
	if imported != nil {
		imported.users++
	}
	s.stateMutex.Unlock()
	if imported != nil {
		defer s.releaseImported(imported)
	}
	s.debug("sign request received")
	if locked || invalid || !ok || len(data) > maxAgentFrameBytes || !agentAlgorithmAllowed(key.publicKey.Type(), algorithm) {
		s.debug("sign denied: locked, unavailable identity or invalid algorithm/payload size")
		return nil, errAgentDenied
	}
	if bindings != nil && (bindings.poisoned || (bindings.forwarded && (!forwardingEnabled || key.policy == nil))) {
		s.debug("request denied: poisoned connection or forwarding not authorized")
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
		if locked || current != generation || !s.importedValid(imported) {
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
	var cached *agentCachedSigner
	defer func() {
		if cached != nil {
			cached.release()
		}
	}()
	// Only fixed error messages cross into upstream protocol logging.
	defer func() {
		refreshErr := s.refresh()
		current, locked := s.signingState()
		if refreshErr != nil || returnErr != nil || ctx.Err() != nil || locked || current != generation || (cached != nil && !cached.valid()) || !s.importedValid(imported) {
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
	sign := func(signer ssh.Signer) error {
		if err := revalidate(); err != nil {
			return err
		}
		algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return errAgentDenied
		}
		var err error
		signature, err = algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
		if err != nil || signature == nil || signature.Format != algorithm {
			return errAgentDenied
		}
		return key.publicKey.Verify(data, signature)
	}
	if imported != nil {
		imported.signMutex.Lock()
		returnErr = sign(imported.signer)
		imported.signMutex.Unlock()
		return signature, returnErr
	}
	cacheKey := string(blob) // Registry generation binds its exact reference and policy.
	useCached := func(entry *agentCachedSigner) error {
		cached = entry
		go func() {
			select {
			case <-entry.done:
				cancel()
			case <-ctx.Done():
			}
		}()
		if err := entry.check(ctx); err != nil {
			return err
		}
		entry.signMutex.Lock()
		err := sign(entry.signer)
		entry.signMutex.Unlock()
		if err != nil {
			return err
		}
		return entry.check(ctx)
	}
	if s.cache.enabled() {
		if entry := s.cache.acquire(cacheKey, generation); entry != nil {
			s.debug("signer cache hit; checking provider readiness")
			err = useCached(entry)
			if err != nil {
				s.debug("cached signing denied or provider invalidated")
			}
			return signature, err
		}
	}
	s.debug("sign authorized; opening credential backend")
	store, err := s.open(ctx, key.record.Backend)
	if store != nil {
		defer func() {
			if err := store.Close(); err != nil {
				if cached != nil {
					cached.invalidate()
				}
				s.debug("sign denied: credential backend cleanup failed")
				returnErr = errAgentDenied
			}
		}()
	}
	if err != nil || store == nil {
		return nil, errAgentDenied
	}
	var lease credential.KeyCacheLease
	if s.cache.enabled() {
		if provider, ok := store.(credential.KeyCacheProvider); ok && s.cache.reserve() {
			lease, err = provider.WatchKey(ctx, credential.Ref{Backend: key.record.Backend, ID: key.record.Reference, Collection: key.record.Collection})
			if err != nil {
				if lease != nil {
					_ = lease.Close()
				}
				<-s.cache.slots
				return nil, errAgentDenied
			}
			if lease == nil {
				<-s.cache.slots
				return nil, errAgentDenied
			}
			defer func() {
				if lease != nil {
					_ = lease.Close()
					<-s.cache.slots
				}
			}()
			if err = lease.Check(ctx); err != nil {
				return nil, errAgentDenied
			}
		} else {
			s.cache.bypasses.Add(1)
			s.debug("signer cache bypass: provider unavailable for caching or capacity reached")
		}
	}
	s.debug("credential backend opened; reading registered key")
	err = registry.withKey(ctx, key.record.ID, store, func(signer ssh.Signer) error {
		if err := revalidate(); err != nil {
			return err
		}
		s.debug("credential read and private-key validation succeeded")
		if lease != nil {
			if err := lease.Check(ctx); err != nil {
				return err
			}
			// Publish atomically with policy/lock transitions. No provider/UI calls
			// occur under stateMutex; the monitor closes its own connection on eviction.
			s.stateMutex.RLock()
			if s.generation == generation && !s.locked && !s.invalid && ctx.Err() == nil {
				cached = s.cache.insert(cacheKey, generation, signer, lease)
			}
			s.stateMutex.RUnlock()
			if cached == nil {
				return errAgentDenied
			}
			lease = nil // Ownership moved to the cache monitor.
			return useCached(cached)
		}
		return sign(signer)
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
