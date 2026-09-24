package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

type agentMutationState struct {
	file        *agentStateFile
	enabled     bool
	failed      bool
	suppressed  map[string]bool
	suppressAll bool
	verifier    *agentLockVerifier
	unlocking   bool
	overlay     map[string]*agentImportedKey
}

// ConfigureMutations loads durable lock/suppression even when wire mutations
// are disabled. It must run before serving; imported private keys are never saved.
func (s *agentServer) ConfigureMutations(path string, enabled bool) error {
	file, document, err := openAgentState(path, enabled)
	if err != nil {
		return err
	}
	if file == nil {
		return nil
	}
	s.keys.stateMutex.Lock()
	defer s.keys.stateMutex.Unlock()
	if s.keys.mutations != nil {
		file.close()
		return errAgentDenied
	}
	m := &agentMutationState{file: file, enabled: enabled, suppressed: map[string]bool{}, suppressAll: document.SuppressAll, verifier: document.Lock, overlay: map[string]*agentImportedKey{}}
	for _, encoded := range document.Suppressed {
		blob, _ := base64.StdEncoding.DecodeString(encoded)
		m.suppressed[string(blob)] = true
	}
	s.keys.mutations = m
	s.keys.locked = m.verifier != nil
	s.keys.advanceGeneration()
	return nil
}
func (s *agentKeyService) mutationAllowed() bool {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return s.mutations != nil && s.mutations.enabled && !s.mutations.failed && !s.invalid
}
func (s *agentKeyService) suppressedLocked(blob string) bool {
	return s.mutations != nil && (s.mutations.suppressAll || s.mutations.suppressed[blob])
}
func (s *agentKeyService) identityLocked(blob string) (registeredAgentKey, *agentImportedKey, bool) {
	if s.mutations != nil {
		if entry := s.mutations.overlay[blob]; entry != nil && !entry.retired && (entry.expires.IsZero() || time.Now().Before(entry.expires)) {
			return entry.key, entry, true
		}
	}
	key, ok := s.byBlob[blob]
	return key, nil, ok && !s.suppressedLocked(blob)
}
func (s *agentKeyService) retireImportedLocked(blob string, entry *agentImportedKey) {
	if entry.retired {
		return
	}
	entry.retired = true
	if entry.timer != nil {
		entry.timer.Stop()
	}
	if s.mutations.overlay[blob] == entry {
		delete(s.mutations.overlay, blob)
	}
	if entry.users == 0 {
		entry.destroy()
		entry.signer = nil
	}
}
func (s *agentKeyService) releaseImported(entry *agentImportedKey) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	entry.users--
	if entry.retired && entry.users == 0 {
		entry.destroy()
		entry.signer = nil
	}
}
func (s *agentKeyService) importedValid(entry *agentImportedKey) bool {
	if entry == nil {
		return true
	}
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return !entry.retired && (entry.expires.IsZero() || time.Now().Before(entry.expires))
}
func (s *agentKeyService) addImported(ctx context.Context, entry *agentImportedKey) error {
	if s.refresh() != nil {
		return errAgentDenied
	}
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	m := s.mutations
	if m == nil || !m.enabled || m.failed || s.locked || s.invalid || ctx.Err() != nil || (entry.key.record.Confirm && s.prompt == nil) {
		return errAgentDenied
	}
	blob := string(entry.key.publicKey.Marshal())
	// Reject every replacement, including disabled/suppressed enrollment aliases.
	for _, key := range s.registry.keys {
		if string(key.publicKey.Marshal()) == blob {
			return errAgentDenied
		}
	}
	if m.overlay[blob] != nil {
		return errAgentDenied
	}
	count, size := len(m.overlay), 5
	for _, key := range s.registry.keys {
		if key.record.Enabled {
			count++
			size += 8 + len(key.publicKey.Marshal()) + len(key.record.Comment)
		}
	}
	for _, key := range m.overlay {
		size += 8 + len(key.key.publicKey.Marshal()) + len(key.key.record.Comment)
	}
	if count >= maxAgentIdentities || size+8+len(blob)+len(entry.key.record.Comment) > maxAgentFrameBytes {
		return errAgentDenied
	}
	if entry.lifetime > 0 {
		entry.expires = time.Now().Add(entry.lifetime)
		entry.timer = time.AfterFunc(entry.lifetime, func() {
			s.stateMutex.Lock()
			defer s.stateMutex.Unlock()
			if !entry.retired {
				s.retireImportedLocked(blob, entry)
				s.advanceGeneration()
			}
		})
	}
	m.overlay[blob] = entry
	s.advanceGeneration()
	return nil
}
func (s *agentKeyService) removeIdentity(ctx context.Context, blob []byte, all bool) error {
	if s.refresh() != nil {
		return errAgentDenied
	}
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	m := s.mutations
	if m == nil || !m.enabled || m.failed || s.locked || s.invalid || ctx.Err() != nil {
		return errAgentDenied
	}
	next := make(map[string]bool, len(m.suppressed))
	for key, value := range m.suppressed {
		next[key] = value
	}
	suppressAll := m.suppressAll
	if all {
		suppressAll = true
	} else {
		_, _, ok := s.identityLocked(string(blob))
		if !ok {
			return errAgentDenied
		}
		if _, ok := s.byBlob[string(blob)]; ok {
			next[string(blob)] = true
		}
	}
	if len(next) > maxAgentIdentities {
		return errAgentDenied
	}
	if err := m.file.save(mutationDocument(next, suppressAll, m.verifier)); err != nil {
		m.failed = true
		s.invalid = true
		s.advanceGeneration()
		return errAgentDenied
	}
	m.suppressed, m.suppressAll = next, suppressAll
	if all {
		for key, entry := range m.overlay {
			s.retireImportedLocked(key, entry)
		}
	} else if entry := m.overlay[string(blob)]; entry != nil {
		s.retireImportedLocked(string(blob), entry)
	}
	s.advanceGeneration()
	return nil
}

const maxAgentLockPassword = 1024
const agentLockRounds = 100000

func (s *agentKeyService) changeLock(ctx context.Context, password []byte, unlock bool) error {
	if len(password) == 0 || len(password) > maxAgentLockPassword || ctx.Err() != nil {
		return errAgentDenied
	}
	s.stateMutex.Lock()
	m := s.mutations
	if m == nil || !m.enabled || m.failed || s.invalid || m.unlocking || unlock != s.locked {
		s.stateMutex.Unlock()
		return errAgentDenied
	}
	if unlock && (m.verifier == nil || time.Now().UnixNano() < m.verifier.NextAttempt) {
		s.stateMutex.Unlock()
		return errAgentDenied
	}
	generation := s.generation
	m.unlocking = true
	var salt, expected []byte
	if unlock {
		salt = append([]byte(nil), m.verifier.Salt...)
		expected = append([]byte(nil), m.verifier.Hash...)
	} else {
		salt = make([]byte, 32)
	}
	s.stateMutex.Unlock()
	defer clearBytes(salt)
	defer clearBytes(expected)
	if !unlock {
		if _, err := rand.Read(salt); err != nil {
			s.stateMutex.Lock()
			m.unlocking = false
			s.stateMutex.Unlock()
			return errAgentDenied
		}
	}
	hash := pbkdf2.Key(password, salt, agentLockRounds, 32, sha256.New)
	defer clearBytes(hash)
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	m.unlocking = false
	if ctx.Err() != nil || s.generation != generation || s.invalid {
		return errAgentDenied
	}
	var next *agentLockVerifier
	success := !unlock || subtle.ConstantTimeCompare(hash, expected) == 1
	if unlock && !success {
		clone := *m.verifier
		if clone.Failures < 6 {
			clone.Failures++
		}
		clone.NextAttempt = time.Now().Add(time.Second * time.Duration(1<<min(clone.Failures-1, 5))).UnixNano()
		next = &clone
	} else if !unlock {
		next = &agentLockVerifier{Salt: append([]byte(nil), salt...), Hash: append([]byte(nil), hash...)}
	}
	if err := m.file.save(mutationDocument(m.suppressed, m.suppressAll, next)); err != nil {
		m.failed = true
		s.invalid = true
		s.advanceGeneration()
		return errAgentDenied
	}
	m.verifier = next
	s.locked = next != nil
	s.advanceGeneration()
	if !success {
		return errAgentDenied
	}
	return nil
}
func (s *agentKeyService) closeMutations() {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	if m := s.mutations; m != nil {
		for blob, entry := range m.overlay {
			s.retireImportedLocked(blob, entry)
		}
		m.file.close()
		s.mutations = nil
	}
}

func (a *agentConnection) dispatchMutation(body []byte) ([]byte, error) {
	failure := agentPacket([]byte{agentFailureCode})
	if !a.keys.mutationAllowed() || a.denied || a.bindings.poisoned || a.bindings.forwarded || a.ctx.Err() != nil {
		return failure, nil
	}
	var err error
	switch body[0] {
	case 17, 25:
		a.keys.stateMutex.RLock()
		locked := a.keys.locked
		a.keys.stateMutex.RUnlock()
		if locked {
			return failure, nil
		}
		select {
		case a.keys.jobs <- struct{}{}:
			defer func() { <-a.keys.jobs }()
		default:
			return failure, nil
		}
		var entry *agentImportedKey
		entry, err = parseAgentAdd(body)
		if err == nil {
			err = a.keys.addImported(a.ctx, entry)
			if err != nil {
				entry.destroy()
			}
		}
	case 18:
		blob, rest, ok := agentWireString(body[1:])
		if !ok || len(rest) != 0 || len(blob) > maxAgentBindingKeyBytes {
			return failure, nil
		}
		err = a.keys.removeIdentity(a.ctx, blob, false)
	case 19:
		if len(body) != 1 {
			return failure, nil
		}
		err = a.keys.removeIdentity(a.ctx, nil, true)
	case 22, 23:
		password, rest, ok := agentWireString(body[1:])
		if !ok || len(rest) != 0 {
			return failure, nil
		}
		err = a.keys.changeLock(a.ctx, password, body[0] == 23)
	default:
		return failure, nil
	}
	if err != nil {
		a.keys.debug("agent mutation denied")
		return failure, nil
	}
	a.keys.debug("agent mutation accepted")
	return agentPacket([]byte{6}), nil
}

func (s *agentKeyService) mutationFaultLocked() bool { return s.mutations != nil && s.mutations.failed }
