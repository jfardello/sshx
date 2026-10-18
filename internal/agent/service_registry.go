package agent

import (
	"crypto/sha256"
	"encoding/json"
)

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
		if s.mutations != nil {
			for blob, entry := range s.mutations.overlay {
				s.retireImportedLocked(blob, entry)
			}
		}
		s.advanceGeneration()
		s.registry, s.byBlob, s.fingerprint = snapshot, byBlob, fingerprint
	}
	s.invalid = false
	return nil
}

func (s *agentKeyService) lookup(blob []byte) (registeredAgentKey, bool) {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	key, _, ok := s.identityLocked(string(blob))
	return key, ok && !s.invalid && !s.mutationFaultLocked()
}
