package agent

// SetForwardingEnabled opts in to recorded-chain, destination-constrained use.
// Changes cancel pending signatures and invalidate caches, but never erase a
// connection's bindings or restore a connection already denied by admission.
func (s *agentServer) SetForwardingEnabled(enabled bool) {
	s.keys.stateMutex.Lock()
	defer s.keys.stateMutex.Unlock()
	if s.keys.forwardingEnabled != enabled {
		s.keys.forwardingEnabled = enabled
		s.keys.advanceGeneration()
	}
}

func (s *agentKeyService) forwardingAllowed() bool {
	if s == nil {
		return false
	}
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return s.forwardingEnabled
}

func agentIdentityVisible(key registeredAgentKey, bindings *agentBindingState) bool {
	if key.policy != nil {
		return key.policy.visible(bindings)
	}
	return bindings == nil || !bindings.forwarded
}
