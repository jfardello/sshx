package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfardello/sshx/internal/credential"
	"golang.org/x/crypto/ssh"
)

const maxAgentCachedSigners = 16
const maxAgentCacheTTL = 5 * time.Minute

type AgentCacheStats struct{ Hits, Misses, Bypasses, Evictions uint64 }
type agentSignerCache struct {
	mutex                             sync.Mutex
	entries                           map[string]*agentCachedSigner
	slots                             chan struct{}
	ttl                               time.Duration
	now                               func() time.Time
	closed                            bool
	workers                           sync.WaitGroup
	hits, misses, bypasses, evictions atomic.Uint64
}
type agentCachedSigner struct {
	cache            *agentSignerCache
	key              string
	generation       uint64
	created, expires time.Time
	signer           ssh.Signer
	lease            credential.KeyCacheLease
	done             chan struct{}
	retired          bool
	users            int
	signMutex        sync.Mutex
}

func newAgentSignerCache() *agentSignerCache {
	return &agentSignerCache{entries: map[string]*agentCachedSigner{}, slots: make(chan struct{}, maxAgentCachedSigners), now: time.Now}
}

func (s *agentServer) SetCacheTTL(ttl time.Duration) error {
	if ttl < 0 || ttl > maxAgentCacheTTL {
		return errors.New("agent cache TTL must be between 0 and 5m")
	}
	s.keys.stateMutex.Lock()
	defer s.keys.stateMutex.Unlock()
	s.keys.cache.mutex.Lock()
	s.keys.cache.ttl = ttl
	s.keys.cache.mutex.Unlock()
	s.keys.advanceGeneration()
	return nil
}
func (s *agentServer) CacheStats() AgentCacheStats {
	c := s.keys.cache
	return AgentCacheStats{c.hits.Load(), c.misses.Load(), c.bypasses.Load(), c.evictions.Load()}
}
func (c *agentSignerCache) enabled() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return !c.closed && c.ttl > 0
}
func (c *agentSignerCache) retireLocked(e *agentCachedSigner) {
	if e.retired {
		return
	}
	e.retired = true
	close(e.done)
	c.evictions.Add(1)
	if c.entries[e.key] == e {
		delete(c.entries, e.key)
	}
	if e.users == 0 {
		e.signer = nil
	}
}
func (c *agentSignerCache) invalidate() {
	if c == nil {
		return
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for _, e := range c.entries {
		c.retireLocked(e)
	}
}
func (c *agentSignerCache) close() {
	c.mutex.Lock()
	c.closed = true
	for _, e := range c.entries {
		c.retireLocked(e)
	}
	c.mutex.Unlock()
	c.workers.Wait()
}
func (c *agentSignerCache) validLocked(e *agentCachedSigner) bool {
	now := c.now()
	if e.retired || c.closed || now.Before(e.created) || !now.Before(e.expires) {
		return false
	}
	select {
	case <-e.lease.Invalidated():
		return false
	default:
		return true
	}
}
func (c *agentSignerCache) acquire(key string, generation uint64) *agentCachedSigner {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	e := c.entries[key]
	if e == nil {
		c.misses.Add(1)
		return nil
	}
	if e.generation != generation || !c.validLocked(e) {
		c.retireLocked(e)
		c.misses.Add(1)
		return nil
	}
	e.users++
	c.hits.Add(1)
	return e
}
func (e *agentCachedSigner) valid() bool {
	e.cache.mutex.Lock()
	defer e.cache.mutex.Unlock()
	return e.cache.validLocked(e)
}
func (e *agentCachedSigner) release() {
	e.cache.mutex.Lock()
	defer e.cache.mutex.Unlock()
	e.users--
	if e.retired && e.users == 0 {
		e.signer = nil
	}
}
func (e *agentCachedSigner) invalidate() {
	e.cache.mutex.Lock()
	defer e.cache.mutex.Unlock()
	e.cache.retireLocked(e)
}
func (e *agentCachedSigner) check(ctx context.Context) error {
	if !e.valid() {
		e.invalidate()
		return errAgentDenied
	}
	if err := e.lease.Check(ctx); err != nil {
		e.invalidate()
		return errAgentDenied
	}
	if !e.valid() {
		e.invalidate()
		return errAgentDenied
	}
	return nil
}

// reserve bounds monitors, retained entries and connections including cleanup.
func (c *agentSignerCache) reserve() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.closed || c.ttl == 0 {
		return false
	}
	select {
	case c.slots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (c *agentSignerCache) insert(key string, generation uint64, signer ssh.Signer, lease credential.KeyCacheLease) *agentCachedSigner {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.closed || c.ttl == 0 {
		return nil
	}
	select {
	case <-lease.Invalidated():
		return nil
	default:
	}
	if prior := c.entries[key]; prior != nil {
		c.retireLocked(prior)
	}
	now := c.now()
	e := &agentCachedSigner{cache: c, key: key, generation: generation, created: now, expires: now.Add(c.ttl), signer: signer, lease: lease, done: make(chan struct{}), users: 1}
	c.entries[key] = e
	c.workers.Add(1)
	timer := time.NewTimer(c.ttl)
	go func() {
		defer c.workers.Done()
		defer func() { <-c.slots }()
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-e.done:
		case <-lease.Invalidated():
		}
		e.invalidate()
		_ = lease.Close()
	}()
	return e
}

// EvictCache cancels pending uses and drops retained signers without changing
// enrollment, provider secrets, or connection bindings.
func (s *agentServer) EvictCache() {
	s.keys.stateMutex.Lock()
	defer s.keys.stateMutex.Unlock()
	s.keys.advanceGeneration()
}
