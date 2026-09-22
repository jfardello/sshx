package agent

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/credential"
	"golang.org/x/crypto/ssh"
)

type cacheTestProvider struct {
	*agentTestBackend
	mutex      sync.Mutex
	generation int
	failure    error
	leases     []*cacheTestLease
}
type cacheTestStore struct {
	*agentTestStore
	provider *cacheTestProvider
}
type cacheTestLease struct {
	provider   *cacheTestProvider
	generation int
	done       chan struct{}
	once       sync.Once
	closed     atomic.Bool
	checks     atomic.Int32
}

func (p *cacheTestProvider) open(ctx context.Context, b credentialBackend) (credential.KeyStore, error) {
	store, err := p.agentTestBackend.open(ctx, b)
	if err != nil {
		return nil, err
	}
	return &cacheTestStore{store.(*agentTestStore), p}, nil
}
func (s *cacheTestStore) WatchKey(ctx context.Context, ref credential.Ref) (credential.KeyCacheLease, error) {
	p := s.provider
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.failure != nil {
		return nil, p.failure
	}
	l := &cacheTestLease{provider: p, generation: p.generation, done: make(chan struct{})}
	p.leases = append(p.leases, l)
	return l, nil
}
func (l *cacheTestLease) Invalidated() <-chan struct{} { return l.done }
func (l *cacheTestLease) Close() error {
	l.closed.Store(true)
	l.once.Do(func() { close(l.done) })
	return nil
}
func (l *cacheTestLease) Check(ctx context.Context) error {
	l.checks.Add(1)
	p := l.provider
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if p.failure != nil {
		return p.failure
	}
	if p.generation != l.generation {
		return credential.ErrProviderChanged
	}
	select {
	case <-l.done:
		return credential.ErrProviderChanged
	default:
		return nil
	}
}
func (p *cacheTestProvider) change(err error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.generation++
	p.failure = err
	for _, l := range p.leases {
		l.once.Do(func() { close(l.done) })
	}
}
func cacheAgent(t *testing.T, encrypted bool) (*agentConnection, *cacheTestProvider, ssh.PublicKey, []byte) {
	a, b, pub, data := confirmationAgent(t, encrypted)
	p := &cacheTestProvider{agentTestBackend: b}
	a.keys.open = p.open
	a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
		if r.Operation == "passphrase" {
			return []byte("fixture-passphrase"), nil
		}
		return nil, nil
	}}
	t.Cleanup(a.keys.cache.close)
	return a, p, pub, data
}
func TestAgentCacheDefaultAndUnsupportedProvider(t *testing.T) {
	a, p, pub, data := cacheAgent(t, false)
	for i := 0; i < 2; i++ {
		if _, err := a.Sign(pub, data); err != nil {
			t.Fatal(err)
		}
	}
	if p.reads.Load() != 2 || len(p.leases) != 0 {
		t.Fatal("cache enabled by default")
	}
	a.keys.open = p.agentTestBackend.open // gopass-style provider, no monitoring.
	if err := (&agentServer{keys: a.keys}).SetCacheTTL(time.Second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := a.Sign(pub, data); err != nil {
			t.Fatal(err)
		}
	}
	if p.reads.Load() != 4 || len(p.leases) != 0 {
		t.Fatal("unsupported provider reused signer")
	}
}
func TestAgentCacheAbsoluteExpiryAndConfirmation(t *testing.T) {
	a, p, pub, data := cacheAgent(t, true)
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	a.keys.cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	if err := (&agentServer{keys: a.keys}).SetCacheTTL(time.Minute); err != nil {
		t.Fatal(err)
	}
	var confirmations, passphrases atomic.Int32
	a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
		if r.Operation == "passphrase" {
			passphrases.Add(1)
			return []byte("fixture-passphrase"), nil
		}
		confirmations.Add(1)
		return nil, nil
	}}
	for _, advance := range []time.Duration{0, 40 * time.Second, 21 * time.Second} {
		clock.Add(int64(advance))
		sig, err := a.Sign(pub, data)
		if err != nil || pub.Verify(data, sig) != nil {
			t.Fatal(err)
		}
	}
	if p.reads.Load() != 2 || confirmations.Load() != 3 || passphrases.Load() != 2 {
		t.Fatal("TTL slid or approval/decryption reused incorrectly")
	}
	if stats := (&agentServer{keys: a.keys}).CacheStats(); stats.Hits != 1 {
		t.Fatal(stats)
	}
	// Backward fake wall-clock jumps fail closed instead of extending retention.
	clock.Add(-int64(time.Hour))
	if _, err := a.Sign(pub, data); err != nil {
		t.Fatal(err)
	}
	if p.reads.Load() != 3 {
		t.Fatal("backward clock jump reused entry")
	}
	p.assertCleared(t)
}
func TestAgentCacheInvalidation(t *testing.T) {
	for _, mode := range []string{"lock", "policy", "provider", "deleted", "unavailable", "shutdown", "explicit"} {
		t.Run(mode, func(t *testing.T) {
			a, p, pub, data := cacheAgent(t, false)
			server := &agentServer{keys: a.keys}
			if err := server.SetCacheTTL(time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Sign(pub, data); err != nil {
				t.Fatal(err)
			}
			l := p.leases[0]
			switch mode {
			case "lock":
				a.keys.setLocked(true)
			case "policy":
				a.keys.invalidateRegistry()
			case "provider":
				p.change(credential.ErrProviderChanged)
			case "deleted":
				p.change(credential.ErrReference)
			case "unavailable":
				p.mutex.Lock()
				p.failure = errors.New("unavailable")
				p.mutex.Unlock()
			case "shutdown":
				a.keys.cache.close()
			case "explicit":
				server.EvictCache()
			}
			if mode == "unavailable" {
				if _, err := a.Sign(pub, data); err == nil {
					t.Fatal("cached use skipped readiness")
				}
			}
			if mode != "unavailable" {
				waitAgentCondition(t, func() bool { return l.closed.Load() })
			}
			if mode == "lock" || mode == "policy" || mode == "provider" || mode == "deleted" {
				if _, err := a.Sign(pub, data); err == nil {
					t.Fatal("revoked identity signed")
				}
			}
		})
	}
}

type blockingCacheSigner struct {
	ssh.AlgorithmSigner
	entered, release chan struct{}
}

func (s *blockingCacheSigner) SignWithAlgorithm(r io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	close(s.entered)
	<-s.release
	return s.AlgorithmSigner.SignWithAlgorithm(r, data, algorithm)
}
func TestAgentCacheLateSignatureAndConcurrentUse(t *testing.T) {
	for _, mode := range []string{"provider", "expiry", "lock", "policy"} {
		t.Run(mode, func(t *testing.T) {
			a, p, pub, data := cacheAgent(t, false)
			server := &agentServer{keys: a.keys}
			if err := server.SetCacheTTL(time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Sign(pub, data); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := a.Sign(pub, data); err != nil {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			if p.reads.Load() != 1 {
				t.Fatal("concurrent hits read backend")
			}
			entry := a.keys.cache.acquire(string(pub.Marshal()), a.keys.generation)
			blocked := &blockingCacheSigner{AlgorithmSigner: entry.signer.(ssh.AlgorithmSigner), entered: make(chan struct{}), release: make(chan struct{})}
			entry.signer = blocked
			entry.release()
			result := make(chan error, 1)
			go func() {
				sig, err := a.Sign(pub, data)
				if sig != nil {
					result <- errors.New("released late signature")
					return
				}
				result <- err
			}()
			<-blocked.entered
			switch mode {
			case "provider":
				p.change(credential.ErrLocked)
			case "expiry":
				a.keys.cache.mutex.Lock()
				entry.expires = time.Time{}
				a.keys.cache.mutex.Unlock()
			case "lock":
				a.keys.setLocked(true)
			case "policy":
				a.keys.invalidateRegistry()
			}
			close(blocked.release)
			if err := <-result; err == nil || err.Error() == "released late signature" {
				t.Fatal(err)
			}
		})
	}
}
func TestAgentCacheCapacityAndLeaseOwnership(t *testing.T) {
	c := newAgentSignerCache()
	c.ttl = time.Minute
	defer c.close()
	p := &cacheTestProvider{agentTestBackend: &agentTestBackend{}}
	for i := 0; i < maxAgentCachedSigners; i++ {
		if !c.reserve() {
			t.Fatal("early capacity refusal")
		}
		lease := &cacheTestLease{provider: p, done: make(chan struct{})}
		e := c.insert(string(rune(i)), 0, nil, lease)
		if e == nil {
			t.Fatal("insert failed")
		}
		e.release()
	}
	if c.reserve() {
		t.Fatal("unbounded entries")
	}
	c.invalidate()
	waitAgentCondition(t, func() bool { return len(c.slots) == 0 })
}

func TestAgentCacheIdleExpiry(t *testing.T) {
	a, p, pub, data := cacheAgent(t, false)
	if err := (&agentServer{keys: a.keys}).SetCacheTTL(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sign(pub, data); err != nil {
		t.Fatal(err)
	}
	lease := p.leases[0]
	waitAgentCondition(t, func() bool { return lease.closed.Load() })
	a.keys.cache.mutex.Lock()
	defer a.keys.cache.mutex.Unlock()
	if len(a.keys.cache.entries) != 0 {
		t.Fatal("idle signer retained past TTL")
	}
}
