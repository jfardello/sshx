package secretservice

import (
	"context"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/jfardello/sshx/internal/credential"
)

// A private synchronous handler never queues signals or launches one goroutine
// per notification. Any owner signal conservatively revokes this one generation.
type keyCacheSignals struct {
	mutex sync.Mutex
	owner string
	done  chan struct{}
	once  sync.Once
}

func (h *keyCacheSignals) invalidate() { h.once.Do(func() { close(h.done) }) }
func (h *keyCacheSignals) Terminate()  { h.invalidate() }
func (h *keyCacheSignals) DeliverSignal(iface, name string, signal *dbus.Signal) {
	h.mutex.Lock()
	owner := h.owner
	h.mutex.Unlock()
	if signal.Sender == owner || (iface == "org.freedesktop.DBus" && name == "NameOwnerChanged" && len(signal.Body) > 0 && signal.Body[0] == secretServiceBusName) {
		h.invalidate()
	}
}

type secretKeyCacheLease struct {
	store            *secretServiceStore
	signals          *keyCacheSignals
	ref              credentialRef
	owner            string
	collection, item dbus.ObjectPath
	modified         uint64
}

func (s *secretServiceStore) WatchKey(ctx context.Context, ref credentialRef) (credential.KeyCacheLease, error) {
	// Test/custom transports must explicitly opt in to monitoring rather than
	// silently treating a metadata snapshot as a revocation subscription.
	if _, ok := s.transport.(*dbusSecretServiceTransport); !ok {
		return nil, errCredentialReference
	}
	if ref.Backend != credentialBackendSecretService || !validRegistryID(ref.ID) || !validRegistryID(ref.Collection) {
		return nil, errCredentialReference
	}
	signals := &keyCacheSignals{done: make(chan struct{})}
	transport, err := connectSecretServiceTransport(ctx, dbus.WithSignalHandler(signals))
	if err != nil {
		return nil, errCredentialProviderChanged
	}
	store := &secretServiceStore{transport: transport}
	success := false
	defer func() {
		if !success {
			_ = store.Close()
		}
	}()
	owner, err := transport.Owner(ctx)
	if err != nil {
		return nil, err
	}
	signals.mutex.Lock()
	signals.owner = owner
	signals.mutex.Unlock()
	conn := transport.(*dbusSecretServiceTransport).conn
	if err := conn.AddMatchSignalContext(ctx, dbus.WithMatchSender(owner)); err != nil {
		return nil, errCredentialProviderChanged
	}
	if err := conn.AddMatchSignalContext(ctx, dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchInterface("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, secretServiceBusName)); err != nil {
		return nil, errCredentialProviderChanged
	}
	lease := &secretKeyCacheLease{store: store, signals: signals, ref: ref, owner: owner}
	collection, item, modified, err := lease.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	lease.collection, lease.item, lease.modified = collection, item, modified
	if err := lease.Check(ctx); err != nil {
		return nil, err
	}
	success = true
	return lease, nil
}
func (l *secretKeyCacheLease) Invalidated() <-chan struct{} { return l.signals.done }
func (l *secretKeyCacheLease) Close() error                 { l.signals.invalidate(); return l.store.Close() }
func (l *secretKeyCacheLease) snapshot(ctx context.Context) (dbus.ObjectPath, dbus.ObjectPath, uint64, error) {
	if ctx.Err() != nil {
		return "", "", 0, ctx.Err()
	}
	select {
	case <-l.signals.done:
		return "", "", 0, errCredentialProviderChanged
	default:
	}
	owner, err := l.store.transport.Owner(ctx)
	if err != nil || owner != l.owner {
		return "", "", 0, errCredentialProviderChanged
	}
	scoped := &secretServiceStore{transport: l.store.transport.WithContext(ctx).WithOwner(l.owner)}
	collection, item, err := scoped.keyLocation(l.ref)
	if err != nil {
		return "", "", 0, err
	}
	locked, err := scoped.boolProperty(item, secretServiceItemInterface+".Locked")
	if err != nil {
		return "", "", 0, err
	}
	if locked {
		return "", "", 0, errCredentialLocked
	}
	value, err := scoped.transport.GetProperty(item, secretServiceItemInterface+".Modified")
	if err != nil {
		return "", "", 0, err
	}
	modified, ok := value.Value().(uint64)
	if !ok {
		return "", "", 0, errCredentialReference
	}
	current, err := l.store.transport.Owner(ctx)
	if err != nil || current != l.owner {
		return "", "", 0, errCredentialProviderChanged
	}
	select {
	case <-l.signals.done:
		return "", "", 0, errCredentialProviderChanged
	default:
	}
	return collection, item, modified, nil
}
func (l *secretKeyCacheLease) Check(ctx context.Context) error {
	collection, item, modified, err := l.snapshot(ctx)
	if err == nil && (collection != l.collection || item != l.item || modified != l.modified) {
		err = errCredentialProviderChanged
	}
	if err != nil {
		l.signals.invalidate()
		return credential.SanitizeKeyReadError(ctx, keyProviderError(err))
	}
	return nil
}

var _ credential.KeyCacheProvider = (*secretServiceStore)(nil)
var _ credential.KeyCacheLease = (*secretKeyCacheLease)(nil)
