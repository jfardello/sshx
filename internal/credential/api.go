package credential

import (
	"context"
	"errors"
	"path"
	"strings"
	"unicode"
)

type Backend = credentialBackend
type Ref = credentialRef
type Query = credentialQuery
type ReadOptions = credentialReadOptions
type Store = credentialStore
type Provider = credentialStoreProvider
type KeyMaterialStore = keyMaterialStore
type KeyStore = keyStore
type BackendStore = backendStore
type Selection = selectedCredentialStore

const (
	BackendAuto          = credentialBackendAuto
	BackendSecretService = credentialBackendSecretService
	BackendGopass        = credentialBackendGopass
	OperationTimeout     = credentialOperationTimeout
	CleanupTimeout       = credentialCleanupTimeout
)

var (
	ErrLocked          = errCredentialLocked
	ErrProviderChanged = errCredentialProviderChanged
	ErrRead            = errCredentialRead
	ErrReference       = errCredentialReference
	ErrTooLarge        = errCredentialTooLarge
	ErrKeyUnsupported  = errKeyUnsupported
	ErrKeyMismatch     = errKeyMismatch
)

func ParseBackend(value string) (Backend, error) { return parseCredentialBackend(value) }
func Select(backend Backend, goos string, gopass Store, secretService Provider, ctx context.Context) (Selection, error) {
	return selectCredentialStore(backend, goos, gopass, secretService, ctx)
}
func NewBackendUnavailableError(backend Backend, err error) error {
	return newCredentialBackendUnavailableError(backend, err)
}
func IsBackendUnavailable(err error) bool           { return isCredentialBackendUnavailable(err) }
func (s Selection) Backend() Backend                { return s.backend }
func (s Selection) Store() Store                    { return s.store }
func Match(query string, refs []Ref) ([]Ref, error) { return matchCredentials(query, refs) }
func ForListing(query string, refs []Ref) []Ref     { return credentialsForListing(query, refs) }
func Identity(ref Ref) string                       { return credentialIdentity(ref) }
func Target(ref Ref, query string) (string, error)  { return credentialTarget(ref, query) }

func ValidGopassReference(value string) bool {
	if value == "" || len(value) > 1024 || path.IsAbs(value) || path.Clean(value) != value || strings.ContainsAny(value, "\\\x00\r\n\t") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." || part == "." || part == "" || strings.HasPrefix(part, "-") {
			return false
		}
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

func ValidRegistryID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return value != "." && value != ".."
}

func SanitizeKeyReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, known := range []error{context.Canceled, context.DeadlineExceeded, ErrLocked, ErrProviderChanged, ErrReference, ErrTooLarge, ErrKeyUnsupported, ErrKeyMismatch} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrRead
}

// KeyCacheLease pins a provider/item generation. Check must verify current
// readiness without unlocking; Invalidated closes on any observed revocation.
// Close releases the independent monitoring connection and must be bounded.
type KeyCacheLease interface {
	Check(context.Context) error
	Invalidated() <-chan struct{}
	Close() error
}

// KeyCacheProvider is optional. Stores without reliable monitoring must not
// implement it: they continue fresh noninteractive reads on every operation.
type KeyCacheProvider interface {
	WatchKey(context.Context, Ref) (KeyCacheLease, error)
}
