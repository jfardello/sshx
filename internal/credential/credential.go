package credential

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type credentialBackend string

const (
	credentialBackendAuto          credentialBackend = "auto"
	credentialBackendSecretService credentialBackend = "secret-service"
	credentialBackendGopass        credentialBackend = "gopass"
)

type credentialRef struct {
	Backend    credentialBackend
	ID         string
	Collection string
	Label      string
	Target     string
	Attributes map[string]string
	Locked     bool
}

type credentialQuery struct {
	Collection       string
	Text             string
	Attributes       map[string]string
	AllowInteraction bool
}

type credentialStore interface {
	Search(context.Context, credentialQuery) ([]credentialRef, error)
	Secret(context.Context, credentialRef, credentialReadOptions) ([]byte, error)
	Close() error
}

type credentialStoreProvider func(context.Context) (credentialStore, error)

type selectedCredentialStore struct {
	backend credentialBackend
	store   credentialStore
}

type credentialBackendUnavailableError struct {
	backend credentialBackend
	err     error
}

func (e *credentialBackendUnavailableError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("credential backend %q is unavailable", e.backend)
	}
	return fmt.Sprintf("credential backend %q is unavailable: %v", e.backend, e.err)
}

func (e *credentialBackendUnavailableError) Unwrap() error {
	return e.err
}

func newCredentialBackendUnavailableError(backend credentialBackend, err error) error {
	return &credentialBackendUnavailableError{backend: backend, err: err}
}

func isCredentialBackendUnavailable(err error) bool {
	var unavailable *credentialBackendUnavailableError
	return errors.As(err, &unavailable)
}

func parseCredentialBackend(value string) (credentialBackend, error) {
	backend := credentialBackend(value)
	switch backend {
	case credentialBackendAuto, credentialBackendSecretService, credentialBackendGopass:
		return backend, nil
	default:
		return "", fmt.Errorf(
			"invalid credential backend %q (expected auto, secret-service, or gopass)",
			value,
		)
	}
}

func selectCredentialStore(
	backend credentialBackend,
	goos string,
	gopass credentialStore,
	secretService credentialStoreProvider,
	contexts ...context.Context,
) (selectedCredentialStore, error) {
	ctx := context.Background()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	if err := ctx.Err(); err != nil {
		return selectedCredentialStore{}, err
	}
	if backend == "" {
		backend = credentialBackendAuto
	}

	switch backend {
	case credentialBackendGopass:
		store, err := configuredCredentialStore(credentialBackendGopass, gopass)
		return selectedCredentialStore{backend: credentialBackendGopass, store: store}, err
	case credentialBackendSecretService:
		store, err := openSecretServiceStore(ctx, secretService)
		return selectedCredentialStore{backend: credentialBackendSecretService, store: store}, err
	case credentialBackendAuto:
		if goos != "linux" {
			store, err := configuredCredentialStore(credentialBackendGopass, gopass)
			return selectedCredentialStore{backend: credentialBackendGopass, store: store}, err
		}
		store, err := openSecretServiceStore(ctx, secretService)
		if err == nil {
			return selectedCredentialStore{backend: credentialBackendSecretService, store: store}, nil
		}
		if !isCredentialBackendUnavailable(err) {
			return selectedCredentialStore{}, err
		}
		store, err = configuredCredentialStore(credentialBackendGopass, gopass)
		return selectedCredentialStore{backend: credentialBackendGopass, store: store}, err
	default:
		return selectedCredentialStore{}, fmt.Errorf("unsupported credential backend %q", backend)
	}
}

func configuredCredentialStore(backend credentialBackend, store credentialStore) (credentialStore, error) {
	if store == nil {
		return nil, newCredentialBackendUnavailableError(backend, nil)
	}
	return store, nil
}

func openSecretServiceStore(ctx context.Context, provider credentialStoreProvider) (credentialStore, error) {
	if provider == nil {
		return nil, newCredentialBackendUnavailableError(
			credentialBackendSecretService,
			errors.New("provider is not configured"),
		)
	}

	store, err := provider(ctx)
	if err != nil {
		return nil, err
	}
	return configuredCredentialStore(credentialBackendSecretService, store)
}

// The zero value never authorizes an unlock prompt.
type credentialReadOptions struct{ AllowInteraction bool }
type keyMaterialStore interface {
	KeyMaterial(context.Context, credentialRef) ([]byte, error)
}

type keyStore interface {
	keyMaterialStore
	Close() error
}

type backendStore interface {
	credentialStore
	keyMaterialStore
}

const credentialOperationTimeout = 30 * time.Second
const credentialCleanupTimeout = 2 * time.Second

var (
	errCredentialLocked          = errors.New("credential store is locked")
	errCredentialProviderChanged = errors.New("credential provider changed or disconnected")
	errCredentialRead            = errors.New("credential operation failed")
	errCredentialReference       = errors.New("invalid or ambiguous credential reference")
	errCredentialTooLarge        = errors.New("credential output exceeds size limit")
	errKeyUnsupported            = errors.New("unsupported or encrypted SSH private key")
	errKeyMismatch               = errors.New("private key does not match registered public key")
)
